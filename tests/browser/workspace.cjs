"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");

const approvedText = "A DNS exchange crossed the capture point.";
const pendingText = "A second observation requires analyst review.";
const invalidText = "This observation cites an unavailable frame.";
const analystNote = "Opening and closing bounds of the web conversation.";
const groupNote = "DNS resolution, HTTP response and TLS client hello for the same hostname.";
const conclusion = "The client contacted the resolved address over plaintext HTTP and TLS.";
const acquisitions = [
  {name: "analyst.cap", source: "Original sensor collection", date: "2026-01-12"},
  {name: "handoff.cap", source: "Incident ticket attachment", date: "2026-01-13"}
];

async function importCapture(page) {
  const raw = await fs.readFile(process.env.HENIX_FIXTURE);
  const input = page.locator("#upload");
  async function submit(buffer, record) {
    await input.setInputFiles({name: record.name, mimeType: "application/octet-stream", buffer});
    await page.locator("#source").fill(record.source);
    await page.locator("#acquired").fill(record.date);
    await page.locator("#importForm button[type=submit]").click();
  }
  await page.locator("#emptyImport").click();
  await submit(raw.subarray(0, 30), acquisitions[0]);
  await page.getByText("Import failed", {exact: true}).waitFor();
  await page.locator("#importAction").click();
  await submit(raw, acquisitions[0]);
  await page.locator("#work").waitFor();
  assert.match(await page.locator("#protocols").innerText(), /tls/i);
  assert.match(await page.locator("#protocols").innerText(), /eth/i);
  await page.locator("#import").click();
  await submit(raw, acquisitions[1]);
  await page.locator("#importAction").filter({hasText: "Open capture"}).click();
  await page.locator("#fileInfo").click();
  assert.equal(await page.locator("#detail tbody tr").count(), 2);
  await page.locator("#detailDialog .dismiss").click();
  assert.equal(await page.locator("#files button").count(), 1);
  return createHash("sha256").update(raw).digest("hex");
}

async function pinConversation(page) {
  await page.locator("#conversationQuery").fill("51001");
  await page.locator("#conversationSearch button").click();
  const pin = page.locator("#streams [data-pin]");
  await pin.waitFor();
  assert.equal(await pin.count(), 1);
  await pin.click();
  assert.match(await page.locator("#pinRefs").innerText(), /#3, #8/);
  await page.locator("#pinNote").fill(analystNote);
  await page.locator("#pinForm button[type=submit]").click();
  await page.locator("#pinDialog").waitFor({state: "hidden"});
}

async function addAssessment(page) {
  await page.locator("[data-page=report]").click();
  await page.locator("#addFramePin").click();
  await page.locator("#pinNumbers").fill("7, 999");
  await page.locator("#pinNote").fill(groupNote);
  await page.locator("#pinForm button[type=submit]").click();
  await page.getByText("A pinned frame falls outside the capture.").waitFor();
  await page.locator("#pinNumbers").fill("12, 2 7");
  await page.locator("#pinForm button[type=submit]").click();
  await page.locator("#pinDialog").waitFor({state: "hidden"});
  await page.locator("#conclusion").fill(conclusion);
  await page.locator("#conclusionForm button").click();
  await page.getByText("Conclusion saved in this workspace.").waitFor();
}

async function reviewCapture(page) {
  let receivedBody;
  let providerFailure;
  const provider = http.createServer(async (req, res) => {
    try {
      assert.equal(req.headers.authorization, "Bearer browser-fixture");
      assert.equal(req.url, "/v1/chat/completions");
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      receivedBody = JSON.parse(Buffer.concat(chunks).toString());
      const transmitted = JSON.parse(receivedBody.messages[1].content);
      const evidence = transmitted.evidence;
      const observations = [
        {text: approvedText, evidence, frames: [1, 2]},
        {text: pendingText, evidence, frames: [2]},
        {text: invalidText, evidence, frames: [99]}
      ];
      const message = {content: JSON.stringify({observations})};
      res.writeHead(200, {"Content-Type": "application/json"});
      res.end(JSON.stringify({choices: [{message, finish_reason: "stop"}]}));
    } catch (error) {
      providerFailure = error;
      res.writeHead(400).end();
    }
  });
  await new Promise((resolve, reject) => {
    provider.once("error", reject);
    provider.listen(0, "127.0.0.1", resolve);
  });
  try {
    await page.locator("[data-page=ai]").click();
    assert.equal(await page.locator("#provider option").count(), 8);
    for (const id of ["anthropic", "xai", "gemini"]) {
      await page.locator("#provider").selectOption(id);
      assert.ok((await page.locator("#model").inputValue()).length);
    }
    const destination = "http://127.0.0.1:" + provider.address().port + "/v1/chat/completions";
    await page.locator("#provider").selectOption("custom");
    await page.locator("#apiEndpoint").fill(destination);
    await page.locator("#model").fill("org/model");
    await page.locator("#key").fill("browser-fixture");
    const send = page.locator("#sendReview");
    assert.equal(await send.isDisabled(), true);
    await page.locator("#redactAI").uncheck();
    await page.locator("#prepareAI").click();
    await page.locator("#preview").waitFor();
    assert.match(await page.locator("#preview").innerText(), /portal\.example\.test/);
    await page.locator("#redactAI").check();
    assert.equal(await send.isDisabled(), true);
    await page.locator("#prepareAI").click();
    await page.locator("#preview").waitFor();
    const preview = JSON.parse(await page.locator("#preview").innerText());
    assert.equal(preview.url, destination);
    assert.equal(preview.body.model, "org/model");
    assert.doesNotMatch(JSON.stringify(preview), /browser-fixture|192\.0\.2\.24|portal\.example\.test/);
    assert.equal(JSON.parse(preview.body.messages[1].content).display_filter, "(redacted)");
    await send.click();
    await page.locator("#aiResult").waitFor();
    if (providerFailure) throw providerFailure;
    assert.deepEqual(receivedBody, preview.body);
    assert.equal(await page.locator("#key").inputValue(), "");
    assert.equal(await page.locator("[data-approve='2']").isDisabled(), true);
    assert.equal(await page.locator("[data-approve='1']").isChecked(), false);
    await page.locator("[data-approve='0']").check();
    await page.locator("#saveAIApproval").click();
    await page.waitForFunction(() => document.querySelector("#reportAi").textContent.endsWith("1"));
  } finally {
    await new Promise(resolve => provider.close(resolve));
  }
}

async function inspectPackets(page) {
  await page.locator("[data-page=packets]").click();
  assert.match(await page.locator("#packetBody tr").first().innerText(), /51000/);
  await page.locator("#packetBody [data-frame='7']").click();
  await page.locator("#frameHeaders").waitFor();
  assert.match(await page.locator("#frameHeaders").innerText(), /Content-Type/);
  assert.match(await page.locator("#frameBytes").textContent(), /0000/);
  assert.match(await page.locator("#payloadBytes").textContent(), /OK/);
  assert.match(await page.locator("#detail").textContent(), /text\/plain/);
  await page.locator("#detailDialog .dismiss").click();
  await page.locator("#presetList").selectOption("http.response.code >= 400");
  await page.waitForFunction(() => document.querySelector("#filter").value === "http.response.code >= 400"
    && !document.querySelector("#packetBody [data-frame]"));
  await page.locator("#filter").fill("tcp.stream ==");
  await page.locator("#filterForm button[type=submit]").click();
  await page.locator("#notice").waitFor();
  await page.locator("#clear").click();
  await page.waitForFunction(() => document.querySelectorAll("#packetBody [data-frame]").length === 12);
}

async function download(page, button) {
  const ready = page.waitForEvent("download");
  await page.locator(button).click();
  const file = await ready;
  assert.equal(await file.failure(), null);
  return await file.path();
}

async function verifyReport(page, digest) {
  await page.locator("[data-page=report]").click();
  assert.ok((await page.locator("#pins").innerText()).includes(analystNote));
  const group = page.locator("#pins .finding").filter({hasText: groupNote});
  assert.deepEqual(await group.locator("[data-frame]").allTextContents(), ["#2", "#7", "#12"]);
  assert.equal(await page.locator("#conclusion").inputValue(), conclusion);
  const report = await fs.readFile(await download(page, "#exportHTML"), "utf8");
  assert.ok(report.includes(analystNote));
  assert.ok(report.includes(groupNote));
  assert.ok(report.includes(conclusion));
  assert.ok(report.includes(digest));
  const evidenceID = "EV-" + digest.slice(0, 12).toUpperCase();
  for (const frames of [[3, 8], [2, 7, 12]]) {
    assert.ok(report.includes(frames.map(number => evidenceID + " #" + number).join(", ")));
  }
  for (const record of acquisitions) {
    assert.ok(report.includes("<td>" + record.name + "</td><td>" + record.source + "</td><td>" + record.date + "</td>"));
  }
  assert.ok(report.includes(approvedText));
  assert.ok(!report.includes(pendingText));
  assert.ok(!report.includes(invalidText));
}

async function reopenCase(page, digest) {
  await page.locator("#caseFiles").click();
  const saved = await download(page, "#saveCase");
  await page.locator("#caseDialog .dismiss").click();
  await page.locator("#fileInfo").click();
  await page.locator("#closeCapture").click();
  await page.locator("#empty").waitFor();
  await page.locator("#caseFiles").click();
  await page.locator("#caseInput").setInputFiles({
    name: "browser.henix", mimeType: "application/octet-stream", buffer: await fs.readFile(saved)
  });
  await page.locator("#openCase").click();
  await page.locator("#caseDialog").waitFor({state: "hidden"});
  await page.locator("#work").waitFor();
  await verifyReport(page, digest);
  await page.locator("#pins [data-frame='7']").click();
  await page.locator("#frameHeaders").waitFor();
  assert.match(await page.locator("#frameHeaders").innerText(), /Content-Type/);
  assert.match(await page.locator("#payloadBytes").textContent(), /OK/);
  await page.locator("#detailDialog .dismiss").click();
  await page.locator("[data-page=ai]").click();
  assert.equal(await page.locator("[data-approve='0']").isChecked(), true);
  assert.equal(await page.locator("[data-approve='1']").isChecked(), false);
}

async function main() {
  const browser = await chromium.launch({executablePath: process.env.CHROME_PATH || undefined, headless: true});
  try {
    const page = await browser.newPage({viewport: {width: 1360, height: 900}, colorScheme: "light"});
    page.setDefaultTimeout(20000);
    const errors = [];
    page.on("pageerror", error => errors.push(error.message));
    await page.goto(process.env.HENIX_URL);
    await page.locator("#empty").waitFor();
    assert.equal(await page.locator("#files button").count(), 0);
    await page.locator("#themeMode").click();
    assert.equal(await page.locator("html").getAttribute("data-theme"), "dark");
    await page.reload();
    await page.waitForFunction(() => document.documentElement.dataset.theme === "dark");
    const digest = await importCapture(page);
    await pinConversation(page);
    await addAssessment(page);
    await reviewCapture(page);
    await inspectPackets(page);
    await verifyReport(page, digest);
    await reopenCase(page, digest);
    await page.locator("[data-page=overview]").click();
    await page.locator("#themeMode").click();
    assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
    await page.setViewportSize({width: 390, height: 844});
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(errors, []);
    console.log("Passed browser checks for import recovery, acquisition history, decoder details, filters, AI redaction and approvals, grouped pins, saved conclusions, case handoff, report provenance, theme and mobile layout.");
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
