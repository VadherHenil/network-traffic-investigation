const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const origin = "http://127.0.0.1:18881";
const web = path.resolve(__dirname, "../../web");

(async () => {
  const browser = await chromium.launch({executablePath:process.env.CHROME_PATH, headless:true});
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(15000);
    const errors = [];
    page.on("pageerror",error => errors.push(error.message));
    const file = {id:"EV-ONE",name:"edge.cap",total:6000000,size:5*1024**3,dissection_passes:1,window:[]};
    const packet = {frame:"1",time:"",src:"192.0.2.1",dst:"192.0.2.2",layers:["eth"],protocol:"Ethernet"};
    const stats = {window:[],bins:Array(48).fill(0),stream_count:0,streams:[],hierarchy:[],layer_counts:[],bytes:file.size,hosts:2};
    const storage = {free_bytes:8*1024**3, index_bytes:128*1024**2,filter_bytes:4096,temp_free_bytes:9*1024**3};
    let job, allowFinish=false, uploads=0, requestedPage=-1, releaseLatePage;
    const latePage = new Promise(resolve => { releaseLatePage = resolve; });
    await page.route(origin + "/**",async route => {
      const req=route.request();
      const url=new URL(req.url());
      if (!url.pathname.startsWith("/api/")) {
        const name=url.pathname==="/" ? "index.html" : url.pathname.slice(1);
        if (!["index.html","style.css","app.js","analyst.js","cases.js"].includes(name)) return route.fulfill({status:404});
        return route.fulfill({contentType:{".html":"text/html",".css":"text/css",".js":"application/javascript"}[path.extname(name)],
          body:fs.readFileSync(path.join(web,name))});
      }
      let value;
      if (url.pathname==="/api/status") {
        value={engine:"TShark",providers:[],captures:job?.state==="ready"?[file]:[],imports:job?[job]:[]};
      } else if (url.pathname==="/api/import") {
        assert.equal(url.searchParams.get("background"),"1");
        assert.equal(req.headers()["x-henix"],"workspace");
        uploads++;
        job = {job:"abc",name:url.searchParams.get("name"),state:"indexing",frames:0,storage};
        value=job;
      } else if (url.pathname==="/api/import-status") {
        if (allowFinish) job={...job,state:"ready",frames:file.total,capture:file};
        else job={...job,frames:12000};
        value=job;
      } else if (url.pathname==="/api/storage") {
        value=storage;
      } else if (url.pathname==="/api/view" || url.pathname==="/api/packets") {
        const n=req.postDataJSON().page || 0;
        requestedPage=n;
        if(n===119999) await latePage;
        value={capture:file, matched:file.total, packets:[packet], page:n,pages:120000,findings:[],events:[],stats,
          annotations:{pins:[],conclusion:""}};
      } else throw new Error(url.pathname);
      await route.fulfill({json:value});
    });
    await page.goto(origin + "/");
    await page.locator("#emptyImport").click();
    await page.locator("#upload").setInputFiles({name:"edge.cap",buffer:Buffer.from("test"),mimeType:"application/octet-stream"});
    // Boundary validation uses file metadata; the test only transfers four bytes.
    await page.locator("#upload").evaluate(el=>Object.defineProperty(el.files[0],"size",{value:5*1024**3+1,configurable:true}));
    await page.locator("#importForm button[type=submit]").click();
    assert.match(await page.locator("#importError").innerText(),/5 GiB/);
    assert.equal(uploads,0);
    await page.locator("#upload").evaluate(el=>Object.defineProperty(el.files[0],"size",{value:5*1024**3,configurable:true}));
    await page.locator("#importForm button[type=submit]").click();
    await page.waitForFunction(()=>document.querySelector("#importStatus").textContent.includes("12,000"));
    assert.match(await page.locator("#importStatus").textContent(), /128.0 MiB in indexes/);
    await page.reload();
    await page.waitForFunction(()=>document.querySelector("#importStage").textContent.includes("Indexing edge.cap"));
    allowFinish=true;
    await page.waitForSelector("#work:visible");
    assert.equal(uploads,1);
    await page.locator("[data-page=packets]").click();
    await page.locator("#pageNumber").fill("120000");
    await page.locator("#pager button[type=submit]").click();
    await page.waitForFunction(()=>document.querySelector("#busyStorage").textContent.includes("8.00 GiB workspace free"));
    releaseLatePage();
    await page.waitForFunction(()=>document.querySelector("#next").disabled);
    assert.equal(requestedPage,119999);
    await page.locator("#import").click();
    allowFinish=false;
    await page.locator("#upload").setInputFiles({name:"second.cap",buffer:Buffer.from("test"),mimeType:"application/octet-stream"});
    await page.locator("#importForm button[type=submit]").click();
    await page.waitForFunction(()=>document.querySelector("#importStage").textContent.includes("Indexing second.cap"));
    await page.locator("[data-page=overview]").click();
    assert.match(await page.locator("#title").textContent(),/overview/);
    job={...job,state:"failed",error:"Workspace drive full"};
    await page.waitForFunction(()=>document.querySelector("#importStatus").textContent.includes("Workspace drive full"));
    await page.locator("#importAction").click();
    assert(await page.locator("#importDialog").isVisible());
    assert.deepEqual(errors,[]);
    console.log("Browser workflow passed: >5 GiB rejected, 5 GiB metadata accepted, native upload, index polling, disk usage, resume on refresh, final page jump, background navigation, failure and retry.");
  } finally {await browser.close();}
})().catch(err=>{console.error(err);process.exitCode=1;});
