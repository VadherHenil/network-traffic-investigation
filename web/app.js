"use strict";

const $ = id => document.getElementById(id);
const fmt = n => Number(n).toLocaleString();
const esc = value => String(value ?? "").replace(/[&<>"']/g, ch =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[ch]));
const titles = {overview:"Capture overview", packets:"Packet explorer", ai:"AI review", report:"Investigation report"};
const presets = {"All frames":"", "DNS":"dns", "DNS replies":"dns.flags.response == 1", "TCP":"tcp",
  "UDP":"udp", "HTTP":"http", "TLS hello":"tls.handshake.type == 1"};
const filterGroups = {
  "Network": {"IPv4":"ip", "IPv6":"ipv6", "ARP":"arp", "ICMP":"icmp || icmpv6", "VLAN":"vlan"},
  "Transport": {"TCP setup":"tcp.flags.syn == 1", "TCP resets":"tcp.flags.reset == 1",
    "TCP retransmissions":"tcp.analysis.retransmission", "QUIC":"quic", "SCTP":"sctp"},
  "Applications": {"DNS queries":"dns.flags.response == 0", "HTTP requests":"http.request",
    "HTTP errors":"http.response.code >= 400", "HTTP/2":"http2", "TLS":"tls", "SSH":"ssh",
    "DHCP":"dhcp || dhcpv6", "NTP":"ntp", "FTP":"ftp"},
  "Frame diagnostics": {"Truncated frames":"frame.cap_len < frame.len", "Malformed frames":"_ws.malformed"}
};
let files = [], view = null, active = "", expression = "", page = "overview", busy = false, pickedFile;
const filters = new Map();
const captureLimit = 5 * 1024 ** 3;
let importing = false;

async function request(path, data={}, binary=false) {
  const headers = {"X-HENIX":"workspace", "Content-Type":"application/json"};
  try {
    const response = await fetch("/api/" + path, {method:"POST", headers, body:JSON.stringify(data)});
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      if (response.status === 404 && data.id && /open capture|capture has been closed/i.test(error.error || "")) {
        files = files.filter(c => c.id !== data.id);
        filters.delete(data.id);
        if (active === data.id) {
          $("detailDialog").close();
          showEmpty();
        } else drawFiles();
        throw new Error("This capture is no longer open. Select another capture or import the file again.");
      }
      const failure = new Error(error.error || "The local server returned HTTP " + response.status + ".");
      failure.status = response.status;
      throw failure;
    }
    return binary ? await response.blob() : await response.json();
  } catch (err) {
    if (err instanceof TypeError) throw new Error("Cannot reach HENIX. Check that the local server is running, then reload the workspace.");
    if (err instanceof SyntaxError) throw new Error("HENIX returned an unreadable response. Reload the workspace and retry.");
    throw err;
  }
}
function scope(extra={}) { return {id:active, filter:expression, ...extra}; }
function notice(message="") {
  $("notice").textContent = message;
  $("notice").hidden = !message;
}
async function task(label, fn) {
  if (busy) return;
  busy = true;
  $("busy").textContent = label;
  $("busy").hidden = false;
  document.querySelector("main").setAttribute("inert", "");
  document.querySelector(".rail").setAttribute("inert", "");
  $("importError").textContent = "";
  $("detailError").textContent = "";
  const importSubmit = $("importForm").querySelector("button[type=submit]");
  if ($("importDialog").open) {
    importSubmit.disabled = true;
    importSubmit.textContent = label;
  }
  notice();
  try { await fn(); }
  catch (err) {
    const message = err.message || "The action failed. Retry it or reload the workspace.";
    if ($("importDialog").open) $("importError").textContent = message;
    else if ($("detailDialog").open) $("detailError").textContent = message;
    else notice(message);
  }
  finally {
    busy = false;
    importSubmit.disabled = false;
    importSubmit.textContent = "Open capture";
    $("busy").hidden = true;
    document.querySelector("main").removeAttribute("inert");
    document.querySelector(".rail").removeAttribute("inert");
  }
}
function size(bytes) {
  if (bytes < 1024) return fmt(bytes) + " B";
  if (bytes < 1048576) return (bytes/1024).toFixed(1) + " KiB";
  if (bytes >= 1024 ** 3) return (bytes/1024 ** 3).toFixed(2) + " GiB";
  return (bytes/1048576).toFixed(1) + " MiB";
}
function drawFiles() {
  $("files").innerHTML = files.map(c => '<button class="file ' + (c.id === active ? "current" : "") +
    '" data-id="' + esc(c.id) + '" title="' + esc(c.name) + '">' + esc(c.name) + '</button>').join("");
}
function setPage(next) {
  page = next;
  $("title").textContent = titles[page];
  document.querySelectorAll(".view").forEach(el => el.hidden = el.id !== page);
  document.querySelectorAll("[data-page]").forEach(el => {
    el.classList.toggle("active", el.dataset.page === page);
    if (el.dataset.page === page) el.setAttribute("aria-current","page"); else el.removeAttribute("aria-current");
  });
}
async function loadView(id, filter) {
  const data = await request("view", {id, filter});
  active = id;
  expression = filter;
  filters.set(id, filter);
  view = data;
  const index = files.findIndex(c => c.id === id);
  if (index === -1) files.push(view.capture); else files[index] = view.capture;
  $("filter").value = filter;
  $("work").hidden = false;
  $("empty").hidden = true;
  $("fileInfo").hidden = false;
  $("excerpt").open = false;
  $("preview").textContent = "";
  $("crumb").textContent = view.capture.name;
  $("identity").textContent = view.capture.name + "  ·  " + id;
  if ($("importState").dataset.readyId === id) $("importState").hidden = true;
  document.querySelectorAll("[data-page]").forEach(button => button.disabled = false);
  drawFiles();
  drawOverview();
  drawPackets(view);
  drawReport();
  drawAI();
  drawPresets();
}
function drawPresets() {
  $("presets").innerHTML = Object.entries(presets).map(([label, filter]) =>
    '<button data-preset="' + esc(filter) + '" aria-pressed="' + (filter === expression) + '" class="' + (filter === expression ? "chosen" : "") + '">' + label + '</button>').join("");
  $("presetList").value = expression;
  if ($("presetList").selectedIndex < 0) $("presetList").selectedIndex = 0;
}
function findings(full) {
  if (!view.findings.length) return '<p class="emptymsg">No frames matched the display filter.</p>';
  return view.findings.map(f => '<div class="finding"><h3>' + esc(f.title) + '</h3><div><p>' + esc(f.observation) +
    '</p>' + (full ? '<p class="muted">' + esc(f.meaning) + '</p>' : '') +
    '<div class="refs">' + f.frames.map(n => '<button class="ref" data-frame="' + esc(n) + '">#' + esc(n) +
    '</button>').join("") + '</div></div></div>').join("");
}
function drawOverview() {
  const s = view.stats;
  const cards = [["Matching packets", fmt(view.matched), "of " + fmt(view.capture.total) + " captured"],
    ["Endpoints", fmt(s.hosts), "distinct addresses"], ["Duration", s.window.length ? s.duration.toFixed(3) + " s" : "—", "matching window"],
    ["Traffic volume", size(s.bytes), "on-wire frame lengths"]];
  $("kpis").innerHTML = cards.map(([label,value,sub]) => '<div class="kpi"><small>' + label + '</small><b>' +
    value + '</b><span>' + sub + '</span></div>').join("");
  const max = Math.max(1,...s.bins);
  $("plot").innerHTML = s.bins.map((v,i) => '<i style="height:' + (v/max*100) +
    '%" title="Interval ' + (i+1) + ' · ' + fmt(v) + ' packets"></i>').join("");
  $("plot").setAttribute("aria-label", s.window.length ? fmt(s.bins.reduce((a,b) => a+b,0)) +
    " packets with timestamps over " + s.duration.toFixed(3) + " seconds. Peak interval " + max + " packets." :
    "No packet timestamps in this view.");
  $("axisStart").textContent = s.window[0]?.slice(11,23) || "—";
  $("axisEnd").textContent = s.window[1] ? s.window[1].slice(11,23) + " UTC" : "—";
  $("hierarchy").textContent = s.hierarchy.map(([path,n]) => "  ".repeat(path.length-1) + path.at(-1) + "  " + fmt(n)).join("\n") || "No decoded layers in this view.";
  if (s.hierarchy_count > s.hierarchy.length) {
    $("hierarchy").textContent += "\nShowing " + fmt(s.hierarchy.length) + " of " + fmt(s.hierarchy_count) + " protocol paths, selected by frame count.";
  }
  $("protocolCount").textContent = fmt(s.layer_counts.length) + " decoded layers · frames containing each layer";
  $("protocols").innerHTML = s.layer_counts.map(([name,n]) => '<div class="layer-row"><b>' + esc(name) +
    '</b><progress max="' + view.matched + '" value="' + n + '" aria-label="' + esc(name) + ' frames"></progress><span>' +
    fmt(n) + '</span></div>').join("") || '<p class="emptymsg">No matching protocol layers.</p>';
  $("findings").innerHTML = findings(false);
  $("streamCount").textContent = fmt(s.stream_count) + " matching streams · select a stream to inspect both directions";
  $("streams").innerHTML = s.streams.length ? '<div class="tablewrap"><table><thead><tr><th>Stream</th><th>Endpoint A</th><th>Endpoint B</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>' +
    s.streams.map(c => '<tr><td><button class="ref" data-stream="' + esc(c.stream) + '">Stream ' + esc(c.stream) +
    '</button></td><td>' + esc(c.a) + '</td><td>' + esc(c.b) + '</td><td>' + fmt(c.packets) + '</td><td>' +
    fmt(c.bytes) + '</td></tr>').join("") + '</tbody></table></div>' +
    (s.stream_count > 100 ? '<p class="muted">Showing the 100 most active streams.</p>' : '') :
    '<p class="emptymsg">No TCP conversation in this view.</p>';
}
function drawPackets(data) {
  view.page = data.page;
  $("packetCount").textContent = fmt(data.matched) + " frames · select a frame for its decoded protocol tree";
  $("packetBody").innerHTML = data.packets.map(r => '<tr><td><button class="ref" data-frame="' + esc(r.frame) +
    '">#' + esc(r.frame) + '</button></td><td class="nowrap" title="' + esc(r.time) + '">' + esc(r.time.slice(11,-1) || "—") +
    '</td><td>' + esc(r.src) + '</td><td>' + esc(r.src_port ?? "—") + '</td><td>' + esc(r.dst) + '</td><td>' +
    esc(r.dst_port ?? "—") + '</td><td title="' + esc(r.layers.join(" → ")) + '">' + esc(r.protocol) + '</td><td>' + esc(r.size) +
    '</td><td>' + esc(r.info) + '</td></tr>').join("") ||
    '<tr><td colspan="9">No frames matched. Clear or adjust the filter.</td></tr>';
  $("pageNumber").value = data.page+1;
  $("pageNumber").max = data.pages;
  $("pageLabel").textContent = "of " + fmt(data.pages);
  $("prev").disabled = data.page === 0;
  $("next").disabled = data.page+1 >= data.pages;
}
function drawReport() {
  $("reportScope").textContent = active + " · " + fmt(view.matched) + " of " + fmt(view.capture.total) +
    " frames · " + (expression || "All frames");
  $("reportFindings").innerHTML = findings(true);
  $("reportTimeline").innerHTML = view.events.length ? '<div class="tablewrap"><table><thead><tr><th>Frame</th><th>Time (UTC)</th><th>Direction</th><th>Observation</th></tr></thead><tbody>' +
    view.events.map(e => '<tr><td><button class="ref" data-frame="' + esc(e.frame) + '">#' + esc(e.frame) +
    '</button></td><td>' + esc(e.time) + '</td><td>' + esc(e.src) + ' → ' + esc(e.dst) + '</td><td>' +
    esc(e.observation) + '</td></tr>').join("") + '</tbody></table></div>' : '<p>No matching events.</p>';
  $("reportAi").textContent = view.ai ? "The export includes the AI review for this filter." : "The export uses locally decoded evidence.";
}
function drawAI() {
  const ai = view.ai;
  $("sendReview").disabled = view.matched === 0;
  $("aiResult").hidden = !ai;
  $("aiResult").innerHTML = ai ? '<h2>Provider review</h2><small>' + esc(ai.provider_label || ai.provider) + ' · ' + esc(ai.model) +
    ' · ' + ai.included + ' frames supplied' + (ai.complete ? '' : ' · Partial response') +
    '</small><p>' + esc(ai.text) + '</p>' : "";
}
function openImport() {
  if (importing) return;
  $("importForm").reset();
  pickedFile = null;
  $("fileName").textContent = "Choose a capture or drop it here";
  $("importError").textContent = "";
  $("importDialog").showModal();
}

function setImporting(value) {
  importing = value;
  for (const id of ["import","sideImport","emptyImport"]) $(id).disabled = value;
}

function importStatus(title, message, value, button="", action=null) {
  $("importState").hidden = false;
  delete $("importState").dataset.readyId;
  $("importStage").textContent = title;
  if ($("importStatus").textContent !== message) $("importStatus").textContent = message;
  const meter = $("importMeter");
  meter.hidden = value === null;
  if (typeof value === "number") {
    meter.max = 100;
    meter.value = value;
  } else meter.removeAttribute("value");
  const control = $("importAction");
  control.hidden = !button;
  control.textContent = button;
  control.onclick = action;
}

function uploadCapture(file, params) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/import?" + params);
    xhr.setRequestHeader("X-HENIX","workspace");
    xhr.setRequestHeader("Content-Type","application/octet-stream");
    xhr.responseType = "json";
    const progress = loaded => {
      const pct = Math.floor(100 * loaded / file.size);
      importStatus("Uploading " + file.name, size(loaded) + " of " + size(file.size) + " · " + pct + "%", pct);
    };
    progress(0);
    xhr.upload.onprogress = e => progress(e.loaded);
    xhr.upload.onload = () => importStatus("Checking " + file.name, "Waiting for the local working copy and SHA-256.", undefined);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300 && xhr.response) resolve(xhr.response);
      else reject(new Error(xhr.response?.error || "Import failed (HTTP " + xhr.status + ")."));
    };
    xhr.onerror = () => reject(new Error("The upload connection closed. Check that HENIX is running and try the import again."));
    xhr.onabort = () => reject(new Error("The upload was interrupted. Choose the file to try again."));
    xhr.send(file);
  });
}

async function watchImport(job) {
  while (job.state === "indexing") {
    importStatus("Indexing " + job.name, fmt(job.frames || 0) + " frames indexed", undefined);
    await new Promise(resolve => setTimeout(resolve,1000));
    try {
      job = await request("import-status",{job:job.job});
    } catch (err) {
      if (err.status && err.status < 500) throw err;
      importStatus("Indexing " + job.name, "Reconnecting to the local server…", undefined);
      await new Promise(resolve => setTimeout(resolve,4000));
    }
  }
  if (job.state === "failed") throw new Error(job.error || "Indexing failed. Review the capture and try again.");
  if (job.state !== "ready" || !job.capture?.id) throw new Error("HENIX returned an unrecognized import status. Reload the workspace to check the import.");
  return job.capture;
}

async function imported(capture) {
  const index = files.findIndex(c => c.id === capture.id);
  if (index === -1) files.push(capture); else files[index] = capture;
  drawFiles();
  const open = () => task("Opening capture overview…",async () => {
    await loadView(capture.id,"");
    setPage("overview");
    $("importState").hidden = true;
  });
  importStatus(capture.name + " is ready", fmt(capture.total) + " indexed frames", null, "Open capture", open);
  $("importState").dataset.readyId = capture.id;
  if (!active && !busy) await open();
}

async function importCapture(file, params, pendingJob) {
  setImporting(true);
  try {
    const result = pendingJob || await uploadCapture(file,params);
    const capture = result.job ? await watchImport(result) : result;
    if (!capture?.id) throw new Error("The upload returned no capture ID. Reload the workspace to check its status.");
    await imported(capture);
  } catch (err) {
    importStatus("Import failed", err.message, null, "Choose capture", openImport);
  } finally {
    setImporting(false);
  }
}
function pick(file) {
  pickedFile = file;
  $("fileName").textContent = file ? file.name + " · " + size(file.size) : "Choose a capture or drop it here";
}
function showEmpty() {
  active = "";
  view = null;
  $("work").hidden = true;
  $("empty").hidden = false;
  $("fileInfo").hidden = true;
  $("identity").textContent = "";
  $("crumb").textContent = "Investigation";
  $("key").value = "";
  setPage("overview");
  document.querySelectorAll("[data-page]").forEach(button => button.disabled = true);
  drawFiles();
}
function evidenceDetails() {
  const c = view.capture;
  const facts = [["Evidence ID",c.id],["Original file",c.name],["Source",c.source || "Local import"],
    ["Acquired",c.acquired || "Unspecified"],["SHA-256",c.sha256],["Capture start",c.window[0] || "—"],
    ["Capture end",c.window[1] || "—"],["Capture size",size(c.size)],
    ["Index dissection",c.dissection_passes === 1 ? "Single pass · later response references may be unavailable" : "Two passes"]];
  $("detailTitle").textContent = "Evidence details";
  $("detailError").textContent = "";
  $("detail").innerHTML = '<dl>' + facts.map(([k,v]) => '<dt>' + k + '</dt><dd>' + esc(v) + '</dd>').join("") +
    '</dl><p class="muted">Closing this capture clears its session review. Your original file stays on disk.</p><div class="evidence-actions"><button class="secondary" id="closeCapture">Close capture</button></div>';
  $("detailDialog").showModal();
}
async function exportReport(format) {
  const blob = await request("report",scope({format}),true);
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = active + (format === "zip" ? "-casefile.zip" : "-report.html");
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href),30000);
}
document.addEventListener("click", e => {
  const b = e.target.closest("button");
  if (!b || busy) return;
  if (b.matches(".dismiss")) return b.closest("dialog").close();
  if (b.dataset.page) return setPage(b.dataset.page);
  if (b.dataset.id) return task("Opening capture…",() => loadView(b.dataset.id,filters.get(b.dataset.id) || ""));
  if (b.hasAttribute("data-preset")) return task("Applying display filter…",() => loadView(active,b.dataset.preset));
  if (b.dataset.frame) return task("Decoding frame…",async () => {
    const data = await request("frame",scope({frame:b.dataset.frame}));
    $("detailTitle").textContent = active + " · Frame " + b.dataset.frame;
    const facts = [["Protocol stack",data.layers.join(" → ") || "Unavailable"],
      ["Source port",data.src_port ?? "—"], ["Destination port",data.dst_port ?? "—"],
      ["Data format",data.format], ["Payload visibility",data.visibility],
      ["Capture length",fmt(data.captured) + " bytes captured / " + fmt(data.wire) + " bytes on wire"]];
    $("detail").innerHTML = '<dl class="frame-facts">' + facts.map(([label,value]) =>
      '<dt>' + label + '</dt><dd>' + esc(value) + '</dd>').join("") +
      '</dl><details open><summary>Decoded headers and fields</summary><pre id="frameHeaders"></pre></details>' +
      '<details open><summary>Decoded payload</summary><p class="muted" id="payloadInfo"></p><pre class="hex" id="payloadBytes"></pre></details>' +
      '<details><summary>Captured bytes · hex and ASCII</summary><pre class="hex" id="frameBytes"></pre></details>';
    $("frameHeaders").textContent = data.detail || "No protocol fields were decoded.";
    $("frameBytes").textContent = data.hex || "No bytes were available.";
    $("payloadInfo").textContent = data.payload_field ? data.payload_field + " · " + fmt(data.payload_size) +
      " bytes in the first decoded field" + (data.payload_field === "http.file_data" ? " · may include reassembled HTTP data" : "") :
      "The decoder supplied no separate payload field. Inspect the captured frame bytes below.";
    $("payloadBytes").textContent = data.payload || "";
    $("payloadBytes").hidden = !data.payload;
    $("detailDialog").showModal();
  });
  if (b.dataset.stream) return task("Opening TCP stream…",async () => {
    await loadView(active,"tcp.stream == " + b.dataset.stream);
    setPage("packets");
  });
  if (b.id === "closeCapture") return task("Closing capture…",async () => {
    await request("close",scope());
    $("detailDialog").close();
    files = files.filter(c => c.id !== active);
    filters.delete(active);
    showEmpty();
    if (files.length) await loadView(files[0].id, filters.get(files[0].id) || "");
  });
});
$("import").onclick = $("sideImport").onclick = $("emptyImport").onclick = openImport;
$("empty").ondragover = e => { e.preventDefault(); $("empty").classList.add("over"); };
$("empty").ondragleave = () => $("empty").classList.remove("over");
$("empty").ondrop = e => {
  e.preventDefault();
  $("empty").classList.remove("over");
  if (busy || importing || !e.dataTransfer.files.length) return;
  openImport();
  pick(e.dataTransfer.files[0]);
};
$("importDialog").addEventListener("cancel", e => { if (busy) e.preventDefault(); });
$("upload").onchange = () => pick($("upload").files[0]);
$("drop").ondragover = e => { e.preventDefault(); $("drop").classList.add("over"); };
$("drop").ondragleave = () => $("drop").classList.remove("over");
$("drop").ondrop = e => { e.preventDefault(); $("drop").classList.remove("over"); pick(e.dataTransfer.files[0]); };
$("importForm").onsubmit = e => {
  e.preventDefault();
  if (importing) return;
  const file = pickedFile;
  let problem = "";
  if (!file) problem = "Choose a capture file first.";
  else if (!/\.(?:cap|pcap|pcapng)$/i.test(file.name)) problem = "Choose a .cap, .pcap or .pcapng file.";
  else if (!file.size) problem = "This file is empty. Choose a capture with a valid file header.";
  else if (file.size > captureLimit) problem = "Choose a capture up to 5 GiB (5,368,709,120 bytes).";
  if (problem) { $("importError").textContent = problem; return; }
  const params = new URLSearchParams({background:"1",name:file.name,source:$("source").value,acquired:$("acquired").value});
  $("importDialog").close();
  $("importForm").reset();
  pickedFile = null;
  void importCapture(file,params);
};
$("fileInfo").onclick = evidenceDetails;
$("goReport").onclick = () => setPage("report");
$("presetList").innerHTML += Object.entries(filterGroups).map(([group,options]) =>
  '<optgroup label="' + esc(group) + '">' + Object.entries(options).map(([label,value]) =>
    '<option value="' + esc(value) + '">' + esc(label) + '</option>').join("") + '</optgroup>').join("");
$("presetList").onchange = () => {
  const selected = $("presetList").value;
  if (selected) task("Applying display filter…",async () => {
    try { await loadView(active,selected); }
    finally { drawPresets(); }
  });
};
$("filterForm").onsubmit = e => {
  e.preventDefault();
  task("Applying display filter…",async () => {
    try { await loadView(active,$("filter").value.trim()); }
    catch (err) {
      if (!view) throw err;
      throw new Error(err.message + "\nCurrent results still use " + (expression || "All frames") + ".");
    }
  });
};
$("clear").onclick = () => task("Clearing filter…",() => loadView(active,""));
for (const [id,offset] of [["prev",-1],["next",1]]) {
  $(id).onclick = () => task("Loading frames…",async () => drawPackets(await request("packets",scope({page:view.page+offset}))));
}
$("pager").onsubmit = e => {
  e.preventDefault();
  task("Loading frames…",async () => drawPackets(await request("packets",scope({page:$("pageNumber").valueAsNumber-1}))));
};
$("provider").onchange = () => {
  const custom = $("provider").value === "custom";
  $("customSettings").hidden = !custom;
  $("apiEndpoint").disabled = !custom;
  $("apiEndpoint").required = custom;
  $("model").value = $("provider").selectedOptions[0]?.dataset.model || "";
  $("key").value = "";
};
$("apiEndpoint").oninput = $("apiAuth").onchange = $("apiProtocol").onchange = () => { $("key").value = ""; };
$("excerpt").ontoggle = () => {
  if ($("excerpt").open && !$("preview").textContent) task("Preparing evidence preview…",async () => {
    $("preview").textContent = JSON.stringify(await request("preview",scope()),null,2);
  });
};
$("aiForm").onsubmit = e => {
  e.preventDefault();
  task("Waiting for provider review…",async () => {
    const key = $("key").value.trim();
    $("key").value = "";
    const provider = $("provider").value;
    const custom = provider === "custom" ? {endpoint:$("apiEndpoint").value.trim(), protocol:$("apiProtocol").value, auth:$("apiAuth").value} : {};
    view.ai = await request("review",scope({provider, model:$("model").value.trim(), key, ...custom}));
    drawAI();
    drawReport();
  });
};
$("exportHTML").onclick = () => task("Generating report…",() => exportReport("html"));
$("exportZip").onclick = () => task("Packaging casefile…",() => exportReport("zip"));
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("themeMode").setAttribute("aria-pressed",String(theme === "dark"));
  $("themeMode").textContent = "Dark mode";
  $("themeMode").title = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
}
const themePreference = window.matchMedia("(prefers-color-scheme: dark)");
let chosenTheme;
try { chosenTheme = localStorage.getItem("henix.theme"); } catch { /* Browser storage may be unavailable. */ }
applyTheme(chosenTheme || (themePreference.matches ? "dark" : "light"));
themePreference.addEventListener("change", e => { if (!chosenTheme) applyTheme(e.matches ? "dark" : "light"); });
$("themeMode").onclick = () => {
  chosenTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(chosenTheme);
  try { localStorage.setItem("henix.theme",chosenTheme); } catch { /* Keep the choice for this page. */ }
};
showEmpty();
task("Opening local workspace…",async () => {
  const state = await request("status");
  for (const item of state.providers) {
    const option = new Option(item.label,item.id);
    option.dataset.model = item.model;
    $("provider").add(option);
  }
  $("provider").onchange();
  files = state.captures;
  $("engineName").textContent = state.engine.split(" (v")[0].replace(" (Wireshark)", "") || "Decoder unavailable";
  $("engineDot").classList.toggle("ready",Boolean(state.engine));
  showEmpty();
  if (state.error) return notice(state.error);
  const pending = state.imports?.find(job => job.state === "indexing");
  if (pending) void importCapture(null,null,pending);
  else {
    const latest = state.imports?.at(-1);
    if (latest?.state === "failed") importStatus("Could not index " + latest.name, latest.error, null, "Choose capture", openImport);
  }
  if (files.length) await loadView(files[0].id,"");
});
