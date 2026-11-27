"use strict";

const caseDialog = $("caseDialog");
const caseMessage = $("caseMessage");
let openingCase = false;

$("caseFiles").onclick = () => {
  $("caseSaveSection").hidden = !active;
  caseMessage.textContent = "";
  caseDialog.showModal();
};
caseDialog.addEventListener("cancel", event => {
  if (openingCase) event.preventDefault();
});
$("saveCase").onclick = async () => {
  try {
    const ticket = await request("case-save", scope());
    const link = document.createElement("a");
    link.href = ticket.url;
    link.download = active + ".henix";
    document.body.append(link);
    link.click();
    link.remove();
    caseMessage.textContent = "Case download requested. Check progress in your browser’s downloads.";
  } catch (error) {
    caseMessage.textContent = error.message;
  }
};
function uploadCase(file, rebuild) {
  return new Promise((resolve, reject) => {
    const upload = new XMLHttpRequest();
    upload.open("POST", "/api/case-open" + (rebuild ? "?rebuild=1" : ""));
    upload.setRequestHeader("X-HENIX", "workspace");
    upload.setRequestHeader("Content-Type", "application/octet-stream");
    upload.responseType = "json";
    upload.upload.onprogress = event => {
      if (event.lengthComputable) caseMessage.textContent = "Reading case · " + size(event.loaded) + " of " + size(event.total);
    };
    upload.upload.onload = () => { caseMessage.textContent = "Checking integrity and opening the packet index…"; };
    upload.onerror = () => reject(new Error("The case transfer failed. Check that the local server is running."));
    upload.onload = () => {
      if (upload.status === 200 && upload.response?.capture) resolve(upload.response);
      else reject(new Error(upload.response?.error || "The server could not open this case."));
    };
    upload.send(file);
  });
}
$("openCase").onclick = async () => {
  const file = $("caseInput").files[0];
  if (!file) {
    caseMessage.textContent = "Select a .henix case to open.";
    return;
  }
  if (openingCase) return;
  openingCase = true;
  caseDialog.querySelectorAll("button,input").forEach(control => { control.disabled = true; });
  try {
    const result = await uploadCase(file, $("caseRebuild").checked);
    let message = result.index_reused ? "Case opened with its saved index." : "Case opened with a rebuilt index.";
    try {
      await loadView(result.capture.id, result.filter);
    } catch (error) {
      if (!result.filter) throw error;
      await loadView(result.capture.id, "");
      message += " The saved filter could not be applied: " + error.message;
    }
    $("caseInput").value = "";
    setPage("overview");
    caseDialog.close();
    notice(message);
  } catch (error) {
    caseMessage.textContent = error.message;
  } finally {
    openingCase = false;
    caseDialog.querySelectorAll("button,input").forEach(control => { control.disabled = false; });
  }
};
