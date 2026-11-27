"use strict";

let conversationPage = 0, searchedTerm = "", editFrames = [], annotationOwner = "";

function resetConversationSearch() {
  conversationPage = 0;
  searchedTerm = "";
  $("conversationQuery").value = "";
  $("conversationPager").hidden = true;
}

async function searchStreams(pageNumber, term) {
  const data = await request("conversations", scope({page:pageNumber, search:term}));
  conversationPage = data.page;
  searchedTerm = term;
  $("conversationPage").textContent = "Page " + (conversationPage+1);
  $("conversationPrev").disabled = conversationPage === 0;
  $("conversationNext").disabled = !data.has_more;
  $("conversationPager").hidden = conversationPage === 0 && !data.has_more;
  $("streams").innerHTML = data.streams.length ? '<div class="tablewrap"><table><thead><tr><th>Stream</th><th>Endpoint A</th><th>Endpoint B</th><th>Packets</th><th>Bytes</th><th>Matching frame bounds</th></tr></thead><tbody>' +
    data.streams.map(s => '<tr><td><button class="ref" data-stream="' + esc(s.stream) + '">Stream ' + esc(s.stream) +
      '</button></td><td>' + esc(s.a) + '</td><td>' + esc(s.b) + '</td><td>' + fmt(s.packets) +
      '</td><td>' + fmt(s.bytes) + '</td><td><button class="secondary" data-pin="' +
      esc([...new Set([s.first,s.last])].join(",")) + '" data-pin-note="TCP stream ' + esc(s.stream) +
      ' · first and last matching frames">Pin #' + esc(s.first) + (s.first === s.last ? "" : " and #" + esc(s.last)) +
      '</button></td></tr>').join("") + '</tbody></table></div>' : '<p class="emptymsg">No TCP streams match this search and display filter.</p>';
}

function drawAnnotations() {
  const state = view.annotations || {pins:[],conclusion:""};
  // Keep unsaved typing when unrelated sections of the same report refresh.
  if (annotationOwner !== active || $("conclusion").value === $("conclusion").defaultValue) {
    $("conclusion").value = state.conclusion;
  }
  $("conclusion").defaultValue = state.conclusion;
  annotationOwner = active;
  $("pins").innerHTML = state.pins.map(pin => {
    const key = esc(pin.frames.join(","));
    return '<div class="finding"><div class="refs">' + pin.frames.map(n =>
      '<button class="ref" data-frame="' + esc(n) + '">#' + esc(n) + '</button>').join(" ") +
      '</div><div><p class="analyst-note">' + (esc(pin.note) || "Pinned frame") +
      '</p><button class="secondary" data-pin="' + key + '">Edit note</button> ' +
      '<button class="secondary" data-unpin="' + key + '">Remove pin</button></div></div>';
  }).join("") || '<p class="emptymsg">Select a frame or exchange to pin evidence.</p>';
}

document.addEventListener("DOMContentLoaded", () => {
  $("conversationSearch").onsubmit = e => {
    e.preventDefault();
    task("Searching TCP conversations…", () => searchStreams(0,$("conversationQuery").value.trim()));
  };
  for (const [id,offset] of [["conversationPrev",-1],["conversationNext",1]]) {
    $(id).onclick = () => task("Searching TCP conversations…", () => searchStreams(conversationPage+offset,searchedTerm));
  }
  document.addEventListener("click", e => {
    const button = e.target.closest("button");
    if (!button || busy) return;
    if (button.dataset.pin || button.id === "addFramePin") {
      const custom = button.id === "addFramePin";
      editFrames = custom ? [] : button.dataset.pin.split(",").sort((a,b)=>Number(a)-Number(b));
      const existing = view.annotations?.pins.find(pin => pin.frames.join(",") === editFrames.join(","));
      $("pinNote").value = existing?.note ?? button.dataset.pinNote ?? "";
      $("pinRefs").textContent = custom ? active : active + " · " + editFrames.map(n=>"#"+n).join(", ");
      $("customPin").hidden = !custom;
      $("pinNumbers").disabled = !custom;
      $("pinNumbers").value = "";
      $("pinError").textContent = "";
      $("pinDialog").showModal();
      $(custom ? "pinNumbers" : "pinNote").focus();
    } else if (button.dataset.unpin) {
      task("Removing pin…",async () => {
        view.annotations = await request("annotations",scope({action:"remove",frames:button.dataset.unpin.split(",")}));
        drawAnnotations();
      });
    }
  });
  $("pinForm").onsubmit = async e => {
    e.preventDefault();
    const pinId = active;
    const submit = $("pinForm").querySelector("[type=submit]");
    if (submit.disabled) return;
    submit.disabled = true;
    try {
      const frames = $("pinNumbers").disabled ? editFrames : $("pinNumbers").value.trim().split(/[\s,]+/);
      const state = await request("annotations",scope({action:"pin",frames,note:$("pinNote").value}));
      if (active === pinId && view) {
        view.annotations = state;
        drawAnnotations();
      }
      $("pinDialog").close();
    } catch (error) {
      $("pinError").textContent = error.message;
    } finally { submit.disabled = false; }
  };
  $("conclusionForm").onsubmit = e => {
    e.preventDefault();
    task("Saving conclusion…",async () => {
      view.annotations = await request("annotations",scope({action:"conclusion",conclusion:$("conclusion").value}));
      $("conclusion").value = view.annotations.conclusion;
      drawAnnotations();
      notice("Conclusion saved in this workspace.");
    });
  };
});
