"""Standalone, printable evidence report and reproducible casefile export."""

import csv
import io
import re
import zipfile
from html import escape
from datetime import datetime, timezone

from analyst import annotations
from capture import address, endpoint, port, utc, version
from findings import investigate
from large_metrics import layer_inventory
from providers import approved_review


INVALID_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def h(value):
    return escape(INVALID_TEXT.sub("\ufffd", str(value)), quote=True)


def flow_diagram(ref, events):
    """Sequence diagram for the first four hosts in the cited timeline."""
    endpoints = list(dict.fromkeys(ep for e in events for ep in (e["src_host"], e["dst_host"])))[:4]
    shown = [e for e in events if e["src_host"] in endpoints and e["dst_host"] in endpoints][:100]
    width, height = max(500, len(endpoints) * 225), 90 + len(shown) * 36
    pos = {ep: 110 + i * 225 for i, ep in enumerate(endpoints)}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Observed packet directions for {h(ref)}"><title>Observed packet directions</title>'
             '<rect width="100%" height="100%" fill="#f2f6ef"/>',
             f'<text x="12" y="18" font-family="monospace" font-size="11" fill="#496451">{h(ref)} · '
             f'{len(shown)} of {len(events)} timeline events</text>']
    for ep, x in pos.items():
        label = ep if len(ep) < 32 else ep[:18] + "…" + ep[-9:]
        parts.append(f'<line x1="{x}" x2="{x}" y1="50" y2="{height-12}" stroke="#b6c8b9" stroke-dasharray="3 4"/>'
                     f'<text x="{x}" y="42" text-anchor="middle" font-family="monospace" font-size="11">'
                     f'<title>{h(ep)}</title>{h(label)}</text>')
    for i, e in enumerate(shown):
        a, b, y = pos[e["src_host"]], pos[e["dst_host"]], 77 + i * 36
        direction = 1 if b >= a else -1
        parts.append(f'<line x1="{a}" x2="{b}" y1="{y}" y2="{y}" stroke="#53755f" stroke-width="2"/>'
                     f'<path d="M {b} {y} l {-7*direction} -4 v 8 z" fill="#53755f"/>'
                     f'<text x="{(a+b)//2}" y="{y-6}" text-anchor="middle" font-family="monospace" '
                     f'font-size="12">#{h(e["frame"])}</text>')
    return "".join(parts) + "</svg>"


def acquisition_history(capture):
    return getattr(capture, "acquisitions", [{"name": capture.name, "source": capture.source,
                                             "acquired": capture.acquired, "imported_at": ""}])


def report_events(capture, auto_events, pins):
    """Preserve selected evidence across filters; label analyst and decoder observations."""
    by_frame = {e["frame"]: {**e, "origin": "Decoder"} for e in auto_events}
    notes = {}
    for pin in pins:
        for number in pin["frames"]:
            notes.setdefault(number, []).append(pin["note"])
    numbers = sorted(set(by_frame) | set(notes), key=int)
    for i in range(0, len(numbers), 500):
        chunk = numbers[i:i+500]
        marks = ",".join("?" for _ in chunk)
        for row in capture.rows.search(f'"frame.number" IN ({marks})', tuple(chunk)):
            number = row["frame.number"]
            event = by_frame.setdefault(number, dict(frame=number, time=utc(row.get("frame.time_epoch")),
                src=endpoint(row, "src"), dst=endpoint(row, "dst"), src_host=address(row,"src"),
                dst_host=address(row,"dst"), observation="", origin="Analyst pin"))
            event.update(src_port=port(row,"src"), dst_port=port(row,"dst"))
            if number in notes:
                if event["origin"] == "Decoder":
                    event["origin"] = "Decoder and analyst pin"
                messages = [note for note in notes[number] if note]
                event["observation"] = "\n".join(filter(None, [event["observation"], *messages])) or "Pinned frame"
    return sorted(by_frame.values(), key=lambda e: (e["time"], int(e["frame"])))


def build_report(capture, rows, expression, ai=None):
    ai = approved_review(ai)
    findings, events = investigate(rows)
    state = annotations(capture)
    ref = capture.id
    window = " to ".join(capture.window) or "Empty capture"
    scope = " to ".join(capture.time_window(rows)) or "No matching timestamps"
    decision = " ".join(f["observation"] for f in findings) or "No frames matched the selected scope."
    next_step = ("Request process-to-connection records for " + events[0]["src"]
                 + " and the other cited endpoints during " + scope
                 + ". Compare process image, user and connection times with the frames below."
                 if events else "Review the display filter or import a capture containing the connection of interest.")
    alternative = ("Browser activity, an updater, and other processes can generate similar traffic. "
                   "Use endpoint records to determine which process initiated the exchange."
                   if events else "There is insufficient packet evidence in this view to compare explanations.")
    sections = []
    for f in findings:
        refs = ", ".join(f"{ref} #{n}" for n in f["frames"])
        sections.append(f"<article><h3>{h(f['title'])}</h3><p>{h(f['observation'])}</p>"
                        f"<p>{h(f['meaning'])}</p><small>{h(refs)}</small></article>")
    pinned = []
    for pin in state["pins"]:
        refs = ", ".join(f"{ref} #{n}" for n in pin["frames"])
        pinned.append(f"<article><p class='ai'>{h(pin['note']) or 'Pinned evidence'}</p><small>{h(refs)}</small></article>")
    analyst_section = ""
    if state["conclusion"] or pinned:
        analyst_section = "<h2>Analyst assessment</h2>"
        if state["conclusion"]:
            analyst_section += f"<h3>Conclusion</h3><p class='ai'>{h(state['conclusion'])}</p>"
        if pinned:
            analyst_section += ("<h3>Pinned evidence</h3><p>Analyst-selected references span the capture and can "
                                "fall outside the report display filter.</p>" + "".join(pinned))
    events = report_events(capture, events, state["pins"])
    timeline = "".join(f"<tr><td>{h(ref)} #{h(e['frame'])}</td><td>{h(e['time'])}</td>"
                       f"<td>{h(e['src'])}<br>→ {h(e['dst'])}</td><td>{h(e['origin'])}</td><td class='ai'>{h(e['observation'])}</td></tr>"
                       for e in events)
    acquisition_table = "".join("<tr>" + "".join(f"<td>{h(a.get(key) or '—')}</td>" for key in
        ("name","source","acquired","imported_at")) + "</tr>" for a in acquisition_history(capture))
    facts = {"Evidence ID": ref, "Original file": capture.name, "SHA-256": capture.digest,
             "Source": capture.source or "Local import · source unspecified",
             "Acquisition date": capture.acquired or "Unspecified", "Decoder": version(),
             "Capture window (UTC)": window, "Matching window (UTC)": scope,
             "Display filter": expression or "All frames", "Matching frames": f"{len(rows):,} of {len(capture.rows):,}"}
    if capture.dissection_passes == 1:
        facts["Metadata index"] = "Single-pass dissection. Forward references may be unavailable in indexed fields."
    else:
        facts["Metadata index"] = "Two-pass dissection."
    meta = "".join(f"<dt>{h(k)}</dt><dd>{h(v)}</dd>" for k, v in facts.items())
    inventory = "".join(f"<tr><td>{h(layer)}</td><td>{count:,}</td></tr>"
                        for layer, count in layer_inventory(rows))
    review = ""
    if ai:
        state = "Complete" if ai["complete"] else "Partial response"
        review = (f"<h2>AI review</h2><p>{h(ai.get('provider_label', ai['provider']))} · {h(ai['model'])} · {state} · "
                  f"{ai['included']} of {ai['matched']} matching frames supplied. Verify generated interpretations "
                  f"against the frame references.</p><div class='ai'>{h(ai['text'])}</div>")
    html = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>HENIX investigation · {h(capture.name)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><style>
*{{box-sizing:border-box}}body{{margin:0;background:#e9eceb;color:#192822;font:15px/1.55 'Segoe UI',sans-serif}}
main{{max-width:940px;margin:28px auto;padding:48px 55px;background:white;border-top:6px solid #de623c}}
header{{display:flex;justify-content:space-between;border-bottom:1px solid #b7c2bc;padding-bottom:13px}}
h1{{font:600 38px/1.12 Georgia,serif;margin:32px 0 8px}}h2{{font-size:21px;border-bottom:1px solid #d5ded7;padding-bottom:5px;margin-top:30px}}
h3{{font-size:17px;margin:0}}article{{break-inside:avoid;border-left:3px solid #db6c47;padding:4px 15px;margin:20px 0}}
p{{margin:7px 0}}small,code,dd,td:first-child{{font-family:Consolas,monospace}}small{{color:#72513d}}
dl{{display:grid;grid-template-columns:155px 1fr;gap:5px 15px}}dt{{color:#4c5e54}}dd{{margin:0}}
table{{border-collapse:collapse;width:100%;font-size:12px}}th,td{{text-align:left;vertical-align:top;padding:7px;border-bottom:1px solid #d7ded9}}
th{{background:#eff4ef}}.ai{{white-space:pre-wrap}}main{{overflow-wrap:anywhere}}footer{{color:#55645b;font-size:12px;margin-top:25px}}
@page{{size:auto;margin:15mm}}@media print{{body{{background:white}}main{{margin:0;padding:0;border:none;max-width:none}}tr{{break-inside:avoid}}h2,h3{{break-after:avoid}}}}
@media(max-width:600px){{main{{padding:18px;margin:0}}dl{{display:block}}dd{{margin-bottom:8px}}table{{font-size:10px}}}}</style>
<main><header><b>HENIX</b><span>Network investigation</span></header><h1>Investigation report</h1>
<p>{h(capture.name)} · {h(ref)}</p><h2>Decision and scope</h2><p>{h(decision)}</p>
<p>This review covers {len(rows):,} of {len(capture.rows):,} frames and highlights selected exchanges.
Capture boundaries and the display filter limit the automated conclusions.</p><dl>{meta}</dl>
<h2>Acquisition history</h2><table><thead><tr><th>Filename</th><th>Source</th><th>Acquired</th>
<th>Imported (UTC)</th></tr></thead><tbody>{acquisition_table}</tbody></table>{analyst_section}<h2>Packet findings</h2>
{''.join(sections) or '<p>No observations are available for this scope.</p>'}
<h2>Observed flow</h2>{flow_diagram(ref, events) if events else ''}<table><thead><tr><th>Reference</th><th>Time (UTC)</th><th>Direction</th><th>Origin</th><th>Observation</th></tr></thead>
<tbody>{timeline}</tbody></table><h2>Alternative explanation</h2><p>{h(alternative)}</p>
<h2>Recommended next step</h2><p>{h(next_step)}</p>{review}
<h2>Decoded protocol layers</h2><p>Each count is the number of matching frames containing the layer.
A frame can contain several layers.</p><table><thead><tr><th>Dissector ID</th><th>Frames</th></tr></thead>
<tbody>{inventory or '<tr><td colspan="2">No decoded layers in this scope.</td></tr>'}</tbody></table><h2>Reproduction</h2><ol>
<li>Open the original capture in Wireshark and verify the SHA-256 above.</li>
<li>Set time display to UTC and apply <code>{h(expression) if expression else '(clear the display filter)'}</code>.</li>
<li>Locate each cited frame with <code>frame.number == N</code>. Expand the matching protocol fields
and compare the endpoints and timestamps with the observed flow.</li></ol>
<footer>Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · HENIX</footer></main></html>"""
    return html, events


def csv_data(columns, rows):
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(columns)
    for row in rows:
        writer.writerow(["'" + str(v) if str(v).lstrip().startswith(("=", "+", "-", "@")) else v for v in row])
    return INVALID_TEXT.sub("\ufffd", out.getvalue()).encode("utf-8-sig")


def bundle(capture, rows, expression, ai):
    html, events = build_report(capture, rows, expression, ai)
    timeline = []
    for event in events:
        timeline.append([capture.id, event["frame"], event["time"], event["src_host"], event["src_port"],
                         event["dst_host"], event["dst_port"], event["observation"], event["origin"]])
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report/investigation.html", html)
        if events:
            archive.writestr("diagrams/observed-flow.svg", flow_diagram(capture.id, events))
        archive.writestr("evidence/manifest.csv", csv_data(
            ["Evidence ID", "Filename", "Source", "Acquisition date", "SHA-256", "Decoder", "Index dissection passes",
             "Capture start UTC", "Capture end UTC", "Imported UTC"],
            [[capture.id, a["name"], a["source"], a["acquired"], capture.digest, version(),
              capture.dissection_passes, *(capture.window or ["", ""]), a["imported_at"]]
             for a in acquisition_history(capture)]))
        archive.writestr("evidence/timeline.csv", csv_data(
            ["Evidence ID", "Frame", "Time (UTC)", "Source address", "Source port", "Destination address", "Destination port", "Observation", "Origin"],
            timeline))
        archive.writestr("analysis/display-filters.txt", "Scope\n" + (expression or "(all frames)") +
                         "\n\nCited frames\n" + "\n".join("frame.number == " + e["frame"] for e in events))
    return output.getvalue()
