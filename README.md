# HENIX

**A local network traffic investigation workspace for security analysts and network engineers.** HENIX helps a team trace a connection through a packet capture and hand off findings another analyst can verify. Each finding cites the evidence file and original frame number. The exported casefile records the capture hash, UTC timeline and display filters needed to reproduce it.

[Quick start](#quick-start) · [Investigation workflow](#investigation-workflow) · [Capacity measurements](#capacity-measurements) · [AI and data handling](#ai-and-data-handling)

![HENIX inspecting a plaintext HTTP response in a synthetic capture. The inspector shows the protocol stack, ports, content type, capture length and decoded headers.](docs/images/frame-inspector.png)

*An HTTP response from the test fixture. Frame 7 shows traffic from port 80 to port 51001, a text/plain body, and all 120 on-wire bytes present in the capture.*

## Investigation workflow

**Example analyst question** — A workstation contacted an unfamiliar address. What name did it resolve, which service did it reach, and what did the capture actually reveal?

| Step | What the analyst does | Evidence for the handoff |
| --- | --- | --- |
| Establish scope | Import a `.cap`, `.pcap` or `.pcapng` file. Record its source and acquisition date. | Original filename, SHA-256, evidence ID and UTC capture window. |
| Trace the connection | Inspect a DNS reply, then follow a TCP stream from the same client to an address in the answer. | Query, reply and connection frames from the same capture. |
| Inspect the exchange | Open a frame to examine its protocol stack, ports, decoded headers, payload and hex/ASCII bytes. | An HTTP method or status when visible, or the fields exposed by a TLS handshake. |
| Hand off the case | Export the filtered investigation as standalone HTML or a ZIP casefile. | Packet citations, a flow diagram, CSV manifest and timeline, alternative explanations and reproduction steps. |

A DNS answer followed by a connection to the returned IP supports an association. Identifying the process that opened the connection requires endpoint telemetry. HENIX keeps that distinction visible in the report.

### Useful display filters

| Investigation question | Wireshark filter |
| --- | --- |
| Which DNS replies are visible? | `dns.flags.response == 1` |
| What happened in one TCP conversation? | `tcp.stream == 0` (substitute the observed stream ID) |
| Which HTTP requests or responses were decoded? | `http.request || http.response` |
| Which frames contain a TLS Client Hello? | `tls.handshake.type == 1` |
| Where did capture truncation limit visibility? | `frame.cap_len < frame.len` |

Packet Explorer, statistics, AI evidence previews and reports share the applied filter. Enter `frame.number == N` to jump to a cited frame using the index.

## Quick start

Install **Python 3.10+** and **Wireshark 4.4+ with TShark**. HENIX uses the Python standard library. [Wireshark downloads](https://www.wireshark.org/download.html)

```sh
git clone https://github.com/VadherHenil/network-traffic-investigation.git
cd network-traffic-investigation
python app.py
```

The app opens in your browser at `http://127.0.0.1:8765` by default. Choose **Import capture** to begin. On Windows, you can also double-click **Start HENIX.cmd**. Keep the console open for the duration of the session.

| Setting | When to use it |
| --- | --- |
| `python app.py --work-dir "D:\HENIX-Work"` | Put working copies and indexes on an existing directory with sufficient free space. |
| `python app.py --port 0 --no-browser` | Choose a free local port and print the address without opening a tab. |
| `TSHARK_PATH` | Point HENIX to a TShark executable outside its standard installation locations. |

## Capacity measurements

HENIX accepts **up to 5 GiB per capture**. Python streams the upload to disk while calculating SHA-256. TShark decodes the frames and SQLite indexes their metadata for paginated inspection. Up to eight captures can be open. One import runs at a time, and previously indexed files remain available during indexing.

The following measurements come from generated captures on the Windows development machine with TShark 4.6.10.

| Capture | Frames | SQLite index | Measured result |
| --- | ---: | ---: | --- |
| 5 GiB mixed test capture | 655,372 | 151 MiB | 102 s to upload and index. The full verification run took 350 s. |
| 33 MiB of short ARP frames | 600,000 | 118 MiB | 13.9 s to index. |

The two captures have similar packet counts despite their different file sizes. Size the workspace using representative traffic. Allow space for the working copy, index and temporary sort files. New display filters and inspection of late frames can require a scan of the capture.

<details>
<summary><strong>Dissection and display limits</strong></summary>

Files over 32 MiB use single-pass dissection for indexing and frame inspection, so a request may lack a forward reference to a later response. Smaller files use two passes. General display filters use two-pass dissection. The overview counts every decoded protocol layer and displays up to 100 TCP streams and 4,096 protocol hierarchy paths. Header and payload visibility depend on the captured bytes and available dissectors.

</details>

## AI and data handling

**Local investigation works offline.** The server binds to IPv4 loopback. HENIX keeps temporary working copies and indexes for the session. Export the casefile before closing a capture or stopping the server. Normal shutdown clears session data; the original capture remains at its source.

**AI review is optional.** Built-in choices include OpenAI, Anthropic Claude, Google AI Studio Gemini, xAI Grok, Groq, DeepSeek and OpenRouter. The analyst selects a model and previews the excerpt before submitting it. The provider receives the display filter and selected metadata from up to 40 matching frames. Endpoints, DNS names and filter values can identify internal systems. The app clears the API key from the form on submission and does not save it.

For an internal gateway, choose **Custom endpoint**, enter the full inference URL and select Chat Completions, Responses, Anthropic Messages or Gemini generateContent. Choose the key header required by the gateway. Gemini-format URLs use `{model}` in the path. Remote endpoints use HTTPS; loopback endpoints can use HTTP.

## Verification

Run the regression suite from the project directory. Decoder tests use real TShark dissection. Provider tests use simulated responses and require no credentials.

```sh
python -m unittest discover -s tests -v
```

To repeat the 5 GiB capacity check, supply an existing scratch directory. The check verifies the upload hash, frame count, final packet page, display filter, frame inspection, AI excerpt, HTML and ZIP exports, and working-file cleanup.

```powershell
python -m tests.large_capture_check --gib 5 --work-dir "D:\HENIX-Work"
```

For a denser workload of approximately 3.5 million frames, add `--record-size 1530`. [Capacity test implementation](tests/large_capture_check.py)
