# HENIX

A local Python app for investigating saved network captures with Wireshark display filters. A new workspace opens empty. Import a capture to see its decoded protocol layers, endpoints, ports and packet details. Each observation cites a content-derived evidence ID and the original frame number.

## Run the app

On this Windows workspace, double-click **Start HENIX.cmd**. Keep its console open while using the app. The launcher chooses a free local port and opens your browser.

For a fresh checkout, install **Python 3.10+** and **Wireshark 4.4+** with the TShark component. The app uses the Python standard library and runs on Windows, macOS and Linux. It reads files offline. Live-capture drivers are optional. [Wireshark downloads](https://www.wireshark.org/download.html)

```sh
python app.py
```

Open the address printed in the console. The default is `http://127.0.0.1:8765`. Use `python app.py --port 0 --no-browser` to choose a free port without opening a tab. The app looks for TShark on PATH, in the standard Windows or macOS installation directory, or in the workspace's private runtime. Set `TSHARK_PATH` to an executable to override discovery.

### Multi-gigabyte captures

HENIX accepts individual capture files up to **5 GiB (5,368,709,120 bytes)**, including a 5 GB decimal file. It streams the upload to a session working copy, computes SHA-256, then builds a SQLite frame index on disk. There is no fixed frame-count limit. One import runs at a time. The progress panel shows bytes transferred during upload and frame count during indexing. You can inspect another open capture while the new file is indexed. Refreshing after indexing has started reconnects to the running job. Keep the browser open until the upload completes.

Choose a workspace drive with room for both the working copy and the index. Index size and run time depend on frame count and protocol fields. A small-packet capture can require substantially more index space than another capture of the same file size. TShark also uses memory for protocol state and reassembly. To place session data on a specific drive, supply an existing directory when starting the server.

```powershell
python app.py --work-dir "D:\HENIX-Work"
```

Opening a large capture for the first time, applying a new Wireshark filter, and inspecting a late frame can take time proportional to the capture size. Packet Explorer shows one page at a time and lets you enter a page number directly. Use a stream, endpoint or protocol filter to narrow an investigation.

The overview shows the count for every decoded protocol layer. It lists the 100 busiest TCP streams and up to 4,096 of the most frequent protocol hierarchy paths, with the total number of streams and paths available when those lists are truncated.

## Investigate a capture

1. Choose **Import capture** and select a `.cap`, `.pcap` or `.pcapng` file. Add the source and acquisition date if known. Up to eight distinct captures can be open at once.
2. Check **Evidence details** for the original filename, SHA-256 and capture window in UTC. Use the sidebar to switch between evidence files.
3. Enter a Wireshark **display filter** and choose **Apply**, or choose a preset. The charts, packets, findings, AI excerpt and report share the applied filter. Selecting a TCP conversation opens that entire stream.
4. In **Packet explorer**, check the source and destination ports for frames that carry them. Select a frame to inspect its decoded headers, payload visibility and captured bytes. The overview lists layers identified by your installed TShark dissectors. HENIX uses a single-pass index and frame inspector for files over 32 MiB. A request can therefore lack a forward reference to a later response. Smaller captures use two-pass dissection. A direct `frame.number == N` lookup uses the packet index. Other Wireshark display filters use two-pass dissection across the capture.
5. Open **Report** and download the standalone HTML report or the ZIP casefile. Open the HTML in a browser and choose **Print → Save as PDF** for a PDF copy.

Use the theme switch to choose a light or dark workspace.

### Inspect headers and payloads

Packet captures can contain multiple protocol layers, including encapsulated headers. An ARP frame typically has addresses and no transport ports. A TCP segment can carry an HTTP request, a TLS record, another application format or bytes the decoder cannot identify. The available fields depend on the captured bytes, the dissector and any usable decryption information. A port number alone cannot establish the application protocol or encryption state. For a truncated frame, inspection is limited to the bytes present in the file.

| Example display filter | What to inspect |
| --- | --- |
| `dns.flags.response == 1` | DNS replies and their answers |
| `tcp.stream == 0` | Both directions of TCP stream 0, if present |
| `tcp.flags.syn == 1` | TCP SYN and SYN/ACK headers |
| `udp.dstport == 53` | UDP datagrams addressed to port 53 |
| `http.request || http.response` | Decoded HTTP requests and responses |
| `tls.handshake.type == 1` | TLS Client Hello messages |
| `frame.cap_len < frame.len` | Frames whose recorded bytes are shorter than their reported lengths |

The workspace highlights one DNS exchange, one TCP stream, one HTTP exchange and one TLS Client Hello where present. A TCP stream containing a decoded HTTP request takes priority for the connection finding. Use a stream filter to focus the report on another connection. A DNS-to-TCP association requires a matched query/reply pair, the same client, an address from the answer and a later SYN in the same file. A Client Hello alone establishes only an attempt to negotiate TLS.

## Optional AI review

In **AI review**, choose **OpenAI**, **Anthropic (Claude)**, **Google AI Studio (Gemini)**, **xAI (Grok)**, **Groq**, **DeepSeek**, or **OpenRouter**. Enter a model ID available to your account and the provider's API key. Expand **Evidence sent to the provider** to inspect the evidence object. **Send excerpt for review** calls the provider and can incur usage charges. The request includes a fixed analysis instruction and the previewed evidence.

For another service or an internal gateway, select **Custom endpoint**. Enter its full inference URL, choose its API format (Chat Completions, Responses, Anthropic Messages, or Gemini generateContent), and choose the API key header. For Gemini-format endpoints, use `{model}` in the URL where the model ID belongs. Remote endpoints require HTTPS. A loopback endpoint can use HTTP. Enter credentials in the API key field. A service using a different request format requires a corresponding adapter.

The excerpt includes the display filter and up to 40 matching frames, prioritizing cited events before filling the sample in capture order. It includes endpoints, timestamps, DNS names and selected protocol fields. Packet bodies, full packet descriptions and HTTP paths are excluded from the excerpt fields. A filter you enter can itself contain sensitive values. The API key is cleared from the form on submission and never saved. Model IDs are editable to accommodate provider availability.

Provider responses are associated with the evidence ID and exact filter. Review the generated citations before sharing a report. Local findings and exports work offline with no provider key. [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses/create) · [Google Gemini generateContent](https://ai.google.dev/api/generate-content)

## Export and session lifetime

The HTML report contains the decision and scope, packet findings, flow diagram, UTC timeline, decoded protocol inventory, alternative explanations, next telemetry request and reproduction steps. The ZIP includes that report, a CSV manifest, CSV timeline with source and destination port columns, display-filter list and an SVG flow diagram when observations are available. The diagram shows the first four observed hosts. The timeline preserves all selected events. Original packet bytes stay out of exports.

The server listens on the IPv4 loopback interface. It holds evidence metadata and reviews in memory and places working copies in a temporary directory. Closing an evidence item removes its working copy. Stopping the server normally clears the session, including temporary copies. Browser refresh reconnects to the running server. Export the casefile before stopping or closing a capture.

## Verification

```sh
python -m unittest discover -s tests -v
```

The decoder tests use TShark and test fixtures. Provider tests use simulated API responses and run without credentials.

To repeat the capacity check on a deployment machine, run this from the project directory and give it an existing scratch directory with room for the capture and index.

```powershell
python -m tests.large_capture_check --gib 5 --work-dir "D:\HENIX-Work"
```

This opt-in test generates exactly 5 GiB of valid PCAP records through the HTTP upload endpoint. It checks the SHA-256, frame count, final packet page, Wireshark display filter, frame dissection, AI evidence preview, HTML/ZIP reports and deletion of the working files. Use `--record-size 1530` to exercise a denser file with approximately 3.5 million frames. SQLite grouping and sorting can also use the operating system's temporary drive.

On the Windows development machine with TShark 4.6.10, the 5 GiB test indexed 655,372 frames. Upload and indexing together took 102 seconds. The entire check, including a two-pass filter and inspection of the final frame, took 350 seconds. The main SQLite index occupied 151 MiB. In a separate test with 600,000 short ARP frames, a 33 MiB capture produced a 118 MiB index. Use representative captures from the intended deployment to measure disk requirements and filter latency.
