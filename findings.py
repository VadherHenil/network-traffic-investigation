"""Build a small set of reproducible findings from frames in the applied view."""

from capture import address, endpoint, utc


def next_seq(row):
    seq, length = row.get("tcp.seq_raw", ""), row.get("tcp.len", "")
    if seq.isdecimal() and length.isdecimal():
        return str((int(seq) + 1 + int(length)) % 2**32)
    return None


def _indexed_candidates(rows):
    """Find the exchanges across the entire SQL scope, then load only their frames."""
    anchors = {
        "first": "1",
        "request": '"http.request.method" IS NOT NULL',
        "response": '"http.response.code" IS NOT NULL',
        "tcp": '"tcp.stream" IS NOT NULL',
        "syn": '''"tcp.flags.syn"='1' AND "tcp.flags.ack"='0' ''',
        "query": '''"dns.flags.response"='0' ''',
        "reply": '''"dns.flags.response"='1' ''',
        "hello": '''instr(',' || "tls.handshake.type" || ',', ',1,')>0''',
    }
    with rows.connection() as db:
        columns = ", ".join(f'MIN(CASE WHEN {condition} THEN "frame.number" END)' for condition in anchors.values())
        numbers = dict(zip(anchors, db.execute("SELECT " + columns + " FROM scoped").fetchone()))
    selected = {str(n): rows.get_frame(n) for n in set(numbers.values()) if n is not None}

    def first(where, params, accept=None):
        # A candidate filter can match retransmissions; validate endpoints
        # before accepting a segment as the handshake reply or final ACK.
        candidates = rows.search(where, params, limit=1 if accept is None else None)
        row = next((r for r in candidates if accept is None or accept(r)), None)
        if row:
            selected[row["frame.number"]] = row
        return row

    request = selected.get(str(numbers["request"]))
    focus = request or selected.get(str(numbers["syn"])) or selected.get(str(numbers["tcp"]))
    stream = focus.get("tcp.stream") if focus else None
    syn = None
    if stream is not None:
        syn = first('''"tcp.stream"=? AND "tcp.flags.syn"='1' AND "tcp.flags.ack"='0' ''', (stream,))
    if syn:
        expected = next_seq(syn)
        if expected is not None:
            sa = first('''"tcp.stream"=? AND "frame.number">? AND "tcp.flags.syn"='1'
                          AND "tcp.flags.ack"='1' AND "tcp.ack_raw"=?''',
                       (stream, int(syn["frame.number"]), expected),
                       lambda r: endpoint(r, "src")==endpoint(syn, "dst") and endpoint(r, "dst")==endpoint(syn, "src"))
            target = next_seq(sa) if sa else None
            if target is not None:
                first('''"tcp.stream"=? AND "frame.number">? AND "tcp.flags.syn"='0'
                         AND "tcp.flags.reset"='0' AND "tcp.flags.ack"='1'
                         AND "tcp.ack_raw"=? AND "tcp.seq_raw"=?''',
                      (stream, int(sa["frame.number"]), target, expected),
                      lambda r: endpoint(r, "src")==endpoint(syn, "src") and endpoint(r, "dst")==endpoint(syn, "dst"))

    if request:
        response = rows.get_frame(request.get("http.response_in")) if request.get("http.response_in") else None
        if response is not None:
            selected[response["frame.number"]] = response
        elif stream is not None:
            first('''"tcp.stream"=? AND "http.request_in"=? AND "http.response.code" IS NOT NULL''',
                  (stream, request["frame.number"]))

    if numbers["query"] is not None and numbers["reply"] is not None:
        def host(alias, direction):
            column = "Source" if direction == "src" else "Destination"
            return (f'COALESCE({alias}."_ws.col.{column}", {alias}."ip.{direction}", '
                    f'{alias}."ipv6.{direction}", {alias}."eth.{direction}")')

        def port(alias, direction):
            return (f'COALESCE({alias}."_ws.col.unres_{direction}_port", '
                    f'{alias}."tcp.{direction}port", {alias}."udp.{direction}port")')

        # Both sides of a proposed pair must be in the display filter. Use
        # the frame number index to join each reply to its decoder reference.
        pair_sql = f'''SELECT q."frame.number", r."frame.number" FROM scoped r
                JOIN scoped q ON q."frame.number" = CAST(r."dns.response_to" AS INTEGER)
                WHERE r."dns.flags.response"='1' AND q."dns.flags.response"='0'
                  AND q."dns.id" IS r."dns.id" AND q."dns.qry.name" IS r."dns.qry.name"
                  AND q."dns.qry.type" IS r."dns.qry.type"
                  AND {host("q","src")} IS {host("r","dst")} AND {host("q","dst")} IS {host("r","src")}
                  AND {port("q","src")} IS {port("r","dst")} AND {port("q","dst")} IS {port("r","src")}'''
        order = ' ORDER BY r."frame.number" LIMIT 1'
        with rows.connection() as db:
            pair = None
            if syn and syn.get("frame.time_epoch"):
                link = f''' AND {host("q","src")}=?
                           AND instr(',' || coalesce(r."dns.a",'') || ',' || coalesce(r."dns.aaaa",'') || ',',?)>0
                           AND r."frame.number"<? AND r."frame.time_epoch"!='' AND CAST(r."frame.time_epoch" AS REAL)<?'''
                pair = db.execute(pair_sql + link + order, (address(syn,"src"), ","+address(syn,"dst")+",",
                                  int(syn["frame.number"]), float(syn["frame.time_epoch"]))).fetchone()
            if pair is None:
                pair = db.execute(pair_sql + order).fetchone()
        if pair:
            for number in pair:
                selected[str(number)] = rows.get_frame(number)
    return [selected[n] for n in sorted(selected, key=int)]


def investigate(rows):
    if hasattr(rows, "connection"):
        if getattr(rows, "_evidence", None) is None:
            rows._evidence = _describe(_indexed_candidates(rows))
        return rows._evidence
    return _describe(rows)


def _describe(rows):
    findings, events = [], {}
    index = {r["frame.number"]: r for r in rows}

    def event(r, text):
        number = r["frame.number"]
        if number not in events:
            events[number] = dict(frame=number, time=utc(r.get("frame.time_epoch")), src=endpoint(r, "src"),
                                  dst=endpoint(r, "dst"), src_host=address(r, "src"),
                                  dst_host=address(r, "dst"), observation=text)

    def add(title, observation, meaning, packets):
        findings.append(dict(title=title, observation=observation, meaning=meaning,
                             frames=[r["frame.number"] for r in packets]))

    request = next((r for r in rows if "http.request.method" in r), None)
    initial = next((r for r in rows if r.get("tcp.flags.syn") == "1" and r.get("tcp.flags.ack") == "0"), None)
    focus = request or initial or next((r for r in rows if "tcp.stream" in r), {})
    stream = focus.get("tcp.stream")
    conversation = [r for r in rows if stream is not None and r.get("tcp.stream") == stream]
    syn = next((r for r in conversation if r.get("tcp.flags.syn") == "1" and r.get("tcp.flags.ack") == "0"), None)
    query = next((r for r in rows if r.get("dns.flags.response") == "0"), None)
    reply = next((r for r in rows if r.get("dns.flags.response") == "1"), None)
    pair = None
    link = None
    for candidate in rows:
        if candidate.get("dns.flags.response") != "1":
            continue
        q = index.get(candidate.get("dns.response_to"))
        if not q or q.get("dns.flags.response") != "0":
            continue
        if not (q.get("dns.id") == candidate.get("dns.id") and
                q.get("dns.qry.name") == candidate.get("dns.qry.name") and
                q.get("dns.qry.type") == candidate.get("dns.qry.type") and
                endpoint(q, "src") == endpoint(candidate, "dst") and
                endpoint(q, "dst") == endpoint(candidate, "src")):
            continue
        if pair is None:
            pair = (q, candidate)
        answers = (candidate.get("dns.a", "") + "," + candidate.get("dns.aaaa", "")).split(",")
        if (syn and address(q, "src") == address(syn, "src") and address(syn, "dst") in answers and
                candidate.get("frame.time_epoch") and syn.get("frame.time_epoch") and
                float(candidate["frame.time_epoch"]) < float(syn["frame.time_epoch"]) and
                int(candidate["frame.number"]) < int(syn["frame.number"])):
            pair, link = (q, candidate), syn
            break
    if pair:
        query, reply = pair
    elif query:
        reply = None
    if query or reply:
        message = query or reply
        name = message.get("dns.qry.name", "(question unavailable)")
        qtype = message.get("dns.qry.type", "?")
        qtype = {"1": "A", "28": "AAAA", "5": "CNAME"}.get(qtype, qtype)
        description = []
        if query:
            description.append(f"{address(query, 'src')} asked {address(query, 'dst')} for {name} ({qtype}).")
            event(query, f"DNS query for {name} ({qtype})")
        if reply:
            answers = [reply[k] for k in ("dns.cname", "dns.a", "dns.aaaa") if k in reply]
            result = ", ".join(answers) or "no decoded A, AAAA or CNAME answer"
            description.append(f"The reply carried {result} (response code {reply.get('dns.flags.rcode', '?')}).")
            event(reply, f"DNS reply for {name} · {result}")
        meaning = ("The decoder linked the reply to this query. Transaction ID, question and reversed endpoints agree."
                   if pair else "Only one side of this exchange is established in the current view.")
        cited = [r for r in (query, reply) if r]
        if link:
            meaning += f" The same client subsequently opened TCP stream {stream} to an address in the answer. Other names may share that address."
            cited.append(link)
        add("DNS resolution", " ".join(description), meaning, cited)
    if conversation:
        first = syn or conversation[0]
        observed = [first]
        if syn:
            event(syn, f"Initial SYN in TCP stream {stream}")
            expected = next_seq(syn)
            sa = next((r for r in conversation if r["frame.number"] != syn["frame.number"]
                       and int(r["frame.number"]) > int(syn["frame.number"])
                       and endpoint(r, "src") == endpoint(syn, "dst") and endpoint(r, "dst") == endpoint(syn, "src")
                       and r.get("tcp.flags.syn") == r.get("tcp.flags.ack") == "1"
                       and expected is not None and r.get("tcp.ack_raw") == expected), None)
            if sa:
                observed.append(sa)
                event(sa, "Server SYN/ACK acknowledged the client sequence")
                target = next_seq(sa)
                ack = next((r for r in conversation if int(r["frame.number"]) > int(sa["frame.number"])
                            and endpoint(r, "src") == endpoint(syn, "src") and endpoint(r, "dst") == endpoint(syn, "dst")
                            and r.get("tcp.flags.syn") == r.get("tcp.flags.reset") == "0" and r.get("tcp.flags.ack") == "1"
                            and target is not None and r.get("tcp.ack_raw") == target and r.get("tcp.seq_raw") == expected), None)
                if ack:
                    observed.append(ack)
                    event(ack, "Client ACK completed the observed three-way handshake")
        else:
            event(first, f"Packet in TCP stream {stream}")
        wording = "initiated a connection to" if syn else "sent a TCP segment to"
        add("TCP connection", f"{endpoint(first, 'src')} {wording} {endpoint(first, 'dst')} in stream {stream}.",
            "The SYN, SYN/ACK and matching ACK establish the three-way handshake." if len(observed) == 3
            else "The current view contains only partial evidence of connection setup.", observed)
    if request:
        text = f"{request['http.request.method']} {request.get('http.request.uri', '(path unavailable)')} on {request.get('http.host', '(host unavailable)')}"
        event(request, text)
        response = index.get(request.get("http.response_in"))
        if not response:
            response = next((r for r in conversation if r.get("http.request_in") == request["frame.number"] and "http.response.code" in r), None)
        cited = [request]
        if response and "http.response.code" in response:
            text += f" received HTTP status {response['http.response.code']}"
            event(response, f"HTTP response {response['http.response.code']}")
            cited.append(response)
        add("HTTP activity", text + ".", "Decoded HTTP fields identify the requested resource."
            + (" The decoder paired the response with this request." if len(cited) == 2 else " A matching response is unavailable in this view."), cited)
    elif response := next((r for r in rows if "http.response.code" in r), None):
        event(response, "HTTP response " + response["http.response.code"])
        add("HTTP activity", f"HTTP status {response['http.response.code']} is visible.", "The matching request is outside the selected evidence.", [response])
    hello = next((r for r in rows if "1" in r.get("tls.handshake.type", "").split(",")), None)
    if hello:
        hostname = hello.get("tls.handshake.extensions_server_name")
        event(hello, "TLS Client Hello" + (f" for {hostname}" if hostname else ""))
        add("TLS visibility", f"{endpoint(hello, 'src')} sent a Client Hello to {endpoint(hello, 'dst')}."
            + (f" Its server name was {hostname}." if hostname else " No server name was decoded in this hello."),
            "The Client Hello identifies a negotiation attempt. It does not establish an HTTP path, response status or completed TLS session.", [hello])
    if rows and not findings:
        first = rows[0]
        event(first, "First matching " + first.get("_ws.col.Protocol", "undecoded") + " frame")
        add("Observed traffic", f"{endpoint(first, 'src')} sent a {first['frame.len']}-byte frame to {endpoint(first, 'dst')}.",
            "Inspect the packet details and adjacent frames to determine the exchange context.", [first])
    return findings, sorted(events.values(), key=lambda e: (e["time"], int(e["frame"])))
