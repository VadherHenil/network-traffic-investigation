"""Analyst-selected evidence and searchable TCP conversations."""

from capture import endpoint
from large_metrics import sql_address

PAGE_SIZE = 50
MAX_PINS = 250
MAX_PIN_FRAMES = 32


def annotations(capture):
    return getattr(capture, "annotations", {"pins": [], "conclusion": ""})


def _text(value, label, limit):
    if not isinstance(value, str) or len(value) > limit or any(
        ord(ch) < 32 and ch not in "\t\n\r" or 0xD800 <= ord(ch) <= 0xDFFF for ch in value
    ):
        raise ValueError(f"Enter valid {label} text of up to {limit} characters.")
    return value.strip()


def _frames(capture, values):
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_PIN_FRAMES:
        raise ValueError(f"Select between 1 and {MAX_PIN_FRAMES} frame references per pin.")
    # The decoder verifies that original frame numbers are contiguous and one-based.
    numbers = set()
    for value in values:
        if not isinstance(value, (int, str)) or not str(value).isascii() or not str(value).isdecimal() or len(str(value)) > 12:
            raise ValueError("Use original frame numbers for pinned evidence.")
        number = int(value)
        if not 1 <= number <= len(capture.rows):
            raise ValueError("A pinned frame falls outside the capture.")
        numbers.add(number)
    return [str(number) for number in sorted(numbers)]


def validate_annotations(capture, state):
    if not isinstance(state, dict) or not isinstance(state.get("pins"), list) or len(state["pins"]) > MAX_PINS:
        raise ValueError("Invalid collection of pinned evidence.")
    pins, seen = [], set()
    for pin in state["pins"]:
        if not isinstance(pin, dict):
            raise ValueError("Invalid pinned observation.")
        frames = _frames(capture, pin.get("frames"))
        if tuple(frames) in seen:
            raise ValueError("Duplicate pinned frame set.")
        seen.add(tuple(frames))
        pins.append({"frames": frames, "note": _text(pin.get("note", ""), "pin note", 2000)})
    return {"pins": pins, "conclusion": _text(state.get("conclusion", ""), "conclusion", 3000)}


def update_annotations(capture, data):
    """Apply one idempotent edit while the caller holds the capture lock."""
    state = annotations(capture)
    action = data.get("action")
    if action == "conclusion":
        state = {**state, "conclusion": _text(data.get("conclusion"), "conclusion", 3000)}
    elif action in ("pin", "remove"):
        frames = _frames(capture, data.get("frames"))
        pins = [pin for pin in state["pins"] if pin["frames"] != frames]
        if action == "pin":
            if len(pins) >= MAX_PINS:
                raise ValueError(f"Remove a pin before adding more than {MAX_PINS} pinned observations.")
            pins.append({"frames": frames, "note": _text(data.get("note", ""), "pin note", 2000)})
        state = {**state, "pins": pins}
    else:
        raise ValueError("Choose a pin, remove or conclusion action.")
    capture.annotations = state
    return state


def search_conversations(rows, data):
    """Aggregate both directions within the applied filter, then search the grouped streams."""
    search = _text(data.get("search", ""), "conversation search", 200).lower()
    page = data.get("page", 0)
    if type(page) is not int or not 0 <= page <= 100_000_000:
        raise ValueError("Choose a valid conversation page.")
    # Group first, so searching either endpoint retains counts for both directions.
    # Restrict the representative frames to the fields needed to render the result page.
    def sql_port(direction):
        return f'coalesce("_ws.col.unres_{direction}_port", "tcp.{direction}port")'

    sql = f'''WITH groups AS (
                SELECT "tcp.stream" stream, count(*) packets, sum("frame.len") bytes,
                       min("frame.number") first_frame, max("frame.number") last_frame
                FROM scoped WHERE "tcp.stream" IS NOT NULL GROUP BY "tcp.stream")
              SELECT g.*, {sql_address('src')} a, {sql_port('src')} a_port,
                     {sql_address('dst')} b, {sql_port('dst')} b_port
              FROM groups g JOIN main.frames f ON f."frame.number"=g.first_frame
              WHERE :q='' OR g.stream=:q OR instr(lower(a),:q)>0 OR instr(lower(b),:q)>0
                    OR a_port=:q OR b_port=:q
              ORDER BY g.packets DESC,g.first_frame LIMIT :n OFFSET :offset'''
    with rows.connection() as db:
        items = db.execute(sql, {"q": search, "n": PAGE_SIZE + 1, "offset": page * PAGE_SIZE}).fetchall()
    streams = []
    for stream, packets, size, first, last, a, a_port, b, b_port in items[:PAGE_SIZE]:
        row = {"_ws.col.Source": a, "_ws.col.Destination": b,
               "_ws.col.unres_src_port": a_port, "_ws.col.unres_dst_port": b_port}
        streams.append(dict(stream=str(stream), a=endpoint(row, "src"), b=endpoint(row, "dst"),
                            packets=packets, bytes=size, first=str(first), last=str(last)))
    return {"streams": streams, "page": page, "has_more": len(items) > PAGE_SIZE}
