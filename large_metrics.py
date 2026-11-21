"""Exact packet statistics with disk-backed grouping for indexed captures."""

import heapq
from collections import Counter

from capture import address, endpoint, protocol_layers, utc


HIERARCHY_LIMIT = 4096
BIN_COUNT = 48


def _group_layers(rows):
    cached = getattr(rows, "_layer_stats", None)
    if cached is not None:
        return cached
    layer_counts = Counter()
    with rows.connection() as db:
        # Expand each distinct stack once, even when millions of frames have
        # the same stack. Dissector names form a small vocabulary. Store the
        # much higher-cardinality hierarchy prefixes on disk.
        db.execute("CREATE TEMP TABLE paths(path TEXT PRIMARY KEY, n INTEGER NOT NULL) WITHOUT ROWID")
        sql = '''SELECT "frame.protocols", COUNT(*) FROM scoped
                 WHERE "frame.protocols" IS NOT NULL GROUP BY "frame.protocols"'''
        for stack, n in db.execute(sql):
            layers = [layer for layer in stack.split(":") if layer]
            for layer in set(layers):
                layer_counts[layer] += n
            db.executemany(
                "INSERT INTO paths(path, n) VALUES (?, ?) ON CONFLICT(path) DO UPDATE SET n=n+excluded.n",
                ((":".join(layers[:i]), n) for i in range(1, len(layers) + 1)))
        total = db.execute("SELECT COUNT(*) FROM paths").fetchone()[0]
        hierarchy = sorted((tuple(path.split(":")), n) for path, n in db.execute(
            "SELECT path,n FROM paths ORDER BY n DESC,path LIMIT ?", (HIERARCHY_LIMIT,)))
    result = (sorted(layer_counts.items(), key=lambda p: (-p[1], p[0])), hierarchy, total)
    rows._layer_stats = result
    return result


def layer_inventory(rows):
    if hasattr(rows, "connection"):
        return _group_layers(rows)[0]
    counts = Counter(layer for row in rows for layer in set(protocol_layers(row)))
    return sorted(counts.items(), key=lambda p: (-p[1], p[0]))


def sql_address(direction):
    column = "Source" if direction == "src" else "Destination"
    return (f'coalesce("_ws.col.{column}", "ip.{direction}", '
            f'"ipv6.{direction}", "eth.{direction}")')


def _indexed_metrics(rows):
    layer_counts, hierarchy, hierarchy_count = _group_layers(rows)
    with rows.connection() as db:
        # Epochs are stored as text to preserve their original precision in
        # evidence. Cast for chronological comparisons and histogram buckets.
        epoch = '''CAST(NULLIF("frame.time_epoch",'') AS REAL)'''
        low, high, volume = db.execute(
            f'SELECT MIN({epoch}), MAX({epoch}), COALESCE(SUM("frame.len"),0) FROM scoped').fetchone()
        bins = [0] * BIN_COUNT
        if low is not None:
            sql = f'''SELECT MIN(?, COALESCE(CAST((({epoch} - ?) / ?) * ? AS INTEGER), 0)), COUNT(*)
                      FROM scoped WHERE {epoch} IS NOT NULL GROUP BY 1'''
            for bucket, n in db.execute(sql, (BIN_COUNT - 1, low, high - low, BIN_COUNT)):
                bins[bucket] = n
        window = [utc(low), utc(high)] if low is not None else []
        rows._window = window
        protocols = [tuple(item) for item in db.execute(
            '''SELECT COALESCE("_ws.col.Protocol",'Unknown'), COUNT(*) FROM scoped GROUP BY 1 ORDER BY 2 DESC,1''')]
        hosts = db.execute(f'''SELECT COUNT(*) FROM (
             SELECT {sql_address('src')} AS host FROM scoped UNION SELECT {sql_address('dst')} FROM scoped
             ) WHERE host IS NOT NULL AND host != '—' ''').fetchone()[0]
        stream_rows = db.execute('''SELECT "tcp.stream", COUNT(*) n, SUM("frame.len"), MIN("frame.number")
                                    FROM scoped WHERE "tcp.stream" IS NOT NULL GROUP BY "tcp.stream"''')
        # Count all groups and keep the earliest maximum-size groups on ties.
        # SQLite does the potentially large GROUP BY with disk-backed spill.
        top = []
        stream_count = 0
        for stream, n, volume_in_stream, first in stream_rows:
            stream_count += 1
            item = (n, -int(first), stream, volume_in_stream)
            if len(top) < 100:
                heapq.heappush(top, item)
            elif item > top[0]:
                heapq.heapreplace(top, item)
    streams = []
    for n, first_negated, stream, byte_count in sorted(top, reverse=True):
        first = rows.get_frame(-first_negated)
        streams.append(dict(stream=str(stream), a=endpoint(first, "src"), b=endpoint(first, "dst"),
                            packets=n, bytes=byte_count))
    return dict(protocols=protocols, hierarchy=hierarchy, hierarchy_count=hierarchy_count,
                layer_counts=layer_counts, hosts=hosts, duration=high-low if low is not None else 0,
                bytes=volume, bins=bins, streams=streams, stream_count=stream_count, window=window)


def metrics(rows):
    if hasattr(rows, "connection"):
        if getattr(rows, "_metrics", None) is None:
            rows._metrics = _indexed_metrics(rows)
        return rows._metrics
    # Lightweight in-memory callers (e.g. unit tests) retain the original
    # sequence interface. Imported evidence always takes the indexed path.
    protocols, hierarchy, streams, hosts = Counter(), Counter(), {}, set()
    low, high, volume = None, None, 0
    for row in rows:
        protocols[row.get("_ws.col.Protocol", "Unknown")] += 1
        layers = protocol_layers(row)
        for i in range(1, len(layers) + 1):
            hierarchy[tuple(layers[:i])] += 1
        for direction in ("src", "dst"):
            hosts.add(address(row, direction))
        if row.get("frame.time_epoch"):
            t = float(row["frame.time_epoch"])
            low = t if low is None else min(low, t)
            high = t if high is None else max(high, t)
        size = int(row["frame.len"])
        volume += size
        if "tcp.stream" in row:
            key = row["tcp.stream"]
            if key not in streams:
                streams[key] = dict(stream=key, a=endpoint(row, "src"), b=endpoint(row, "dst"), packets=0, bytes=0)
            stream = streams[key]
            stream["packets"] += 1
            stream["bytes"] += size
    bins = [0] * BIN_COUNT
    for row in rows:
        if row.get("frame.time_epoch"):
            t = float(row["frame.time_epoch"])
            bucket = min(BIN_COUNT - 1, int(BIN_COUNT * (t - low) / (high - low))) if high > low else 0
            bins[bucket] += 1
    return dict(protocols=protocols.most_common(), hierarchy=sorted(hierarchy.most_common(HIERARCHY_LIMIT)),
                hierarchy_count=len(hierarchy), layer_counts=layer_inventory(rows), hosts=len(hosts - {"—"}),
                duration=high - low if low is not None else 0, bytes=volume, bins=bins,
                streams=sorted(streams.values(), key=lambda s: -s["packets"])[:100], stream_count=len(streams),
                window=[utc(low), utc(high)] if low is not None else [])
