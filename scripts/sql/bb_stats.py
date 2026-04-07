import sqlite3
import csv
import argparse
import sys
from collections import defaultdict
from tqdm import tqdm


def to_u64(val: int) -> int:
    """Convert signed i64 (from SQLite) back to unsigned u64."""
    return val & 0xFFFFFFFFFFFFFFFF


def bb_stats(db_path: str, output: str, prv: int | None, ctx: int | None, limit: int | None) -> None:
    conn = sqlite3.connect(db_path)

    # Always scan all events to get correct deltas; filter prv/ctx in Python
    sql_where = "event_type NOT IN ('SYNC_START', 'SYNC_END')"

    count_query = f"SELECT COUNT(*) FROM events WHERE {sql_where}"
    total_rows = conn.execute(count_query).fetchone()[0]

    query = f"SELECT timestamp, from_addr, to_addr, prv, ctx FROM events WHERE {sql_where} ORDER BY id"
    cursor = conn.execute(query)

    # Streaming aggregation: track (count, sum, min) per BB
    bb_agg = defaultdict(lambda: [0, 0, float('inf')])  # [count, sum, min]
    prev_ts = None
    prev_to = None
    prev_matches = False

    for timestamp, from_addr, to_addr, row_prv, row_ctx in tqdm(cursor, total=total_rows, desc="Scanning", unit="events"):
        from_addr = to_u64(from_addr)
        to_addr = to_u64(to_addr)
        curr_matches = (prv is None or row_prv == prv) and (ctx is None or row_ctx == ctx)
        if prev_ts is not None and prev_matches and curr_matches:
            delta = timestamp - prev_ts
            bb = (prev_to, from_addr)
            agg = bb_agg[bb]
            agg[0] += 1
            agg[1] += delta
            if delta < agg[2]:
                agg[2] = delta
        prev_ts = timestamp
        prev_to = to_addr
        prev_matches = curr_matches

    conn.close()
    print(f"Aggregated {len(bb_agg)} unique BBs", file=sys.stderr)

    # Sort by netvar descending
    results = []
    for (bb_start, bb_end), (count, total, min_delta) in bb_agg.items():
        mean = total / count
        netvar = total - min_delta * count
        results.append((count, mean, netvar, bb_start, bb_end))
    results.sort(key=lambda r: r[2], reverse=True)

    if limit:
        results = results[:limit]

    with open(output, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['count', 'mean', 'netvar', 'bb'])
        for count, mean, netvar, bb_start, bb_end in results:
            writer.writerow([count, f'{mean:.1f}', netvar, f'{bb_start:#x}-{bb_end:#x}'])

    print(f"Written {len(results)} rows to {output}", file=sys.stderr)

    # Summary stats
    total_cycles = sum(r[1] * r[0] for r in results)  # mean * count = total per BB
    total_netvar = sum(r[2] for r in results)
    total_events = sum(r[0] for r in results)
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"BB Stats Summary", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"  Events scanned:   {total_rows}", file=sys.stderr)
    print(f"  Unique BBs:       {len(bb_agg)}", file=sys.stderr)
    print(f"  Total cycles:     {total_cycles:.0f}", file=sys.stderr)
    print(f"  Total netvar:     {total_netvar:.0f}", file=sys.stderr)
    if results:
        top = results[0]
        print(f"  Top BB by netvar: {top[3]:#x}-{top[4]:#x} (netvar={top[2]}, count={top[0]}, mean={top[1]:.1f})", file=sys.stderr)
        top10_netvar = sum(r[2] for r in results[:10])
        print(f"  Top 10 netvar:    {top10_netvar:.0f} ({top10_netvar/total_netvar*100:.1f}% of total)", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Compute BB stats from SQLite trace DB')
    parser.add_argument('--db', type=str, default='trace.db', help='Path to SQLite trace DB')
    parser.add_argument('--output', type=str, default='trace.bb_stats.csv', help='Output CSV path')
    parser.add_argument('--prv', type=int, default=None, help='Filter by privilege level (0=user, 1=supervisor, 3=machine)')
    parser.add_argument('--ctx', type=int, default=None, help='Filter by ASID context')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of output rows')
    args = parser.parse_args()

    bb_stats(args.db, args.output, args.prv, args.ctx, args.limit)
