#!/usr/bin/env python3
"""Convert perfect_sampler receiver output into a speedscope 'sampled'
profile, visualizing what a sampling profiler would have recorded.

Usage:
  samples_to_speedscope.py --samples X.samples.csv --stacks X.stacks.csv \
      --out emulated.speedscope.json [--name "..."] [--start T --end T]
"""
import argparse
import csv
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--stacks", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", default="emulated sampling profiler")
    ap.add_argument("--start", type=int, default=None,
                    help="restrict to samples with timestamp >= start (cycles)")
    ap.add_argument("--end", type=int, default=None,
                    help="restrict to samples with timestamp <= end (cycles)")
    args = ap.parse_args()

    folded = {}
    for r in csv.DictReader(open(args.stacks)):
        folded[int(r["stack_id"])] = r["folded"]

    rows = []
    for r in csv.DictReader(open(args.samples)):
        t = int(r["timestamp"])
        if args.start is not None and t < args.start:
            continue
        if args.end is not None and t > args.end:
            continue
        rows.append((t, int(r["stack_id"])))
    if not rows:
        raise SystemExit("no samples in range")

    interval = round((rows[-1][0] - rows[0][0]) / max(len(rows) - 1, 1))

    frame_ids = {}
    frames = []
    stack_expanded = {}
    for sid, f in folded.items():
        idxs = []
        for nm in f.split(";"):
            if nm not in frame_ids:
                frame_ids[nm] = len(frames)
                frames.append({"name": nm})
            idxs.append(frame_ids[nm])
        stack_expanded[sid] = idxs

    samples = [stack_expanded[sid] for _, sid in rows]
    weights = [interval] * len(rows)

    out = {
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "shared": {"frames": frames},
        "profiles": [
            {
                "type": "sampled",
                "name": f"{args.name} (interval {interval} cycles)",
                "unit": "none",
                "startValue": rows[0][0],
                "endValue": rows[-1][0] + interval,
                "samples": samples,
                "weights": weights,
            }
        ],
        "name": args.name,
        "exporter": "samples_to_speedscope.py",
    }
    with open(args.out, "w") as f:
        json.dump(out, f)
    print(f"wrote {args.out}: {len(samples)} samples, {len(frames)} frames, "
          f"interval={interval}, span=[{rows[0][0]}, {rows[-1][0]}]")


if __name__ == "__main__":
    main()
