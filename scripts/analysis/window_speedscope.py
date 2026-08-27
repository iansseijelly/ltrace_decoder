#!/usr/bin/env python3
"""Cut an evented speedscope profile (tacit decoder output) down to a time
window, preserving exact frame structure: frames open at the window start are
re-opened at the start boundary, and frames still open at the window end are
closed at the end boundary.

Usage:
  window_speedscope.py --in trace.speedscope.json --out cut.speedscope.json \
      --start T --end T [--name "..."]
"""
import argparse
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end", type=int, required=True)
    ap.add_argument("--name", default=None)
    args = ap.parse_args()

    d = json.load(open(args.inp))
    prof = d["profiles"][0]
    assert prof["type"] == "evented", "expects an evented (tacit decoder) profile"
    ev = prof["events"]

    out_events = []
    stack = []
    entered = False
    for e in ev:
        t = e["at"]
        if t < args.start:
            if e["type"] == "O":
                stack.append(e["frame"])
            elif stack:
                stack.pop()
            continue
        if not entered:
            entered = True
            for fr in stack:  # re-open frames live at window start
                out_events.append({"type": "O", "frame": fr, "at": args.start})
        if t > args.end:
            break
        out_events.append(e)
        if e["type"] == "O":
            stack.append(e["frame"])
        elif stack:
            stack.pop()
    if not entered:  # window starts after last event
        for fr in stack:
            out_events.append({"type": "O", "frame": fr, "at": args.start})
    for fr in reversed(stack):  # close frames live at window end
        out_events.append({"type": "C", "frame": fr, "at": args.end})

    used = sorted({e["frame"] for e in out_events})
    remap = {old: new for new, old in enumerate(used)}
    frames = [d["shared"]["frames"][old] for old in used]
    for e in out_events:
        e["frame"] = remap[e["frame"]]

    name = args.name or f"{prof.get('name', 'trace')} [{args.start}..{args.end}]"
    out = {
        "$schema": "https://www.speedscope.app/file-format-schema.json",
        "shared": {"frames": frames},
        "profiles": [
            {
                "type": "evented",
                "name": name,
                "unit": prof.get("unit", "none"),
                "startValue": args.start,
                "endValue": args.end,
                "events": out_events,
            }
        ],
        "name": name,
        "exporter": "window_speedscope.py",
    }
    with open(args.out, "w") as f:
        json.dump(out, f)
    print(f"wrote {args.out}: {len(out_events)} events, {len(frames)} frames, "
          f"window [{args.start}, {args.end}]")


if __name__ == "__main__":
    main()
