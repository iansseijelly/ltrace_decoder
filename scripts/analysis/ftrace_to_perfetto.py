#!/usr/bin/env python3
"""Prepare a raw ftrace text dump (cat /sys/kernel/tracing/trace) for the
Perfetto UI (ui.perfetto.dev ingests this format natively).

Transforms:
  --window LO HI      keep only events with LO <= timestamp(s) <= HI
                      (header always kept)
  --collapse-children merge the benchmark's short-lived children (comm
                      `dummy`, plus pre-exec forks that still carry the
                      parent's comm under a different pid) into a single
                      pseudo-thread child-63000, collapsing hundreds of
                      one-shot Perfetto tracks into one. Safe on single-CPU
                      traces (at most one child runs at any instant).
  --parent-comm/--parent-pid identify the long-lived launcher to keep
                      (default comm trace-submit, pid auto-detected as its
                      most frequent pid).

Usage:
  ftrace_to_perfetto.py --in trace.ftrace.txt --out perfetto.txt \
      [--window 3.264 3.289] [--collapse-children]
"""
import argparse
import re
from collections import Counter

CHILD_PID = "63000"
CHILD_COMM = "child"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--window", nargs=2, type=float, default=None)
    ap.add_argument("--collapse-children", action="store_true")
    ap.add_argument("--parent-comm", default="trace-submit")
    ap.add_argument("--parent-pid", default=None)
    args = ap.parse_args()

    lines = open(args.inp).read().split("\n")
    header = [l for l in lines if l.startswith("#")]
    ts_pat = re.compile(r"\s(\d+\.\d+): ")

    body = []
    for l in lines:
        if l.startswith("#") or not l.strip():
            continue
        if args.window:
            m = ts_pat.search(l)
            if not m or not (args.window[0] <= float(m.group(1)) <= args.window[1]):
                continue
        body.append(l)

    if args.collapse_children:
        parent_pid = args.parent_pid
        if parent_pid is None:
            pids = Counter()
            task_pat = re.compile(r"^\s*" + re.escape(args.parent_comm) + r"-(\d+)\s")
            for l in body:
                m = task_pat.match(l)
                if m:
                    pids[m.group(1)] += 1
            parent_pid = pids.most_common(1)[0][0] if pids else "-1"
            print(f"auto-detected parent {args.parent_comm}-{parent_pid}")

        def is_child(comm, pid):
            if comm == "dummy":
                return True
            return comm == args.parent_comm and pid != parent_pid

        def fix(l):
            # emitting-task prefix column: "  comm-pid   [cpu] ..."
            m = re.match(r"^(\s*)(\S+)-(\d+)(\s+\[)", l)
            if m and is_child(m.group(2), m.group(3)):
                l = f"{m.group(1)}{CHILD_COMM}-{CHILD_PID}{m.group(4)}" + l[m.end():]
            # sched_switch prev_/next_ pairs and waking/wakeup comm=/pid= pairs
            for cpat in (r"(prev_comm=)(\S+)( prev_pid=)(\d+)",
                         r"(next_comm=)(\S+)( next_pid=)(\d+)",
                         r"(comm=)(\S+)( pid=)(\d+)"):
                def sub(mm):
                    if is_child(mm.group(2), mm.group(4)):
                        return f"{mm.group(1)}{CHILD_COMM}{mm.group(3)}{CHILD_PID}"
                    return mm.group(0)
                l = re.sub(cpat, sub, l)
            return l

        body = [fix(l) for l in body]

    with open(args.out, "w") as f:
        f.write("\n".join(header + body) + "\n")
    print(f"wrote {args.out}: {len(body)} events (+{len(header)} header lines)")


if __name__ == "__main__":
    main()
