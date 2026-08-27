#!/usr/bin/env python3
"""Puzzle: why do measured epsilon (vs tacit-decoded deltas) and proxy
epsilon (vs oracle exit_tsc deltas) differ at all?

On every MATCHED pair the residency t is identical; only the estimate
differs: that_tacit = ev[k+1].ts - ev[k].ts (encoder-stamped) versus
that_proxy = exit(i) - exit(i-1) (commit-stamped). This script walks the
same alignment bb_epsilon uses and, per pair, computes
Delta = that_tacit - that_proxy, classifying nonzero pairs by context:
  - trap_entry:  the pair's entry event (ev[k]) is a Trap
  - trap_exit:   the pair's exit event (ev[k+1]) is a Trap
  - post_resync: first pair after a resync (proxy delta spans skipped rows)
  - other:       none of the above
It also accounts the pair-SET difference: rows the proxy epsilon includes
that the measured comparison never sees (foreign-asid filtered rows and
resync-skipped rows).

Usage: proxy_vs_measured.py BUNDLE [--policy boundary|inst] [--asids CSV]
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bb_epsilon as be

RX = re.compile(r"\[timestamp: (\d+)\] (\w+): (0x[0-9a-f]+) -> (0x[0-9a-f]+)")


def parse_events_kinds(path):
    out = []
    with open(path) as f:
        for line in f:
            m = RX.match(line)
            if m:
                out.append((int(m.group(1)), m.group(4), m.group(2)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", type=Path)
    ap.add_argument("--policy", default="boundary",
                    choices=["boundary", "inst"])
    ap.add_argument("--asids", default=None)
    args = ap.parse_args()

    bundle = args.bundle.resolve()
    ev = parse_events_kinds(bundle / "out/tacit_decoded.txt")
    csv = bundle / f"out/bboracle_{args.policy}.csv"
    if not csv.exists():
        csv = bundle / f"oracle/bboracle_{args.policy}.csv"
    user_asids = (set(int(a) for a in args.asids.split(","))
                  if args.asids else None)
    # filtered instances for alignment, but each carries the exit_tsc of its
    # UNFILTERED predecessor so proxy deltas never bridge filtered rows
    inst = []
    prev_exit = None
    with open(csv) as f:
        f.readline()
        for line in f:
            p = line.strip().split(",")
            if len(p) != 10:
                continue
            keep = not (user_asids is not None and int(p[3]) == 0
                        and int(p[4]) not in user_asids)
            if keep:
                inst.append((p[2], sum(int(x) for x in p[6:10]) / 12.0,
                             int(p[1]), prev_exit))
            prev_exit = int(p[1])
    targets = [e[1] for e in ev]

    # same walk as bb_epsilon.main, recording matched pairs + resync marks
    i, k = 1, 0
    pairs = []  # (i, k, post_resync)
    resyncs = skip_i = skip_k = 0
    fresh = False
    while i < len(inst) and k < len(targets):
        if inst[i][0] == targets[k]:
            if k + 1 < len(ev):
                pairs.append((i, k, fresh))
            fresh = False
            i += 1
            k += 1
            continue
        upcoming = {}
        for di in range(min(be.RESYNC_INST_WINDOW, len(inst) - i)):
            upcoming.setdefault(inst[i + di][0], []).append(di)
        best = None
        for dk in range(min(be.RESYNC_EV_WINDOW + 1, len(targets) - k)):
            for di in upcoming.get(targets[k + dk], []):
                if (di, dk) == (0, 0):
                    continue
                if best and di + dk >= best[0] + best[1]:
                    break
                if be.probe_match(inst, targets, i + di, k + dk,
                                  be.RESYNC_PROBE):
                    best = (di, dk)
                    break
        if best is None:
            print(f"resync failed at inst {i} / ev {k}; truncating")
            break
        resyncs += 1
        skip_i += best[0]
        skip_k += best[1]
        i += best[0]
        k += best[1]
        fresh = True

    classes = {}

    def acc(name, dd, dm, dp):
        c = classes.setdefault(name, [0, 0.0, 0.0, 0.0])
        c[0] += 1
        c[1] += abs(dd)
        c[2] += dm
        c[3] += dp

    den = 0.0
    for i, k, fresh in pairs:
        t = inst[i][1]
        den += t
        that_t = ev[k + 1][0] - ev[k][0]
        that_p = inst[i][2] - (inst[i][3] if inst[i][3] is not None else inst[i - 1][2])
        dm, dp = abs(t - that_t), abs(t - that_p)
        dd = that_t - that_p
        if dd == 0 and dm == dp:
            continue
        if fresh:
            acc("post_resync", dd, dm, dp)
        elif ev[k][2] == "Trap":
            acc("trap_entry", dd, dm, dp)
        elif ev[k + 1][2] == "Trap":
            acc("trap_exit", dd, dm, dp)
        else:
            acc("other", dd, dm, dp)

    print(f"pairs compared: {len(pairs)}  (resyncs {resyncs}, skipped "
          f"{skip_i} inst / {skip_k} ev)  sum t = {den:.0f}")
    print(f"\npairs where that_tacit != that_proxy (or |d| differs), "
          "by context:")
    print(f"{'class':>12} {'pairs':>8} {'sum|dTacit-dProxy|':>18} "
          f"{'sum d_meas':>12} {'sum d_proxy':>12}")
    tot = [0, 0.0, 0.0, 0.0]
    for name, c in sorted(classes.items(), key=lambda x: -x[1][1]):
        print(f"{name:>12} {c[0]:>8} {c[1]:>18.0f} {c[2]:>12.1f} "
              f"{c[3]:>12.1f}")
        for j in range(4):
            tot[j] += c[j]
    print(f"{'TOTAL':>12} {tot[0]:>8} {tot[1]:>18.0f} {tot[2]:>12.1f} "
          f"{tot[3]:>12.1f}")
    print(f"\nas %% of sum t: measured-vs-proxy disagreement "
          f"{100 * tot[1] / den:.3f}%  (d_meas {100 * tot[2] / den:.3f}%, "
          f"d_proxy {100 * tot[3] / den:.3f}% over these pairs)")

    # pair-set difference: what proxy sees that measured never compares
    all_rows = be.parse_instances(csv, None)
    proxy_only = len(all_rows) - 1 - len(pairs)
    print(f"\npair-set difference: proxy compares {len(all_rows) - 1} pairs, "
          f"measured {len(pairs)} -> {proxy_only} proxy-only rows "
          "(foreign-asid + resync-skipped + tails)")

    # a few worst examples for eyeballing
    worst = []
    for i, k, fresh in pairs:
        that_t = ev[k + 1][0] - ev[k][0]
        that_p = inst[i][2] - (inst[i][3] if inst[i][3] is not None else inst[i - 1][2])
        if that_t != that_p:
            worst.append((abs(that_t - that_p), i, k, that_t, that_p,
                          inst[i][1], ev[k][2], ev[k + 1][2]))
    worst.sort(reverse=True)
    print("\nworst |that_tacit - that_proxy| examples:")
    for w in worst[:6]:
        print(f"  inst {w[1]} ev {w[2]}: tacit {w[3]} vs proxy {w[4]} "
              f"(t={w[5]:.2f}) entry={w[6]} exit={w[7]} bb={inst[w[1]][0]}")


if __name__ == "__main__":
    main()
