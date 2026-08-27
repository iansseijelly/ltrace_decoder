#!/usr/bin/env python3
"""Quantify what an idealized sampling profiler (perfect_sampler receiver
output) can see of the RCU/EEVDF ping-pong pathology, against the decoded
ground truth (speedscope timeline).

Usage:
  sampler_visibility.py --samples trace.pl-t256.sampler100k.samples.csv \
      --stacks trace.pl-t256.sampler100k.stacks.csv \
      --speedscope trace.pl-t256.speedscope.json \
      --trace-bytes 46469120
"""
import argparse
import csv
import json
import math
from collections import defaultdict

GP_FUNCS = {"k:rcu_gp_cleanup", "k:rcu_gp_init"}
SCHED = "k:__schedule"
SMOKING_GUN = "k:check_preempt_wakeup_fair"
OVERHEAD = GP_FUNCS | {SCHED}
CLUSTER_GAP = 2_000_000


def load_ground_truth(path):
    d = json.load(open(path))
    name = {i: f["name"] for i, f in enumerate(d["shared"]["frames"])}
    ev = d["profiles"][0]["events"]
    rdb = [e["at"] for e in ev if e["type"] == "O" and name[e["frame"]] == "k:rcu_do_batch"]
    gp = [e["at"] for e in ev if e["type"] == "O" and name[e["frame"]] in GP_FUNCS]
    gun = [e["at"] for e in ev if e["type"] == "O" and name[e["frame"]] == SMOKING_GUN]
    clusters, cur = [], [rdb[0]]
    for t in rdb[1:]:
        if t - cur[-1] > CLUSTER_GAP:
            clusters.append(cur)
            cur = [t]
        else:
            cur.append(t)
    clusters.append(cur)
    # worst drain = most mid-drain GP episodes
    worst = max(clusters, key=lambda c: sum(1 for g in gp if c[0] < g < c[-1]))
    episodes = sum(1 for g in gp if worst[0] < g < worst[-1])
    return {
        "span": (worst[0], worst[-1]),
        "batches": len(worst),
        "gp_episodes": episodes,
        "gun_invocations": sum(1 for g in gun if worst[0] < g < worst[-1]),
        "n_drains": len(clusters),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--stacks", required=True)
    ap.add_argument("--speedscope", required=True)
    ap.add_argument("--trace-bytes", type=int, default=None,
                    help="raw ATT trace size for the bandwidth comparison")
    ap.add_argument("--cpu-hz", type=float, default=1e9)
    args = ap.parse_args()

    gt = load_ground_truth(args.speedscope)
    lo, hi = gt["span"]

    leaf = {}
    for r in csv.DictReader(open(args.stacks)):
        leaf[int(r["stack_id"])] = r["leaf"]

    samples = []
    for r in csv.DictReader(open(args.samples)):
        samples.append((int(r["timestamp"]), int(r["stack_id"])))
    n = len(samples)
    span_cycles = samples[-1][0] - samples[0][0]
    interval = round(span_cycles / (n - 1))
    freq_hz = args.cpu_hz / interval

    in_win = [(t, s) for t, s in samples if lo <= t <= hi]
    win_gp = [(t, s) for t, s in in_win if leaf[s] in GP_FUNCS]
    win_sched = [(t, s) for t, s in in_win if leaf[s] == SCHED]
    gun_hits = sum(1 for _, s in samples if leaf[s] == SMOKING_GUN)
    gun_hits_win = sum(1 for _, s in in_win if leaf[s] == SMOKING_GUN)

    # episode-count estimate: maximal runs of consecutive in-window samples
    # whose leaf is a GP function
    runs, prev_gp = 0, False
    for t, s in in_win:
        is_gp = leaf[s] in GP_FUNCS
        if is_gp and not prev_gp:
            runs += 1
        prev_gp = is_gp

    # marginal detectability: overhead-function share, all vs excluding window
    tot_ovh = sum(1 for _, s in samples if leaf[s] in OVERHEAD)
    out_samples = [(t, s) for t, s in samples if not (lo <= t <= hi)]
    out_ovh = sum(1 for _, s in out_samples if leaf[s] in OVERHEAD)
    p_all = tot_ovh / n
    p_out = out_ovh / len(out_samples)
    shift = p_all - p_out
    sigma = math.sqrt(max(p_out * (1 - p_out), 1e-12) / n)

    print(f"== ground truth (afflicted drain): span={hi-lo} cycles, "
          f"batches={gt['batches']}, GP episodes={gt['gp_episodes']}, "
          f"check_preempt_wakeup_fair invocations={gt['gun_invocations']}, "
          f"drains in trace={gt['n_drains']}")
    print(f"== sampler: interval={interval} cycles (~{freq_hz/1e3:.0f} kHz), "
          f"n={n} samples over {span_cycles} cycles")
    print(f"   samples inside afflicted drain window     : {len(in_win)}")
    print(f"   ... with leaf in GP maintenance           : {len(win_gp)}"
          f"   (truth: {gt['gp_episodes']} episodes)")
    print(f"   ... with leaf in __schedule               : {len(win_sched)}")
    print(f"   GP-episode count estimate (sample runs)   : {runs}"
          f"   (truth: {gt['gp_episodes']})")
    print(f"   samples in check_preempt_wakeup_fair      : {gun_hits_win} in window, "
          f"{gun_hits} whole-trace   (truth in window: {gt['gun_invocations']} x ~250 cycles)")
    print(f"   overhead-fn share all/excl-window         : {100*p_all:.3f}% / "
          f"{100*p_out:.3f}%  (shift {100*shift:.3f} pp, "
          f"binomial sigma {100*sigma:.3f} pp, {shift/sigma if sigma else 0:.1f} sigma)")
    if args.trace_bytes:
        trace_bps = args.trace_bytes / (span_cycles / args.cpu_hz)
        print(f"   bandwidth: sampler leaf-only {freq_hz*16/1e6:.1f} MB/s, "
              f"full-stack {freq_hz*128/1e6:.1f} MB/s vs ATT {trace_bps/1e6:.1f} MB/s")


if __name__ == "__main__":
    main()
