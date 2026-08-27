#!/usr/bin/env python3
"""Paper figure: smoothed process-lifecycle latency densities, uninstrumented
control vs. the same benchmark with diagnosis tracepoints enabled (full set,
and lite = full minus rcu_invoke_callback).

Reads the per-iteration latency lines ("N: <ns>") from the three uartlogs of
the tracepoint A/B FireSim run and renders a 300-dpi PNG.

Usage:
  plot_tracepoint_overhead_density.py [--results DIR] [--out PNG]
"""
import argparse
import re
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEF_RESULTS = ("/scratch/iansseijelly/tacit-chipyard/sims/firesim/deploy/"
               "results-workload/2026-07-09--21-13-40-process-launch-tp-ab-fixa")
INK, INK2, GRID = "#1a1a19", "#5f5e56", "#e6e5df"
SERIES = [
    ("control", "pl-10k-tp-ctrl", "#2a78d6"),
    ("tracepoints, lite", "pl-10k-tp-lite", "#1baf7a"),
    ("tracepoints, full", "pl-10k-tp-full", "#eda100"),
]
XMAX = 1800


def load(path):
    raw = open(path, "rb").read().decode("utf-8", "replace")
    return np.array([int(m) for m in re.findall(r"^\d+: (\d+)\r*$", raw, re.M)]) / 1000.0


def smooth_pct(x, grid, sigma_us=18.0, per_us=25.0):
    step = grid[1] - grid[0]
    hist, _ = np.histogram(x, bins=np.append(grid, grid[-1] + step))
    k_half = int(4 * sigma_us / step)
    kx = np.arange(-k_half, k_half + 1) * step
    kern = np.exp(-0.5 * (kx / sigma_us) ** 2)
    kern /= kern.sum()
    dens = np.convolve(hist, kern, mode="same") / (len(x) * step)
    return dens * per_us * 100.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=DEF_RESULTS)
    ap.add_argument("--out", default="tracepoint_overhead_density.png")
    args = ap.parse_args()

    grid = np.arange(650, XMAX, 5.0)
    fig, ax = plt.subplots(figsize=(7.0, 3.1), dpi=300)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=8)
    ax.grid(axis="y", color=GRID, linewidth=0.7)
    ax.set_axisbelow(True)

    PCTS = [(50, (0, (2, 2))), (90, (0, (4, 1, 1, 1))), (99, "solid")]
    marks = []
    for label, slot, color in SERIES:
        x = load(f"{args.results}/{slot}/uartlog")
        y = smooth_pct(x, grid)
        ax.plot(grid, y, color=color, linewidth=1.8)
        ax.fill_between(grid, y, color=color, alpha=0.08, linewidth=0)
        for p, ls in PCTS:
            v = np.percentile(x, p)
            ax.axvline(v, color=color, linewidth=0.9, linestyle=ls, alpha=0.85)
            marks.append((v, color))
    # two-row label staggering to avoid collisions
    marks.sort()
    prev_x, row = -1e9, 0
    for v, color in marks:
        row = 1 - row if v - prev_x < 55 else 0
        ax.text(v, 29.6 - row * 2.0, f"{v:.0f}", color=color, fontsize=6.5,
                ha="center", va="bottom")
        prev_x = v

    ax.set_xlim(650, XMAX)
    ax.set_ylim(0, 31.5)
    ax.set_xlabel("process lifecycle latency (µs)", color=INK2, fontsize=9)
    ax.set_ylabel("% of iterations (per 25 µs)", color=INK2, fontsize=9)
    ax.set_title("Process lifecycle latency distribution: uninstrumented vs. tracepoints enabled",
                 color=INK, fontsize=10, loc="left", pad=8)

    ax.text(720, 3.5, "control", color="#2a78d6", fontsize=9, fontweight="bold")
    ax.text(880, 7.0, "lite", color="#1baf7a", fontsize=9, fontweight="bold")
    ax.text(930, 11.5, "full", color="#eda100", fontsize=9, fontweight="bold")
    handles = [plt.Line2D([], [], color=c, linewidth=1.8, label=n) for n, _, c in SERIES]
    handles.append(plt.Line2D([], [], color=INK2, linewidth=0.9,
                              linestyle=(0, (2, 2)), label="p50"))
    handles.append(plt.Line2D([], [], color=INK2, linewidth=0.9,
                              linestyle=(0, (4, 1, 1, 1)), label="p90"))
    handles.append(plt.Line2D([], [], color=INK2, linewidth=0.9, label="p99"))
    ax.legend(handles=handles, loc="lower right", 
              frameon=False, fontsize=7.5, labelcolor=INK)
    fig.tight_layout()
    fig.savefig(args.out, bbox_inches="tight")
    print("saved", args.out)


if __name__ == "__main__":
    main()
