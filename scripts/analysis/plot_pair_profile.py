#!/usr/bin/env python3
"""Figures for the pair-conditioned BB profiling vignette.

Fig 1: fan-out — one BB (mcf cost_compare entry), per-predecessor latency.
Fig 2: collapse — golden vs PT-like-emulated timing for a path-split block.
Fig 3: netvar decomposition — context-explained fraction vs netvar, all workloads.

Inputs are the bb_pair_stats CSVs produced by the *_pair_study.json configs.
"""
import bisect
import subprocess

import matplotlib.pyplot as plt
import pandas as pd

# palette: reference categorical slots (light mode), fixed order
S1, S2, S3, S4 = "#2a78d6", "#eb6834", "#1baf7a", "#eda100"
S1_LIGHT = "#9ec5f4"  # slot-1 ramp step 200 for interval fills
S2_LIGHT = "#f5c0aa"
INK, INK2, GRID = "#1a1a19", "#6b6a63", "#e5e4df"

MCF_BIN = "/scratch/iansseijelly/interesting_profile/mcf_s_base.riscv-64.wave1"


def style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK2, labelsize=9)
    ax.xaxis.label.set_color(INK2)
    ax.yaxis.label.set_color(INK2)
    ax.grid(True, axis="x", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def load(path):
    df = pd.read_csv(path, skipinitialspace=True)
    for c in ("prev_bb", "bb"):
        df[c] = df[c].str.strip()
    return df


def symtab(binary):
    out = subprocess.run(["nm", "--defined-only", binary],
                         capture_output=True, text=True).stdout
    syms = sorted((int(l.split()[0], 16), l.split()[2]) for l in out.splitlines()
                  if len(l.split()) == 3 and l.split()[1] in "tT")
    return [a for a, _ in syms], syms


def sym_at(addrs, syms, addr_hex):
    a = int(addr_hex, 16)
    i = bisect.bisect_right(addrs, a) - 1
    if i < 0:
        return addr_hex
    base, name = syms[i]
    off = a - base
    return f"{name}+{off:#x}" if off else name


# ---------------------------------------------------------------- figure 1
def fig_fanout(mcf):
    addrs, syms = symtab(MCF_BIN)
    target = "0x12c8a-0x12c92"
    grp = mcf[mcf["bb"] == target].nlargest(10, "count").sort_values("p50")
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    ys = range(len(grp))
    for y, (_, r) in zip(ys, grp.iterrows()):
        ax.barh(y, r["p90"] - r["min"], left=r["min"], height=0.52,
                color=S1_LIGHT, edgecolor="none", zorder=2)
        ax.plot(r["p50"], y, "o", color=S1, markersize=8, zorder=3)
        ax.plot([r["p99"], r["p99"]], [y - 0.26, y + 0.26],
                color=INK2, linewidth=1.2, zorder=3)
        n = r["count"]
        label = f"{n/1e6:.1f}M" if n >= 1e6 else f"{n/1e3:.0f}k"
        ax.text(r["p99"] + 1.2, y, f"n={label}", va="center",
                fontsize=8.5, color=INK2)
    ax.set_yticks(list(ys))
    ax.set_yticklabels([sym_at(addrs, syms, r["prev_bb"].split("-")[0])
                        for _, r in grp.iterrows()], fontsize=9, color=INK)
    ax.set_xlabel("per-instance latency of the cost_compare entry block (cycles)")
    ax.set_xlim(0, grp["p99"].max() * 1.22)
    style(ax)
    ax.grid(True, axis="x")
    ax.set_title("Same basic block, 35 call sites: entry cost of mcf's comparator\n"
                 "depends on which spec_qsort site invokes it — top 10 sites by count\n"
                 "(bar min–p90, dot p50, tick p99)",
                 fontsize=10.5, color=INK, loc="left")
    fig.tight_layout()
    fig.savefig("pair_profile_fig1_fanout.png", dpi=200,
                facecolor="white", bbox_inches="tight")
    print("wrote pair_profile_fig1_fanout.png")


# ---------------------------------------------------------------- figure 2
def fig_collapse(mcf, mcf_emu):
    target = "0x12e24-0x12e82"
    g = mcf[mcf["bb"] == target].nlargest(2, "count").reset_index(drop=True)
    e = mcf_emu.set_index(["prev_bb", "bb"])
    rows = []
    for _, r in g.iterrows():
        er = e.loc[(r["prev_bb"], r["bb"])]
        rows.append((r, er))

    fig, axes = plt.subplots(2, 1, figsize=(7.2, 3.4), sharex=True)
    names = ["hot loop-back path", "alternate path"]
    colors, fills = [S1, S2], [S1_LIGHT, S2_LIGHT]
    xmax = 0
    for ax, (title, which) in zip(
            axes, [("ATT (per-BB timestamps)", 0), ("emulated PT-like trace", 1)]):
        for y, ((gr, er), name, c, f) in enumerate(zip(rows, names, colors, fills)):
            r = gr if which == 0 else er
            ax.barh(y, r["p90"] - r["min"], left=r["min"], height=0.5,
                    color=f, edgecolor="none", zorder=2)
            ax.plot(r["p50"], y, "o", color=c, markersize=8, zorder=3)
            ax.text(r["p50"], y + 0.38, f"p50 {r['p50']:.0f}",
                    ha="center", fontsize=8.5, color=INK)
            xmax = max(xmax, r["p90"])
        ax.set_yticks([0, 1])
        ax.set_yticklabels(names, fontsize=9, color=INK)
        ax.set_ylim(-0.6, 1.75)
        ax.set_title(title, fontsize=9.5, color=INK2, loc="left")
        style(ax)
    axes[1].set_xlabel("per-instance latency of primal_bea_mpp block 0x12e24 (cycles)")
    axes[1].set_xlim(0, xmax * 1.15)
    fig.suptitle("Sparse timestamps erase the path split (bar min–p90, dot p50)",
                 fontsize=10.5, color=INK, x=0.012, y=0.98, ha="left")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    fig.savefig("pair_profile_fig2_collapse.png", dpi=200,
                facecolor="white", bbox_inches="tight")
    print("wrote pair_profile_fig2_collapse.png")


# ---------------------------------------------------------------- figure 3
def decompose(df):
    """Per BB: netvar, and the share of it attributable to predecessor-typical
    (p50) cost differences — cycles recovered if every predecessor behaved
    like the cheapest predecessor's typical instance."""
    df = df.copy()
    df["sum"] = df["count"] * df["mean"]
    out = []
    for bb, g in df.groupby("bb"):
        n = g["count"].sum()
        min_g = g["min"].min()
        netvar = g["sum"].sum() - n * min_g
        if n < 2000 or netvar < 1000:
            continue
        # weight by count so a 15-instance straggler predecessor can't
        # define the baseline
        heavy = g[g["count"] >= max(0.01 * n, 100)]
        p50_best = heavy["p50"].min() if len(heavy) else g["p50"].min()
        explained = (g["count"] * (g["p50"] - p50_best).clip(lower=0)).sum()
        frac = min(explained / netvar, 1.0) if netvar > 0 else 0.0
        out.append((bb, n, netvar, frac, len(g)))
    return pd.DataFrame(out, columns=["bb", "n", "netvar", "frac", "npred"])


def fig_decomposition(traces):
    fig, ax = plt.subplots(figsize=(7.2, 4.8))
    shapes = {"process spawn": "o", "TLB shootdown": "s",
              "gcc": "^", "mcf": "D"}
    colors = {"process spawn": S1, "TLB shootdown": S2, "gcc": S3, "mcf": S4}
    decs = {}
    for name, df in traces.items():
        d = decompose(df)
        decs[name] = d.set_index("bb")
        ax.scatter(d["frac"], d["netvar"], s=22, alpha=0.55,
                   marker=shapes[name], color=colors[name], label=name,
                   edgecolors="none", zorder=3)
    ax.set_yscale("log")
    ax.set_xlim(-0.03, 1.03)
    ax.set_xlabel("fraction of net variation explained by predecessor identity")
    ax.set_ylabel("net variation (cycles)")
    style(ax)
    ax.grid(True, axis="both", color=GRID, linewidth=0.6)

    notes = [
        ("process spawn", "0xffffffff8098efca-0xffffffff8098efd0", "down_write", (0.05, 2.2)),
        ("TLB shootdown", "0xffffffff8007ccfc-0xffffffff8007cd16", "do_raw_spin_lock", (0.05, 0.35)),
        ("gcc", "0x3dbc34-0x3dbc54", "gcc recog", (0.05, 1.8)),
        ("mcf", "0x12e24-0x12e82", "primal_bea_mpp (path-split block)", (-0.42, 0.22)),
        ("mcf", "0x12e02-0x12e1c", "primal_bea_mpp (arc-scan stalls)", (0.06, 0.3)),
        ("mcf", "0x12c8a-0x12c92", "cost_compare", (0.06, 0.5)),
    ]
    for wl, bb, label, (dx, fy) in notes:
        if bb not in decs[wl].index:
            continue
        r = decs[wl].loc[bb]
        ax.annotate(label, (r["frac"], r["netvar"]),
                    xytext=(r["frac"] + dx, r["netvar"] * fy),
                    fontsize=8.5, color=INK,
                    arrowprops=dict(arrowstyle="-", color=INK2, linewidth=0.7))
    ax.text(0.02, 0.03, "← data-driven variance (prefetch / MLP)",
            transform=ax.transAxes, fontsize=8.5, color=INK2)
    ax.text(0.98, 0.03, "context-driven variance (specialize / layout) →",
            transform=ax.transAxes, fontsize=8.5, color=INK2, ha="right")
    leg = ax.legend(loc="upper center", ncols=4, frameon=False, fontsize=9,
                    bbox_to_anchor=(0.5, 1.02))
    for t in leg.get_texts():
        t.set_color(INK)
    ax.set_title("Pair-conditioned profiling decomposes each block's variance:\n"
                 "is it the data, or the path that got you here?",
                 fontsize=10.5, color=INK, loc="left", pad=26)
    fig.tight_layout()
    fig.savefig("pair_profile_fig3_decomposition.png", dpi=200,
                facecolor="white", bbox_inches="tight")
    print("wrote pair_profile_fig3_decomposition.png")


def main():
    mcf = load("trace.mcf.pair-study.golden.bb_pair_stats.csv")
    mcf_emu = load("trace.mcf.pair-study.tnt_cyc_retcompressed.bb_pair_stats.csv")
    spawn = load("trace.pl-t256.pair-study.golden.bb_pair_stats.csv")
    ipi = pd.concat([load("trace.ipi0.pair-study.golden.bb_pair_stats.csv"),
                     load("trace.ipi1.pair-study.golden.bb_pair_stats.csv")])
    gcc = load("trace.gcc.pair-study.golden.bb_pair_stats.csv")

    fig_fanout(mcf)
    fig_collapse(mcf, mcf_emu)
    fig_decomposition({"process spawn": spawn, "TLB shootdown": ipi,
                       "gcc": gcc, "mcf": mcf})


if __name__ == "__main__":
    main()
