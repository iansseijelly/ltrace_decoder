import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib
import sys

matplotlib.rcParams.update({'font.size': 16})

named_bbs = {
    "0x80000418": "trap save",
    "0x8000290c": "memcpy",
    "0x800053cc": "atmoic exchange",
    "0x800054fa": "spin_lock",
    "0x800004a6": "trap restore",
    "0x800022c4": "pmu_ctr_incr_fw",
    "0x800010b2": "ipi process",
    "0x80005526": "spin_unlock",
    "0x80008756": "hart_has_extension",
    "0x80003a74": "trap_handler",
    "0x80002908": "memcpy",
    "0x80017c98": "clear clint ipi"
}

def main():
    if len(sys.argv) < 2:
        print("Usage: python plot_func_path_pareto.py <bb_csv> [output_png]")
        sys.exit(1)

    bb_csv = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "func_path_pareto.png"

    df = pd.read_csv(bb_csv)
    # strip whitespace from column names
    df.columns = df.columns.str.strip()

    # aggregate by BB
    bb_agg = df.groupby(["bb_start", "bb_end"]).agg(
        total_cycles=("duration", "sum"),
        count=("duration", "count"),
        mean_cycles=("duration", "mean"),
    ).reset_index()

    bb_agg = bb_agg.sort_values("total_cycles", ascending=False).reset_index(drop=True)

    top_n = 12
    top = bb_agg.head(top_n).copy()
    other_total = bb_agg.iloc[top_n:]["total_cycles"].sum()

    # labels
    top["label"] = top.apply(
        lambda r: f"{r['bb_start']}", axis=1
    )
    # substitute named bbs
    top["label"] = top["label"].apply(
        lambda k: named_bbs[k] if k in named_bbs else k
    )
    labels = list(top["label"]) + ["Other"]
    values = list(top["total_cycles"]) + [other_total]

    grand_total = sum(values)
    cumulative = []
    running = 0
    for v in values:
        running += v
        cumulative.append(running / grand_total * 100)

    top_pct = cumulative[top_n - 1]

    # convert to % of total
    values_pct = [v / grand_total * 100 for v in values]

    # plot
    fig, ax1 = plt.subplots(figsize=(10,6))

    bars = ax1.bar(range(len(labels)), values_pct, color="#4878CF", edgecolor="white", zorder=2)
    # highlight "Other" bar
    bars[-1].set_color("#CCCCCC")

    ax1.set_ylabel("% of Total Cycles")
    ax1.set_xticks(range(len(labels)))
    ax1.set_xticklabels(labels, rotation=45, ha="right", fontsize=12, family="monospace")
    ax1.set_xlim(-0.6, len(labels) - 0.4)
    ax1.grid(axis="y", alpha=0.3, zorder=0)

    # cumulative line on secondary axis
    ax2 = ax1.twinx()
    ax2.plot(range(len(labels)), cumulative, color="#D65F5F", marker="o",
             markersize=5, linewidth=2, zorder=3)
    ax2.set_ylabel("Cumulative %", color="#D65F5F")
    ax2.set_ylim(0, 105)
    ax2.yaxis.set_major_formatter(mticker.PercentFormatter())
    ax2.tick_params(axis="y", labelcolor="#D65F5F")

    # annotate the top-N cumulative point
    ax2.annotate(
        f"{top_pct:.1f}%",
        xy=(top_n - 1, cumulative[top_n - 1]),
        xytext=(top_n - 1.5, cumulative[top_n - 1] - 10),
        color="#D65F5F"
    )

    ax2.annotate(
        f"{cumulative[4-1]:.1f}%",
        xy=(4 - 1, cumulative[4 - 1]),
        xytext=(4 - 1.5, cumulative[4 - 1] + 5),
        color="#D65F5F"
    )

    n_invocations = df["invocation"].nunique()
    ax1.set_title(
        f"BB-Level Cycle Attribution — Top {top_n} BBs ({n_invocations} invocations)",
        pad=12,
    )

    fig.tight_layout()
    fig.savefig(output, dpi=200, bbox_inches="tight")
    print(f"Saved to {output}")
    print(f"--- Stats ---")
    print(f"Invocations:      {n_invocations}")
    print(f"Total BB records: {len(df)}")
    print(f"Unique BBs:       {len(bb_agg)}")
    print(f"Total cycles:     {grand_total}")
    print(f"Mean cycles/inv:  {grand_total / n_invocations:.1f}")
    print(f"Top {top_n} BBs:       {top_pct:.1f}% of total cycles")


if __name__ == "__main__":
    main()
