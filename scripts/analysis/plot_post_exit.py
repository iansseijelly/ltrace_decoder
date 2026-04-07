import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import sys

matplotlib.rcParams.update({'font.size': 16})

def main():
    if len(sys.argv) < 2:
        print("Usage: python plot_post_exit.py <post_exit_csv> [output_png]")
        sys.exit(1)

    csv_path = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "func_path_post_exit.png"

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    max_idx = df["bb_index"].max()
    # prepare data for box plot
    data = [df[df["bb_index"] == i]["duration"].values for i in range(max_idx + 1)]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.scatter(df["bb_index"], df["duration"], alpha=0.3, s=10, color="#4878CF")


    # box plot
    # bp = ax.boxplot(data, positions=range(max_idx + 1), widths=0.5,
    #                 patch_artist=True, showfliers=True,
    #                 flierprops=dict(marker='.', markersize=4, alpha=0.5, color="#999999"),
    #                 medianprops=dict(color="white", linewidth=2),
    #                 whiskerprops=dict(color="#4878CF"),
    #                 capprops=dict(color="#4878CF"))
    # for box in bp["boxes"]:
    #     box.set_facecolor("#4878CF")
    #     box.set_alpha(0.7)

    # mean line
    means = df.groupby("bb_index")["duration"].mean()
    ax.plot(means.index, means.values, color="#D65F5F", marker="o",
            markersize=5, linewidth=2, label="mean", zorder=5, alpha=0.7)

    ax.set_xlabel("BB Index After Trap Return")
    ax.set_ylabel("Duration (cycles)")
    ax.set_xticks(range(max_idx + 1))
    ax.grid(axis="y", alpha=0.3)
    ax.legend()

    n_inv = df["invocation"].nunique()
    ax.set_title(f"Post-Trap Return BB Latency", pad=12)

    fig.tight_layout()
    fig.savefig(output, dpi=200, bbox_inches="tight")
    print(f"Saved to {output}")

if __name__ == "__main__":
    main()
