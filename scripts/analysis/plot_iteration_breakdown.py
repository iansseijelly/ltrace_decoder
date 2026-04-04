import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import argparse

matplotlib.rcParams.update({'font.size': 16})


def _sci_fmt(x: float) -> str:
    return f'{x:.2e}'


def plot_latency_distribution(df: pd.DataFrame, output_prefix: str) -> None:
    times = df['total_cycles'].values
    plt.figure(figsize=(10, 6))
    plt.hist(times, bins=50, alpha=0.8, weights=np.ones_like(times) / len(times) * 100)

    p50 = np.percentile(times, 50)
    p90 = np.percentile(times, 90)
    p95 = np.percentile(times, 95)
    p99 = np.percentile(times, 99)

    plt.axvline(p50, color='green', linestyle='--', linewidth=1, label=f'p50 ({_sci_fmt(p50)})')
    plt.axvline(p90, color='orange', linestyle='--', linewidth=1, label=f'p90 ({_sci_fmt(p90)})')
    plt.axvline(p95, color='red', linestyle='--', linewidth=1, label=f'p95 ({_sci_fmt(p95)})')
    plt.axvline(p99, color='darkviolet', linestyle='--', linewidth=1, label=f'p99 ({_sci_fmt(p99)})')
    plt.legend()
    plt.xlabel('Latency (cycles)')
    plt.ylabel('Percentage (%)')
    plt.title('Iteration Latency Distribution')
    plt.tight_layout()
    plt.savefig(f'{output_prefix}.latency_distribution.png')
    plt.close()


def plot_prv_breakdown(df: pd.DataFrame, output_prefix: str) -> None:
    fig, ax = plt.subplots(figsize=(12, 6))
    iters = df['iter'].values
    ax.bar(iters, df['user_cycles'], label='User', color='#2196F3')
    ax.bar(iters, df['supervisor_cycles'], bottom=df['user_cycles'], label='Supervisor', color='#FF9800')
    ax.bar(iters, df['machine_cycles'],
           bottom=df['user_cycles'] + df['supervisor_cycles'], label='Machine', color='#F44336')
    ax.set_xlabel('Iteration')
    ax.set_ylabel('Cycles')
    ax.set_title('Per-Iteration Privilege Level Breakdown')
    ax.legend()
    plt.tight_layout()
    plt.savefig(f'{output_prefix}.prv_breakdown.png')
    plt.close()


def plot_tracked_func_impact(df: pd.DataFrame, tracked_func: str, output_prefix: str) -> None:
    count_col = f'{tracked_func}_count'
    cycles_col = f'{tracked_func}_cycles'
    avg_col = f'{tracked_func}_avg_cycles'

    if count_col not in df.columns:
        print(f'No {count_col} column found, skipping tracked function plots')
        return

    df_with = df[df[count_col] > 0]
    df_without = df[df[count_col] == 0]

    # Box plot: with vs without tracked function
    fig, ax = plt.subplots(figsize=(8, 6))
    data = [d['total_cycles'].values for d in [df_without, df_with] if len(d) > 0]
    labels = []
    if len(df_without) > 0:
        labels.append(f'Without {tracked_func}\n(n={len(df_without)})')
    if len(df_with) > 0:
        labels.append(f'With {tracked_func}\n(n={len(df_with)})')
    ax.boxplot(data, labels=labels)
    ax.set_ylabel('Total Cycles')
    ax.set_title(f'Impact of {tracked_func} on Iteration Latency')
    plt.tight_layout()
    plt.savefig(f'{output_prefix}.tracked_func_boxplot.png')
    plt.close()

    if len(df_with) > 0:
        # Scatter: tracked_func_cycles vs total_cycles (publication grade)
        fig, ax = plt.subplots(figsize=(8, 6))
        x = df_with[cycles_col].values
        y = df_with['total_cycles'].values
        ax.scatter(x, y, alpha=0.5, s=25, edgecolors='none', color='#1f77b4', zorder=3)

        # Linear fit (excluding 1 max and 1 min by total_cycles to reduce outlier influence)
        sort_idx = np.argsort(y)
        trimmed = sort_idx[1:-1]
        x_trim, y_trim = x[trimmed], y[trimmed]
        coeffs = np.polyfit(x_trim, y_trim, 1)
        x_fit = np.linspace(x.min(), x.max(), 100)
        y_fit = np.polyval(coeffs, x_fit)
        r2 = 1 - np.sum((y_trim - np.polyval(coeffs, x_trim)) ** 2) / np.sum((y_trim - y_trim.mean()) ** 2)
        ax.plot(x_fit, y_fit, color='#d62728', linewidth=1.5, alpha=0.7, zorder=4,
                label=f'Linear fit after outlier removal')

        ax.ticklabel_format(axis='x', style='scientific', scilimits=(0, 0))
        ax.grid(True, linestyle=':', linewidth=0.5, alpha=0.5)
        ax.set_xlabel(f'{tracked_func} Total Cycles')
        ax.set_ylabel('Total Iteration Cycles')
        ax.set_title(f'{tracked_func} Cycles vs Iteration Latency', pad=15)
        ax.legend()
        plt.tight_layout()
        plt.savefig(f'{output_prefix}.tracked_func_scatter.png', dpi=300)
        plt.close()

        # Scatter: invocation count vs total_cycles
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.scatter(df_with[count_col], df_with['total_cycles'], alpha=0.6, s=20)
        ax.set_xlabel(f'{tracked_func} Invocation Count')
        ax.set_ylabel('Total Iteration Cycles')
        ax.set_title(f'{tracked_func} Invocation Count vs Iteration Latency')
        plt.tight_layout()
        plt.savefig(f'{output_prefix}.tracked_func_count_scatter.png')
        plt.close()


def plot_prv_comparison(df: pd.DataFrame, tracked_func: str, output_prefix: str) -> None:
    count_col = f'{tracked_func}_count'
    if count_col not in df.columns:
        return

    df_with = df[df[count_col] > 0]
    df_without = df[df[count_col] == 0]
    if len(df_with) == 0 or len(df_without) == 0:
        return

    groups = {'Without': df_without, 'With': df_with}
    labels = list(groups.keys())
    user_pcts, sup_pcts, mach_pcts = [], [], []
    for group in groups.values():
        total = group['total_cycles'].mean()
        user_pcts.append(group['user_cycles'].mean() / total * 100)
        sup_pcts.append(group['supervisor_cycles'].mean() / total * 100)
        mach_pcts.append(group['machine_cycles'].mean() / total * 100)

    fig, ax = plt.subplots(figsize=(8, 3))
    y = np.arange(len(labels))
    bar_height = 0.5

    ax.barh(y, user_pcts, bar_height, label='User', color='#2196F3')
    ax.barh(y, sup_pcts, bar_height, left=user_pcts, label='Supervisor', color='#FF9800')
    ax.barh(y, mach_pcts, bar_height,
            left=[u + s for u, s in zip(user_pcts, sup_pcts)], label='Machine', color='#F44336')

    ax.set_yticks(y)
    ax.set_yticklabels([f'{l} {tracked_func}\n(n={len(g)})' for l, g in zip(labels, groups.values())])
    ax.set_xlabel('Percentage of Total Cycles (%)')
    ax.set_xlim(0, 100)
    ax.set_title(f'Privilege Level Breakdown: With vs Without {tracked_func}')
    ax.legend(loc='upper left', bbox_to_anchor=(1.01, 1))
    plt.tight_layout()
    plt.savefig(f'{output_prefix}.prv_comparison.png')
    plt.close()


def print_summary(df: pd.DataFrame, tracked_func: str) -> None:
    times = df['total_cycles']
    print('=' * 60)
    print('Iteration Breakdown Summary')
    print('=' * 60)
    print(f'  Iterations:  {len(df)}')
    print(f'  Min:         {times.min()}')
    print(f'  Max:         {times.max()}')
    print(f'  Mean:        {times.mean():.0f}')
    print(f'  Std:         {times.std():.0f}')
    print(f'  Median:      {times.median():.0f}')
    print(f'  p90:         {np.percentile(times, 90):.0f}')
    print(f'  p95:         {np.percentile(times, 95):.0f}')
    print(f'  p99:         {np.percentile(times, 99):.0f}')
    print()
    print('Privilege level breakdown (mean across iterations):')
    for col in ['user_cycles', 'supervisor_cycles', 'machine_cycles']:
        pct = df[col].mean() / times.mean() * 100
        print(f'  {col:25s}: {df[col].mean():12.0f} ({pct:5.1f}%)')

    count_col = f'{tracked_func}_count'
    cycles_col = f'{tracked_func}_cycles'
    avg_col = f'{tracked_func}_avg_cycles'
    if count_col in df.columns:
        df_with = df[df[count_col] > 0]
        df_without = df[df[count_col] == 0]
        n_with = len(df_with)
        n_total = len(df)
        print()
        print(f'{tracked_func} impact:')
        print(f'  Iterations with {tracked_func}: {n_with}/{n_total} ({n_with/n_total*100:.1f}%)')
        if n_with > 0:
            mean_with = df_with['total_cycles'].mean()
            mean_without = df_without['total_cycles'].mean() if len(df_without) > 0 else 0
            mean_count = df_with[count_col].mean()
            mean_total_cycles = df_with[cycles_col].mean()
            mean_avg_cycles = df_with[avg_col].mean()
            print(f'  Mean latency with:        {mean_with:.0f}')
            if len(df_without) > 0:
                print(f'  Mean latency without:     {mean_without:.0f}')
                print(f'  Mean overhead:            {mean_with - mean_without:.0f} ({(mean_with - mean_without) / mean_without * 100:.1f}%)')
            print(f'  Mean invocations/iter:    {mean_count:.1f}')
            print(f'  Mean total cycles/iter:   {mean_total_cycles:.0f}')
            print(f'  Mean cycles/invocation:   {mean_avg_cycles:.0f}')
        print()
        print(f'Privilege level comparison (with vs without {tracked_func}):')
        for label, group in [('With', df_with), ('Without', df_without)]:
            if len(group) == 0:
                continue
            u_pct = group['user_cycles'].mean() / group['total_cycles'].mean() * 100
            s_pct = group['supervisor_cycles'].mean() / group['total_cycles'].mean() * 100
            m_pct = group['machine_cycles'].mean() / group['total_cycles'].mean() * 100
            print(f'  {label:10s}  user={u_pct:5.1f}%  supervisor={s_pct:5.1f}%  machine={m_pct:5.1f}%')
        if len(df_with) > 0 and len(df_without) > 0:
            for col, name in [('user_cycles', 'user'), ('supervisor_cycles', 'supervisor'), ('machine_cycles', 'machine')]:
                pct_with = df_with[col].mean() / df_with['total_cycles'].mean() * 100
                pct_without = df_without[col].mean() / df_without['total_cycles'].mean() * 100
                print(f'  Delta {name:12s}: {pct_with - pct_without:+.1f}pp')
    print('=' * 60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Plot iteration breakdown analysis')
    parser.add_argument('--iterations', type=str, required=True, help='Path to iteration_breakdown CSV')
    parser.add_argument('--tracked-func', type=str, default='rcu_do_batch', help='Name of tracked function')
    parser.add_argument('--output-prefix', type=str, default='iteration', help='Output file prefix')
    args = parser.parse_args()

    df = pd.read_csv(args.iterations)
    print_summary(df, args.tracked_func)
    plot_latency_distribution(df, args.output_prefix)
    plot_prv_breakdown(df, args.output_prefix)
    plot_tracked_func_impact(df, args.tracked_func, args.output_prefix)
    plot_prv_comparison(df, args.tracked_func, args.output_prefix)
    print(f'Plots saved to {args.output_prefix}.*.png')
