# Given a sequence of iter: time pairs, plot the distribution of the times.

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import argparse
import re

pattern = r'(\d+): (\d+)'

def _sci_fmt(x: float) -> str:
    s = f'{x:.2e}'
    return s

def plot_distribution(input_file: str) -> None:
    with open(input_file, 'r') as f:
        content = f.read()
    matches = re.findall(pattern, content)
    times = [int(match[1]) for match in matches]
    plt.hist(times, bins=100, alpha=0.8, weights=np.ones_like(times) / len(times) * 100)

    mean_val = sum(times) / len(times)
    p90 = np.percentile(times, 90)
    p95 = np.percentile(times, 95)
    p99 = np.percentile(times, 99)

    plt.axvline(mean_val, color='green', linestyle='--', linewidth=1, label=f'p50 ({_sci_fmt(mean_val)})')
    plt.axvline(p90, color='orange', linestyle='--', linewidth=1, label=f'p90 ({_sci_fmt(p90)})')
    plt.axvline(p95, color='red', linestyle='--', linewidth=1, label=f'p95 ({_sci_fmt(p95)})')
    plt.axvline(p99, color='darkviolet', linestyle='--', linewidth=1, label=f'p99 ({_sci_fmt(p99)})')
    plt.legend()
    plt.xlabel('Latency (cycles)')
    plt.ylabel('Percentage (%)')

    plt.title(f'Distribution for process spawn-reap latency')
    plt.tight_layout()

    print(f'{input_file}: {min(times)} to {max(times)}')
    print(f'{input_file}: {mean_val} average')
    print(f'{input_file}: {np.median(times)} median')
    print(f'{input_file}: {np.percentile(times, 25)} 25th percentile')
    print(f'{input_file}: {np.percentile(times, 75)} 75th percentile')
    print(f'{input_file}: {p90} 90th percentile')
    print(f'{input_file}: {p95} 95th percentile')
    print(f'{input_file}: {p99} 99th percentile')

    plt.savefig(f'{input_file}.png')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, required=True)
    args = parser.parse_args()
    plot_distribution(args.input)