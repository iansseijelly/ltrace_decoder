import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os
import re

matplotlib.rcParams.update({'font.size': 18})

BENCHMARKS = [
    "600_perlbench",
    "602_gcc",
    "605_mcf",
    "620_omnetpp",
    "623_xalancbmk",
    "625_x264",
    "641_leela",
    "648_exchange2",
    "657_xz_cld",
    "657_xz_cpu2006docs",
]

# Pattern: BB Emulation Error (name): Weighted Error XX.XXXX%
# Pattern: Func Emulation Error (name): Weighted Error XX.XXXX%
BB_PATTERN = re.compile(r'BB Emulation Error \((.+?)\): Weighted Error ([\d.]+)%')
FUNC_PATTERN = re.compile(r'Func Emulation Error \((.+?)\): Weighted Error ([\d.]+)%')


def parse_results(trace_errors_dir: str):
    bb_results = {}   # emulator_name -> {benchmark -> error}
    func_results = {}

    for bench in BENCHMARKS:
        path = os.path.join(trace_errors_dir, f"{bench}.txt")
        if not os.path.exists(path):
            print(f"Warning: {path} not found, skipping")
            continue
        with open(path) as f:
            content = f.read()

        for m in BB_PATTERN.finditer(content):
            name, error = m.group(1), float(m.group(2))
            bb_results.setdefault(name, {})[bench] = error

        for m in FUNC_PATTERN.finditer(content):
            name, error = m.group(1), float(m.group(2))
            func_results.setdefault(name, {})[bench] = error

    return bb_results, func_results


def plot_grouped_bar(results: dict, title: str, output_path: str, legend_loc: str = 'lower right'):
    if not results:
        print(f"No data for {title}, skipping")
        return

    emulators = sorted(results.keys())
    benchmarks = [b for b in BENCHMARKS if any(b in results[e] for e in emulators)]
    short_names = [b.split('_', 1)[1] for b in benchmarks]

    x = np.arange(len(benchmarks))
    n = len(emulators)
    width = 0.8 / n

    def legend_name(emu_name):
        if 'tnt_cyc_nret' in emu_name:
            return 'TNT_CYC_NRET'
        if 'tnt_cyc_retcompressed' in emu_name:
            return 'TNT_CYC'
        if emu_name.startswith('tc_'):
            return 'TC'
        return emu_name

    fig, ax = plt.subplots(figsize=(10, 7))
    for i, emu in enumerate(emulators):
        values = [results[emu].get(b, 0) for b in benchmarks]
        offset = (i - n / 2 + 0.5) * width
        ax.bar(x + offset, values, width, label=legend_name(emu))

    ax.set_xlabel('Benchmark')
    ax.set_ylabel('Weighted Error (%)')
    ax.set_title(title, pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(short_names, rotation=45, ha='right')

    ax.legend(loc=legend_loc, fontsize=16)
    ax.grid(axis='y', linestyle=':', alpha=0.5)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"Saved {output_path}")


def print_summary(bb_results, func_results):
    print('=' * 80)
    print('BB Emulation Errors (Weighted Error %)')
    print('=' * 80)
    emulators = sorted(bb_results.keys())
    header = f"{'Benchmark':25s}" + "".join(f"{e:>20s}" for e in emulators)
    print(header)
    for bench in BENCHMARKS:
        row = f"{bench:25s}"
        for emu in emulators:
            val = bb_results.get(emu, {}).get(bench, None)
            row += f"{val:>19.4f}%" if val is not None else f"{'N/A':>20s}"
        print(row)

    print()
    print('=' * 80)
    print('Func Emulation Errors (Weighted Error %)')
    print('=' * 80)
    emulators = sorted(func_results.keys())
    header = f"{'Benchmark':25s}" + "".join(f"{e:>20s}" for e in emulators)
    print(header)
    for bench in BENCHMARKS:
        row = f"{bench:25s}"
        for emu in emulators:
            val = func_results.get(emu, {}).get(bench, None)
            row += f"{val:>19.4f}%" if val is not None else f"{'N/A':>20s}"
        print(row)
    print('=' * 80)


def legend_name(emu_name):
    if 'tnt_cyc_nret' in emu_name:
        return 'TNT_CYC_NRET'
    if 'tnt_cyc_retcompressed' in emu_name:
        return 'TNT_CYC'
    if emu_name.startswith('tc_'):
        return 'TC'
    return emu_name


def plot_combined(bb_results: dict, func_results: dict, output_path: str):
    if not bb_results or not func_results:
        print("Missing data for combined plot, skipping")
        return

    # Group by emulation strategy — match BB and Func keys by legend name
    bb_keys = sorted(bb_results.keys())
    func_keys = sorted(func_results.keys())
    strategies = []  # (legend_label, bb_key, func_key)
    seen = set()
    for key in bb_keys:
        label = legend_name(key)
        if label in seen:
            continue
        seen.add(label)
        func_key = next((k for k in func_keys if legend_name(k) == label), None)
        strategies.append((label, key, func_key))

    benchmarks = [b for b in BENCHMARKS if any(b in bb_results.get(s[1], {}) for s in strategies)]
    short_names = [b.split('_', 1)[1] for b in benchmarks]

    x = np.arange(len(benchmarks))
    n = len(strategies)
    colors = [plt.cm.tab10(i) for i in range(n)]
    width = 0.8 / n

    fig, (ax_bb, ax_func) = plt.subplots(2, 1, figsize=(10, 9), sharex=True)

    for i, (label, bb_key, func_key) in enumerate(strategies):
        offset = -0.4 + width * (i + 0.5)
        bb_vals = [bb_results.get(bb_key, {}).get(b, 0) for b in benchmarks]
        ax_bb.bar(x + offset, bb_vals, width * 0.95, color=colors[i], label=label)
        if func_key:
            func_vals = [func_results.get(func_key, {}).get(b, 0) for b in benchmarks]
            ax_func.bar(x + offset, func_vals, width * 0.95, color=colors[i])

    ax_bb.set_ylabel('Weighted Error (%)')
    ax_bb.set_title('BB-Level', pad=10)
    ax_bb.grid(axis='y', linestyle=':', alpha=0.5)

    ax_func.set_ylabel('Weighted Error (%)')
    ax_func.set_title('Func-Level', pad=10)
    ax_func.set_xticks(x)
    ax_func.set_xticklabels(short_names, rotation=45, ha='right')
    ax_func.grid(axis='y', linestyle=':', alpha=0.5)

    fig.legend(*ax_bb.get_legend_handles_labels(), loc='upper center', ncol=n, fontsize=16, bbox_to_anchor=(0.5, 1.02))
    fig.suptitle('Emulation Weighted Error by Benchmark', fontsize=18, y=1.08)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Saved {output_path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Plot emulation error results')
    parser.add_argument('--dir', type=str, default='trace_errors', help='Directory with benchmark .txt outputs')
    parser.add_argument('--output-prefix', type=str, default='emulation_error', help='Output file prefix')
    args = parser.parse_args()

    bb_results, func_results = parse_results(args.dir)
    print_summary(bb_results, func_results)
    plot_combined(bb_results, func_results, f'{args.output_prefix}.combined.png')
