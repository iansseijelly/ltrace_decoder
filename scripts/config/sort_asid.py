import argparse
import re
from collections import defaultdict

def parse_args():
    parser = argparse.ArgumentParser(
        description="Summarize min/max ASID per comm from a log file."
    )
    parser.add_argument(
        "input",
        type=str,
        help="Path to the input log file",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    pattern = re.compile(r"\basid=(\d+)\b.*\bcomm=([^\s]+)")
    stats = defaultdict(list)

    with open(args.input, "r") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue
            asid = int(m.group(1))
            comm = m.group(2)
            stats[comm].append(asid)

    for comm in sorted(stats.keys()):
        values = stats[comm]
        print(f"{comm} {min(values)} {max(values)}")


if __name__ == "__main__":
    main()
