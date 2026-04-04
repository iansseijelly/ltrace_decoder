#!/usr/bin/env python3
"""Extract ASIDs from a uartlog and populate a tacit_decoder config JSON."""

import argparse
import json
import re
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Extract ASIDs from uartlog and populate config JSON."
    )
    parser.add_argument("--uartlog", help="Path to the uartlog file")
    parser.add_argument("--config", help="Path to the tacit_decoder config JSON")
    parser.add_argument("--binary_name", help="Binary comm name to filter for (e.g. perlbench_s_bas)")
    args = parser.parse_args()

    # Extract matching ASIDs from the log
    pattern = re.compile(r"^tacit: asid=(\d+) pid=\d+ comm=(.+)$")
    asids = []
    with open(args.uartlog) as f:
        for line in f:
            line = line.strip()
            m = pattern.match(line)
            if m and m.group(2) == args.binary_name:
                asids.append(int(m.group(1)))

    if not asids:
        print(f"Warning: no ASIDs found for '{args.binary_name}'", file=sys.stderr)

    asids = sorted(set(asids))
    print(f"Found {len(asids)} unique ASIDs for '{args.binary_name}': {asids}")

    # Update the config
    with open(args.config) as f:
        config = json.load(f)

    for entry in config.get("user_binaries", []):
        entry["asids"] = asids

    with open(args.config, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")

    print(f"Updated {args.config}")


if __name__ == "__main__":
    main()
