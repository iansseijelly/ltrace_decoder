"""
Given a per-basic block emulation CSV with reference_delta and emulated_delta columns,
quantify the emulation error.
"""

import argparse
import csv


def variance(values):
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=str, required=True, help="CSV with reference_delta and emulated_delta columns")
    args = parser.parse_args()

    abs_errors = []
    ref_deltas = []
    emu_deltas = []

    with open(args.input, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, 2):
            try:
                ref = int(row["reference_delta"])
                emu = int(row["emulated_delta"])
            except (KeyError, ValueError) as exc:
                raise ValueError(f"{args.input}:{row_idx}: invalid row: {row}") from exc
            abs_errors.append(abs(ref - emu))
            ref_deltas.append(ref)
            emu_deltas.append(emu)

    if not ref_deltas:
        raise ValueError("Input is empty.")

    mae = sum(abs_errors) / len(abs_errors)
    total_error = sum(abs_errors)
    total_time = sum(ref_deltas)
    var_ref = variance(ref_deltas)
    var_emu = variance(emu_deltas)
    var_ratio = float("inf") if var_ref == 0 else var_emu / var_ref
    weighted_error = float("inf") if total_time == 0 else total_error / total_time

    print(f"Events:        {len(ref_deltas)}")
    print(f"MAE:           {mae:.6f}")
    if var_ratio == float("inf"):
        print("VarRatio:      inf")
    else:
        print(f"VarRatio:      {var_ratio:.6f}")
    if weighted_error == float("inf"):
        print("WeightedError: inf")
    else:
        print(f"TotalError:    {total_error}")
        print(f"TotalTime:     {total_time}")
        print(f"WeightedError: {weighted_error * 100:.4f}%")


if __name__ == "__main__":
    main()
