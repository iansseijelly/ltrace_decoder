"""
Given two per-basic block delta CSV files, quantify delta error.
"""

import argparse
import csv

REQUIRED_COLUMNS = {"delta", "event", "from", "to"}


def load_rows(path: str):
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: missing CSV header")
        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                f"{path}: missing required column(s): {', '.join(sorted(missing))}"
            )

        for row_idx, row in enumerate(reader, 2):
            event = (row.get("event") or "").strip()
            src = (row.get("from") or "").strip()
            dst = (row.get("to") or "").strip()
            delta_str = (row.get("delta") or "").strip()
            if not (event or src or dst or delta_str):
                continue
            try:
                delta = int(delta_str)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{row_idx}: invalid delta value: {delta_str}"
                ) from exc
            rows.append({"delta": delta, "event": event, "from": src, "to": dst})
    return rows


def variance(values):
    mean = sum(values) / len(values)
    return sum((v - mean) ** 2 for v in values) / len(values)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", type=str, required=True)
    parser.add_argument("--measured", type=str, required=True)
    args = parser.parse_args()

    golden_rows = load_rows(args.golden)
    measured_rows = load_rows(args.measured)

    if len(measured_rows) > len(golden_rows):
        raise ValueError(
            f"Measured has more rows than golden: {len(measured_rows)} > {len(golden_rows)}"
        )
    if not measured_rows:
        raise ValueError("Measured trace is empty.")

    abs_errors = []
    golden_deltas = []
    measured_deltas = []
    for idx, measured_row in enumerate(measured_rows, 1):
        golden_row = golden_rows[idx - 1]
        golden_rest = (golden_row["event"], golden_row["from"], golden_row["to"])
        measured_rest = (measured_row["event"], measured_row["from"], measured_row["to"])
        if golden_rest != measured_rest:
            raise ValueError(
                f"Row {idx} mismatch:\n"
                f"  golden:   event={golden_row['event']}, from={golden_row['from']}, to={golden_row['to']}\n"
                f"  measured: event={measured_row['event']}, from={measured_row['from']}, to={measured_row['to']}"
            )
        abs_errors.append(abs(golden_row["delta"] - measured_row["delta"]))
        golden_deltas.append(golden_row["delta"])
        measured_deltas.append(measured_row["delta"])

    mae = sum(abs_errors) / len(abs_errors)
    total_error = sum(abs_errors)
    total_time = sum(golden_deltas)
    var_golden = variance(golden_deltas)
    var_measured = variance(measured_deltas)
    var_ratio = float("inf") if var_golden == 0 else var_measured / var_golden
    weighted_error = float("inf") if total_time == 0 else total_error / total_time

    print(f"MAE: {mae:.6f}")
    if var_ratio == float("inf"):
        print("VarRatio: inf")
    else:
        print(f"VarRatio: {var_ratio:.6f}")
    if weighted_error == float("inf"):
        print("WeightedError: inf")
    else:
        print(f"WeightedError: {weighted_error * 100:.4f}%")


if __name__ == "__main__":
    main()
