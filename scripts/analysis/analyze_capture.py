#!/usr/bin/env python3
"""Analyze a self-contained capture bundle produced by bundle_run.py:

  1. Provenance check: every driver_binary_entry_tuples address in the
     bundle's config must match the module base recorded in the bundle's
     own uartlog (/proc/modules block). Refuse to decode on mismatch --
     a wrong base silently mis-symbolizes kernel PCs.
  2. Decode the TACIT trace with tacit-decoder (config paths resolved to
     absolute inside the bundle; products land in <bundle>/out/).
  3. Compute epsilon(BB) against every bboracle csv in the bundle (both
     the plain and boundary-policy captures when present).

Usage: analyze_capture.py BUNDLE_DIR [--decoder-bin PATH] [--skip-decode]
Exits nonzero on provenance mismatch, decode failure, or epsilon failure.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DECODER_ROOT = HERE.parents[1]
MODULES_RX = re.compile(r"^(\w+) \d+ \d+ \S+ Live (0x[0-9a-f]+)",
                        re.MULTILINE)
EPS_RX = re.compile(r"epsilon\(BB\) = ([0-9.]+)%")


def die(msg):
    sys.exit(f"analyze_capture: ERROR: {msg}")


def parse_uartlog_modules(uartlog):
    text = uartlog.read_text(errors="replace").replace("\r", "")
    m = re.search(r"::MODULES_BEGIN::\n(.*?)::MODULES_END::", text, re.DOTALL)
    scope = m.group(1) if m else text
    return {name: addr for name, addr in MODULES_RX.findall(scope)}


def module_name(tuple_path):
    stem = Path(tuple_path).name
    for suffix in ("-dwarf", ".o", ".ko"):
        if stem.endswith(suffix):
            return stem[:-len(suffix)]
    return stem


def check_provenance(bundle, cfg):
    tuples = cfg.get("driver_binary_entry_tuples") or []
    if not tuples:
        print("provenance: baremetal capture (no driver tuples), skipping "
              "module check")
        return
    uartlog = bundle / "uartlog"
    if not uartlog.exists():
        die("config has driver tuples but bundle has no uartlog")
    mods = parse_uartlog_modules(uartlog)
    if not mods:
        die("uartlog contains no /proc/modules lines; cannot verify "
            "driver addresses (image predates the pinned-modprobe init?)")
    for path, addr in tuples:
        name = module_name(path)
        if name not in mods:
            die(f"module '{name}' in config but not in uartlog "
                f"(saw: {sorted(mods)})")
        if int(mods[name], 16) != int(addr, 16):
            die(f"ADDRESS MISMATCH for '{name}': config says {addr}, "
                f"uartlog says {mods[name]} -- refusing to decode")
    print(f"provenance: OK ({len(tuples)} module addresses verified "
          "against uartlog)")


def resolve_config(bundle, cfg):
    """Absolutize every path in the config against the bundle root; receiver
    outputs go to <bundle>/out/."""
    out = bundle / "out"
    out.mkdir(exist_ok=True)

    def absolutize(rel):
        return str((bundle / rel).resolve()) if rel else rel

    r = json.loads(json.dumps(cfg))  # deep copy
    for key in ("encoded_trace", "machine_binary", "kernel_binary",
                "kernel_jump_label_patch_log"):
        if r.get(key):
            if key == "encoded_trace" and not (bundle / r[key]).exists():
                die(f"{key} '{r[key]}' missing from bundle")
            r[key] = absolutize(r[key])
    for ub in r.get("user_binaries", []):
        ub["binary"] = absolutize(ub["binary"])
    r["driver_binary_entry_tuples"] = [
        [absolutize(p), a] for p, a in
        (r.get("driver_binary_entry_tuples") or [])]
    for rcfg in r.get("receivers", {}).values():
        if isinstance(rcfg, dict) and rcfg.get("path"):
            rcfg["path"] = str(out / Path(rcfg["path"]).name)
    resolved = out / "resolved_config.json"
    resolved.write_text(json.dumps(r, indent=2) + "\n")
    return resolved, r


def find_decoder(arg):
    if arg:
        return Path(arg)
    binpath = DECODER_ROOT / "target/release/tacit-decoder"
    if not binpath.exists():
        print("analyze_capture: building tacit-decoder (release)...")
        subprocess.run(["cargo", "build", "--release"],
                       cwd=DECODER_ROOT, check=True)
    return binpath


def decompress_oracles(bundle):
    """Return bboracle csv paths; .zst files are passed through untouched --
    bb_epsilon streams them (raw csvs reach ~100GB at SPEC scale)."""
    return [f for f in sorted((bundle / "oracle").glob("bboracle*"))
            if f.suffix in (".zst", ".csv")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", type=Path)
    ap.add_argument("--decoder-bin", type=Path, default=None)
    ap.add_argument("--skip-decode", action="store_true",
                    help="reuse an existing decode in out/")
    ap.add_argument("--skip-epsilon", action="store_true",
                    help="provenance check + decode only")
    args = ap.parse_args()

    bundle = args.bundle.resolve()
    cfg_path = bundle / "config.json"
    if not cfg_path.exists():
        die(f"{cfg_path} not found -- is this a bundle_run.py bundle?")
    cfg = json.loads(cfg_path.read_text())

    check_provenance(bundle, cfg)
    resolved, rcfg = resolve_config(bundle, cfg)

    txt_recv = rcfg.get("receivers", {}).get("txt", {}).get("path")
    if not txt_recv:
        die("config has no txt receiver; epsilon needs the decoded event "
            "trace")
    decoded = Path(txt_recv)

    if args.skip_decode:
        if not decoded.exists():
            die(f"--skip-decode but {decoded} does not exist")
    else:
        decoder = find_decoder(args.decoder_bin)
        log = bundle / "out/decode.log"
        with open(log, "w") as lf:
            rc = subprocess.run([str(decoder), "--config", str(resolved)],
                                stdout=lf, stderr=subprocess.STDOUT).returncode
        if rc != 0:
            die(f"decoder failed (rc={rc}), see {log}")
        if not decoded.exists() or decoded.stat().st_size == 0:
            die(f"decoder produced no events at {decoded}, see {log}")
        print(f"decode: OK ({decoded.name}, "
              f"{sum(1 for _ in open(decoded))} lines)")

    if args.skip_epsilon:
        print("analyze_capture: --skip-epsilon, done after decode")
        return

    asids = sorted({a for ub in cfg.get("user_binaries", [])
                    for a in ub.get("asids", [])})
    eps_args = ["--asids", ",".join(map(str, asids))] if asids else []

    summary = {}
    for csv in decompress_oracles(bundle):
        label = csv.stem
        print(f"\n=== epsilon(BB) vs {csv.name} ===")
        proc = subprocess.run(
            [sys.executable, str(HERE / "bb_epsilon.py"),
             "--tacit", str(decoded), "--oracle", str(csv)] + eps_args,
            capture_output=True, text=True)
        sys.stdout.write(proc.stdout)
        if proc.returncode != 0:
            sys.stdout.write(proc.stderr)
            die(f"bb_epsilon failed on {csv.name}")
        m = EPS_RX.search(proc.stdout)
        summary[label] = {"epsilon_pct": float(m.group(1)) if m else None,
                          "raw": proc.stdout}

        # oracle-only proxy epsilon: same csv, tacit emulated from entry_tsc
        # deltas; the gap to the measured value is the instrument term
        pproc = subprocess.run(
            [sys.executable, str(HERE / "bb_epsilon.py"),
             "--oracle", str(csv), "--proxy"],
            capture_output=True, text=True)
        sys.stdout.write(pproc.stdout)
        if pproc.returncode == 0:
            pm = re.search(r"epsilon_proxy\(BB\) = ([0-9.]+)%", pproc.stdout)
            summary[label]["epsilon_proxy_pct"] = \
                float(pm.group(1)) if pm else None
            summary[label]["proxy_raw"] = pproc.stdout
        else:
            sys.stdout.write(pproc.stderr)
    if summary:
        (bundle / "out/epsilon_summary.json").write_text(
            json.dumps(summary, indent=2) + "\n")
        print(f"\nanalyze_capture: wrote out/epsilon_summary.json")
    else:
        print("analyze_capture: no bboracle csvs in bundle, skipped epsilon")


if __name__ == "__main__":
    main()
