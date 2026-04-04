#!/bin/bash
benchmarks=(
  "600_perlbench"
  "602_gcc"
  "605_mcf"
  "620_omnetpp"
  "623_xalancbmk"
  "625_x264"
  "641_leela"
  "648_exchange2"
  "657_xz_cld"
  "657_xz_cpu2006docs"
)

mkdir -p trace_errors

echo $(pwd)

for benchmark in "${benchmarks[@]}"; do
  echo "Decoding $benchmark"
  ./target/release/tacit-decoder --config configs/spec-emulation/linux_$benchmark.json > trace_errors/$benchmark.txt 2>&1
done