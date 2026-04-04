#!/bin/bash

# a list of workloads to process
WORKLOADS=(
  trace.perlbench_s.sqlite.db
  trace.mcf_s.sqlite.db
  trace.gcc_s.sqlite.db
  trace.x264_s.sqlite.db
  trace.omnetpp_s.sqlite.db
  trace.xalancbmk_s.sqlite.db
  trace.leela_s.sqlite.db
  trace.xz_s-cpu2006docs.sqlite.db
  trace.xz_s-cld.sqlite.db
  trace.exchange2_s.sqlite.db
)

NAMES=(
  "perlbench"
  "mcf"
  "gcc"
  "x264"
  "omnetpp"
  "xalancbmk"
  "leela"
  "xz-cpu2006docs"
  "xz-cld"
  "exchange2"
)

cd /scratch/iansseijelly/tacit-chipyard/software/tacit_decoder

for i in "${!WORKLOADS[@]}"; do
  workload=${WORKLOADS[i]}
  name=${NAMES[i]}
  echo "Processing $workload to $name"
  ./target/release/trace_db_tools bb-stats --db /scratch/iansseijelly/spec-db/$workload --outdir /scratch/iansseijelly/spec-path-profiles-vbb/$name --prv 0 --limit 10
done