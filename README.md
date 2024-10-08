# RISC-V L-Trace Decoder

## Running L-Trace Flow
```
spike --extlib libspikedevices.so --device trace_encoder_ctrl --trace [binary]
cargo run -- --binary [binary] --encoded-trace [/path/to/trace_l.bin] 
```

## What is L-Trace?
L-trace is the **lean trace format** that is simple, efficient, and profiling-friendly. 
Comparing to other trace formats that focus on compression efficiency, it tries to capture all basic-block exits. 
This includes taken and non-taken branches, inferable and uninferable jumps. 
It will also be extended to support traps and OS-level events. 
This provides rich information to profilers 

## Why L-Trace?
L-trace is motivated by the observation that both N-trace and E-trace significantly drops timestamps on certain control flow changes. 
N-trace BTM mode drops all inferable jump and non-taken branches. N-trace BHT and E-trace drops even more timestamps, only reports a timestamp after an extended period of time (when the counter is full or address report is necessary). 
This makes a profiler based on these trace formats no-better and may be even worse than sampling based profiler. 

Additionally, would it be a signficant cost (bandwidth-wise, perturbation-wise, and so on) to report every timestamp? Well, the hypothesis is, if we try to encode everything efficiently, combined with the fact that we report more frequently (so delta compression achives better efficiency), and the fact that repetitive packets can later be further compressed, the results might be desirable! 

## Why certain design decisions?
In this section, I profiled various ingress statistics and timing statistics. See my [notion page](https://iansseijelly.notion.site/L-Trace-A-Lean-Trace-Format-that-is-Simple-and-Profiler-Friendly-10c92828bf7480d38ce1e300fef6bdb3?pvs=74) for detailed profiling results!

## Ranting
An additional benefit of doing things in nice and simple (risc-y) ways is that the engineering is easier. 
If you're interested, it might be a fun reading to compare [ntrace-encoder-model](https://github.com/iansseijelly/riscv-isa-sim/blob/n_trace/riscv/trace_encoder_n.cc#L20) and [ltrace-encoder-model](https://github.com/iansseijelly/riscv-isa-sim/blob/n_trace/riscv/trace_encoder_n.cc#L20), and then compare the [ntrace-decoder](https://github.com/iansseijelly/ntrace-deocder) and [ltrace-decoder](https://github.com/iansseijelly/ltrace_decoder) (this repo). Hopefully you'll find out it's much a more pleasant reading (and implementation) for L-trace!