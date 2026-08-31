# TACIT Packet Encoding Specification

**Status:** v1.1. Sections 1–8 document the format as implemented by
`generators/tacit` (encoders) and `software/tacit_decoder` (decoder).
Section 9 (lossy mode: Pause / Resume, multi-session files) is **normative**
and implemented in the decoder; the encoder side is not implemented yet.

Where the RTL and the decoder disagree, or where the format has known warts,
this is called out explicitly in §8 (Errata) rather than papered over.

Source of truth, in priority order:

| Layer | File |
|---|---|
| Header/type constants (RTL) | `generators/tacit/src/main/scala/TacitConstants.scala` |
| Varint encoders (RTL) | `generators/tacit/src/main/scala/VarLenEncoder.scala` |
| Serial encoder (Rocket/Shuttle) | `generators/tacit/src/main/scala/TacitEncoder.scala` |
| Parallel encoder (BOOM) | `generators/tacit/src/main/scala/TacitParallelEncoder.scala` |
| Byte serialization order | `generators/tacit/src/main/scala/TracePacketizer.scala` |
| Decoder packet reader | `src/frontend/packet.rs`, `src/frontend/{c_header,f_header,sync_type,trap_type,runtime_cfg}.rs` |
| Decoder semantics | `src/frontend/decoder.rs` |

---

## 1. Model

TACIT is a **control-flow trace with a timestamp on every control-flow event**.
The encoder observes the core's retirement interface (`TraceCoreInterface`:
per-retire-slot `iaddr` + `itype`, plus hart-wide `priv`, `ctx`, `time`) and
emits one packet per retired instruction whose `itype` is not `ITNothing`:

| Retire `itype` | Packet |
|---|---|
| `ITBrTaken` | Taken branch (TB) |
| `ITBrNTaken` | Not-taken branch (NT) |
| `ITInJump` (`jal`) | Inferable jump (IJ) |
| `ITUnJump` (`jalr`) | Uninferable jump (UJ) |
| `ITException` / `ITInterrupt` / `ITReturn` | Trap |
| (encoder state machine) | Sync |

Everything between control-flow events is **not** in the stream: the decoder
reconstructs it by walking the program binary from the last known PC
(`step_bb`). Consequently the stream is a *chain*: the meaning of every packet
depends on all packets before it (see §6). There is no framing, no length
prefix, and no self-synchronizing marker. Absolute state appears only in Sync
packets.

`time` is the hart's cycle counter as presented on the core's CSR `time`
output (`csr.io.time`), sampled at retire.

## 2. Conventions

* The trace is a raw byte stream. On the DMA sink, wide words are filled
  little-endian (first byte in the least significant byte of the word); the
  FireSim bridge writes bytes in order to `tacitN.out`. Either way the file on
  disk is the byte stream with no header or padding.
* Bit numbering is LSB = bit 0. Bit-field notation `[a:b]` is inclusive.
* **varint**: a value is split into 7-bit groups, least-significant group
  first. Each byte carries one group in bits `[6:0]`. Bit 7 is **set on the
  last byte only**. The value `0` encodes as the single byte `0x80`. Maximum
  lengths: 64-bit fields → 10 bytes, 16-bit fields → 3 bytes. The RTL never
  emits leading zero groups (`VarLenMaskEncoder` sizes the field from the MSB).
  The decoder tolerates up to 10 bytes (`read_varint`).
* **Address fields are shifted right by one** before encoding (bit 0 of an
  instruction address is always 0 under RVC alignment). The decoder shifts left
  on receipt.

## 3. Header byte

Every packet starts with one header byte:

```
 bit:  7   6   5 | 4   3   2 | 1   0
       func3      | f_header  | c_header
```

| Field | Values |
|---|---|
| `c_header` `[1:0]` | `00` CTB (compressed taken branch), `01` CNT (compressed not-taken branch), `10` **CNA** (not compressed: this is a full packet), `11` CIJ (compressed inferable jump) |
| `f_header` `[4:2]` (only if `c_header == CNA`) | `000` TB, `001` NT, `010` UJ, `011` IJ, `100` Trap, `101` Sync, `110` reserved (was "value"), `111` reserved |
| `func3` `[7:5]` | Trap: trap type. Sync: sync type. Otherwise `000`. |

Trap type (`func3` when `f_header == Trap`): `001` exception, `010` interrupt,
`100` trap return (`sret`/`mret`). `000` and other values are invalid.

Sync type (`func3` when `f_header == Sync`): `001` Start, `010` Periodic
(defined, never emitted), `011` End, `100` Pause, `101` Resume (§9). `000`,
`110`, `111` are invalid; the decoder rejects them.

If `c_header != CNA`, the byte is a **compressed packet** and bits `[7:2]` are
not a header at all but a 6-bit timestamp delta (§4.1).

## 4. Packet catalog

Payload fields, when present, always appear in this order:

```
header | prv | ctx | trap_addr | target_addr | time
```

(`TracePacketizer` and `TraceMaskedPacketizer` both serialize in this order;
the decoder reads in this order.)

### 4.1 Compressed packet (1 byte)

```
 bit:  7 6 5 4 3 2 | 1 0
       delta_time   | c_header ∈ {CTB, CNT, CIJ}
```

Encodes a TB / NT / IJ event whose timestamp delta fits in 6 bits. There is no
other payload. Decoder: `timestamp = byte >> 2`, `f_header = from(c_header)`.

Eligibility: the event must be TB/NT/IJ **and** the delta must be small.
The parallel encoder compresses when `delta < 63`; the serial encoder when
`delta <= 63`. Decoders must accept `63` in a compressed packet.

### 4.2 Full TB / NT / IJ

```
header(CNA, f=TB|NT|IJ, func3=000) | time: varint
```

Used when the delta does not fit in 6 bits (or, in BP mode, for the hit-count
packet; §7).

### 4.3 Uninferable jump (UJ)

```
header(CNA, f=UJ) | target_addr: varint | time: varint
```

`target_addr = (jump_pc XOR target_pc) >> 1`, where `jump_pc` is the address
of the `jalr` itself and `target_pc` is the address of the next retired
instruction. XOR against the *jump* PC (not the fall-through) is what the
decoder assumes (`PC::compute_from_xored_target_addr` is called with `pc`
pointing at the resolving instruction).

### 4.4 Trap

```
header(CNA, f=Trap, func3=type) | prv | [ctx: varint] | trap_addr: varint | target_addr: varint | time: varint
```

* `prv` (1 byte): `[7:6] = 0b10` (fixed check pattern), `[5:3] = to_priv`,
  `[2:0] = from_priv`. Privilege codes: `0` U, `1` S, `2` H (unused), `3` M.
  (The RTL truncates the core's 4-bit priv to 3 bits.)
* `ctx` is present **iff** `type == return && to_priv == U`. It is the ASID
  (`satp.asid`) of the context being returned to.
* `trap_addr = trapping_pc >> 1`, **absolute** (not XORed). For an
  exception/interrupt this is the instruction that trapped (or the instruction
  before which the interrupt was taken); for a return it is the `sret`/`mret`.
* `target_addr = (trapping_pc XOR handler_or_return_pc) >> 1` — XORed against
  `trapping_pc`, same convention as UJ.
* Decoder behavior: walk from current PC to `trap_addr` (`step_bb_until`; must
  land exactly, else assert), then jump to the XOR-resolved target, switch
  `prv`, and if `ctx` is present switch context (and mark the context
  known/unknown against the configured ASID list).

### 4.5 Sync

```
header(CNA, f=Sync, func3=type) | prv | ctx: varint | trap_addr: varint | target_addr: varint | time: varint
```

* `prv`: `from_priv` is always `0`; `to_priv` is the current privilege.
* `ctx`: current ASID, always present.
* `trap_addr`: the same field position Trap packets use for the trapping PC.
  A sync has no trapping PC, so each sync type gives it its own meaning; there
  is no tag, the header byte alone decides. For **Start** it is the 7-bit
  `runtime_cfg`, emitted through the varint encoder so it is always exactly one
  byte `0x80 | cfg`: `cfg[1:0] = bp_mode`, `cfg[6:2] = log2(bp_entries / 64)`
  (so `bp_entries = 64 << cfg[6:2]`). For **End** and **Pause** it is `0`
  (byte `0x80`). For **Resume** it is the dropped-packet count (§9.4). The
  decoder reads it as a varint for every sync type.
* `target_addr = sync_pc >> 1`, **absolute**, encoded at full `iaddrWidth`
  (a sign-extended kernel VA costs up to 10 varint bytes).
* `time`: **absolute** cycle count.

**Sync point semantics.** The sync binds to the *next* retire group after the
encoder decides to sync: `sync_pc` is the oldest instruction of that group and
`time` its retire cycle. Every control-flow event of instructions at or after
`sync_pc` is in the stream; events of older instructions are not. Any messages
still in the encoder's ingress pipeline at that moment are discarded (they are
older than the sync point).

* **Start**: first packet of the stream, emitted on the first retire after
  enable. Sets PC, time, prv, ctx and the runtime configuration.
* **End**: emitted on the first retire after disable. The decoder walks from
  its current PC to `sync_pc`, emits `SyncEnd`, and then continues reading:
  EOF ends the trace, a Start opens a new session (§9.5).
* **Pause** / **Resume**: see §9.

## 5. Timestamps

* All Sync packets carry **absolute** time. All other packets
  carry a **delta** relative to the previous *enqueued* packet's retire cycle
  (`prev_time`, updated whenever a packet is enqueued; set to the sync cycle by
  a Sync).
* Multiple control-flow events can retire in one cycle on a superscalar core.
  The encoder emits one packet per event, in retire-slot order (oldest first).
  **Only the first packet of a cycle carries the delta; subsequent packets in
  the same cycle carry `0`** (compressed: `delta_time` bits `= 0`; full:
  `time = 0x80`). Decoders therefore accumulate `timestamp += delta` on every
  packet and get the same cycle for all events of that group.
* Timestamps are never negative and never reset except by a Sync.

## 6. Stream grammar and decoding rules

```
trace   := session+
session := Start body ( Pause Resume body )* End
body    := ( compressed | TB | NT | IJ | UJ | Trap )*
```

(§9 defines sessions and gaps; a lossless single-session trace is
`Start body End`.)

The decoder (`decode_trace`) maintains `(pc, timestamp, prv, ctx)`:

1. Read the Start packet (`read_first_packet`): it **must** be the first byte
   of the file (no magic, no version field). Initialize state from it.
2. For each subsequent packet:
   * `timestamp += packet.time` (or `= packet.time` for Start/Resume).
   * Walk the current binary from `pc` until the next control-flow
     instruction (`step_bb`; in `BrTarget` mode any branch/`jal`/`jalr` stops
     the walk). The instruction found **must** match the packet type (TB/NT →
     branch, IJ → direct jump, UJ → indirect jump); mismatch is a decode error.
   * Resolve: TB → `pc + imm`; NT → `pc + len`; IJ → `pc + imm`;
     UJ → `pc XOR (target_addr << 1)`; Trap → §4.4.
   * Emit the event with the accumulated timestamp.
3. Instruction maps are selected by `(prv, ctx)`. User-mode packets from an
   ASID not in the decoder's configured list are consumed (for timing) but not
   walked (`u_unknown_ctx`).

Because step (2) is a walk from the previous state, **losing or corrupting a
single byte anywhere desynchronizes every later packet until the next Sync**.
This is why lossy mode (§9) drops only whole packets, upstream of
serialization, and brackets every gap with explicit syncs.

## 7. Branch-prediction mode (serial `TacitEncoder` only)

`bp_mode` is a runtime control register value, reported in Start's `cfg`:

| `bp_mode` | Decoder `BrMode` | Encoder behavior |
|---|---|---|
| `0` | `BrTarget` | Every TB/NT/IJ/UJ/Trap gets a packet (§4). |
| `1` | `BrHistory` | **Serial encoder emits no TB/NT/IJ packets in this mode** (`packet_valid` requires `is_bt_mode` or `is_bp_mode`, neither holds). Effectively unsupported; do not use. |
| `2` | `BrPredict` | Encoder and decoder run identical 2-bit saturating-counter predictors indexed by `(pc >> 1) % bp_entries`, all initialized to weak-not-taken. Branch outcomes are reported only on mispredict. |

In `BrPredict`:

* A run of `n` correct predictions is flushed as a **TB packet whose time
  field is `n`** (hit count, not a delta). Compressed if `n <= 63`. Flushed
  when a mispredict occurs or when a non-branch event (IJ/UJ/trap) must be
  emitted. The decoder replays `n` predictions.
* A mispredict is an **NT packet with a normal time delta**. The decoder
  predicts, takes the opposite outcome, and updates its counter.
* IJ packets are not emitted in this mode (`is_bt_mode` false); the decoder
  follows direct jumps inline while walking.
* UJ and Trap packets are unchanged.

The parallel encoder always reports `bp_mode = 0` (`runtime_cfg = 0`) and
implements only `BrTarget`.

## 8. Errata / observations (current implementation)

1. **`bp_entries` was parsed incorrectly (fixed in v1.1).** The decoder read
   Start's `trap_addr` byte with `read_u8` and a mask that included bit 7 (the
   varint terminator), and then treated the field as a linear multiplier
   (`field * 64`) although the RTL writes `log2(n_entries / 64)`. A 1024-entry
   hardware predictor decoded as `2304`; the parallel encoder's `cfg = 0`
   decoded as `2048`. Since the decoder's index is `(pc>>1) % num_entries`,
   `BrPredict` decoding was mis-indexed relative to hardware (harmless in
   `BrTarget`). The decoder now reads the field as a varint and computes
   `64 << field`. Traces are unaffected; only the printed/used table size
   changes.
2. `bp_mode = 1` produces an unusable stream from the serial encoder (§7).
3. Compressed-packet threshold differs by one between encoders (§4.1).
4. The decoder assumes 40-bit virtual addresses (`ADDR_BITS = 40`) when
   sign-extending XOR results; the encoders XOR full `iaddrWidth` bits. This
   is consistent only because XOR of two same-sign-extended addresses cancels
   the upper bits.
5. Sync and Trap `trap_addr` fields carry full-width absolute addresses; a
   kernel VA `0xffffffff8xxxxxxx >> 1` costs 9–10 bytes. A base-relative or
   XOR-against-previous-PC encoding would save most of that.
6. There is no stream magic/version byte. Start's `cfg` is the only
   configuration carried in-band.
7. `SyncPeriodic` is defined on both sides but never emitted; the decoder
   rejects it as an error (v1.1; it used to be treated as End).
8. `f_header = 110` ("value") and `111` are reserved on the RTL side; the
   decoder returns a decode error for them (v1.1; it used to panic).

## 9. Lossy mode: Pause / Resume and multi-session traces (v1.1)

Motivation: in lossless mode, when the packet queues fill the encoder asserts
`stall` and the core stops committing. Lossy mode stops *tracing* instead of
stopping the *core*. Because of §6, that is only decodable if the loss is
(a) at whole-packet granularity, before serialization, and (b) bracketed by
explicit synchronization packets. This section defines (b); §9.7 lists what
(a) requires of the encoder. It also defines how several independently
collected traces concatenate into one file.

Design rule: **every distinct semantic gets its own sync type.** Sync type
codes are plentiful (8) and cost nothing; what is scarce is payload fields
(each sync has exactly one spare, the `trap_addr` position). No packet's
meaning depends on a payload value or on what follows it.

Status: decoder implemented (`packet.rs`, `decoder.rs`, all receivers);
encoder not yet implemented.

### 9.1 Sync types

| `func3` | Name | Header byte | Binds to | `trap_addr` | Decoder action on `target_addr` |
|---|---|---|---|---|---|
| `001` | Start | `0x36` | next retire group | `runtime_cfg` (1 byte) | set PC |
| `010` | Periodic (reserved) | `0x56` | — | — | error |
| `011` | End | `0x76` | next retire group | `0` (`0x80`) | walk to PC and verify; session terminal |
| `100` | **Pause** | `0x96` | the first *lost* message | `0` (`0x80`) | walk to PC, verify exact landing; enter gap |
| `101` | **Resume** | `0xB6` | next retire group | `dropped` (varint) | set PC; leave gap |

All share the §4.5 layout `header | prv | ctx | trap_addr | target_addr | time`,
with `prv.from = 0`, `ctx` always present, `target_addr` absolute (`>> 1`),
and `time` absolute.

### 9.2 Stream grammar

```
trace   := session+
session := Start body ( Pause Resume body )* End
body    := ( compressed | TB | NT | IJ | UJ | Trap )*
```

Invariants the decoder enforces (violations are decode errors, not panics):

* Start appears only as the first packet of the file or immediately after End.
* Pause appears only inside a body. Resume appears only immediately after
  Pause. Any non-sync packet inside a gap is an error.
* End appears only inside a body (never directly after Pause — see §9.5).
* After End, the next byte is either EOF or a Start.
* A `body` may be empty: `Pause Resume Pause Resume` is legal (two gaps with no
  covered event between them).

A **session** is one enable→disable window. Timestamps are monotonic within a
session and **unrelated across sessions** (sessions may come from different
runs; the time base may go backwards). Each Start carries `runtime_cfg`; the
decoder currently requires it to be identical across sessions (receivers are
configured once).

A **gap** is `[pause.time, resume.time)` inside one session: control flow is
unknown in the gap and exact outside it; the time base is continuous across
it.

### 9.3 Pause

```
header(CNA, f=Sync, func3=100) | prv | ctx: varint | 0x80 | target_addr: varint | time: varint
```

Header byte `0x96`.

* **Binding.** The retire group the encoder decides to drop (the encoder's
  `ingress_1` stage). Let `j` be the lowest slot in that group whose `itype`
  is not `ITNothing`. Then `target_addr = group(j).iaddr >> 1`,
  `time = group.time`, `prv`/`ctx` = the group's. `pause_pc` is therefore
  the address of the **first instruction whose packet was not encoded**, and
  is always a control-flow instruction (or a trap point). Slots `0..j-1` are
  plain instructions covered by the decoder's straight-line walk.
* **Coverage contract.** Every control-flow event of instructions before
  `pause_pc` is in the stream; `pause_pc` and everything after it until Resume
  are not. A lost trap-type message makes `pause_pc` the trapping (or
  interrupted-before) instruction, exactly what the Trap's `trap_addr` would
  have carried; the trap's target, privilege and context change are lost and
  re-established by Resume.
* **Time.** `time` is the retire cycle of the lost group, i.e. of `pause_pc`
  itself, so it is **at or after** the accumulated time of the last covered
  event (equal only when both retired in the same cycle). It is therefore the
  exact end time of the last covered basic block, which receivers may record;
  the decoder can only check monotonicity (`time >= accumulated`). The exact
  check at a Pause is the walk landing on `target_addr`. All syncs carry
  absolute time for uniformity; byte count does not affect queue pressure
  (queue entries are fixed-width bundles).
* **Emission.** Pause is enqueued in the very cycle the drop is decided, from
  the reserve the high watermark guarantees; it is never itself dropped. It is
  only emitted from the data state (never before Start has enqueued). A group
  carrying no message never triggers a Pause: nothing was lost.
* **Decoder.** If in a known context, `step_bb_until(pause_pc)` must land
  exactly (error in `BrTarget`; warning in `BrPredict`, where the walk passes
  through predicted branches). `time` must not be before the accumulated
  timestamp (error). `prv`/`ctx` must equal the decoder's (warning).
  `trap_addr` must be `0` (warning, then ignored — reserved). Then
  `timestamp := time`, emit `Pause { pause_pc }`, enter the gap.

### 9.4 Resume

```
header(CNA, f=Sync, func3=101) | prv | ctx: varint | dropped: varint | target_addr: varint | time: varint
```

Header byte `0xB6`.

* **Binding.** Exactly like Start: the oldest slot of the next retire group
  after the encoder decides to resume (`ingress_0.group(0)`); `target_addr`,
  `time`, `prv`, `ctx` are absolute state there. The oldest slot (not the
  first message slot) is used because the decoder needs a PC to walk *from*.
  The message sitting in `ingress_1` in that cycle is older than the bind
  point and is dropped and counted, as `sSync` already does for Start.
* **`dropped`**: number of **packets** (messages with `itype != ITNothing`),
  not groups or bytes, discarded from the Pause group inclusive to the Resume
  group exclusive. In `BrPredict` mode it counts branch events the encoder
  saw, not coalesced packets. 32-bit saturating in hardware;
  `0xFFFF_FFFF` means "at least this many".
* **Invariants.** `resume.time > pause.time`, strictly (the resume group is at
  least one pipeline advance later). `prev_time := resume.time` in the encoder;
  the next packet's delta is relative to Resume. The session's time base is
  continuous across the gap (unlike Start).
* **Decoder.** Error unless the previous packet was Pause or
  `time <= pause.time`. No walk; set `pc`, `prv`, `ctx`, `timestamp` from the
  packet; drop the decode cache; re-evaluate the known/unknown-context flag
  against the ASID list (with no ASID list configured every context is
  known, as for Start); in `BrPredict` reset the predictor table and pending
  hit count (hardware does the same); emit
  `Resume { pc, prv, ctx, dropped, pause_ts }`; leave the gap.

### 9.5 End and multi-session files

End is unchanged from v1.0: `trap_addr` `0x80`, PC verified by walk, terminal
for the session. After End the decoder emits `SyncEnd` and then **continues
reading**: EOF ends the trace; a Start begins a new session (state
re-initialized from it, `SyncStart` emitted again); anything else is an error.
A trace that ends without End (truncated file) decodes with a warning.

If tracing is disabled while the encoder is paused, the encoder emits
**Resume then End** on consecutive retire groups (a zero-length covered
segment) rather than End directly. This keeps End's walk-verification and zero
field unconditional and keeps the grammar free of a `Pause End` production.

### 9.6 Decoder / receiver behavior (implemented)

* `packet.rs`: one shared sync-body parser for all sync types; `trap_addr`
  read as a varint (this also fixed erratum 8.1). Reserved codes are errors.
* `decoder.rs`: a `Body / Gap / Ended` stream-state machine enforcing §9.2,
  plus end-of-run statistics: sessions, gaps, gap cycles, dropped packets,
  fraction of session time covered.
* Events: `SyncStart`/`SyncEnd` mean *session* boundaries (new time base);
  `Pause { pause_pc }` / `Resume { pc, prv, ctx, dropped, pause_ts }` mean
  *gap* boundaries (same time base).
* Stack unwinder: Pause closes every frame (return paths across a gap are
  unknowable); Resume adopts prv/ctx and reopens only the function containing
  the resume PC — callers cannot be recovered.
* Receivers: the block ending at `pause_pc` is exact and is recorded
  (`bb_stats`, `bb_pair_stats`); gap cycles are attributed to nothing
  (`prv_breakdown` reports them separately; `perfect_sampler` skips ticks in
  the gap; `iteration_breakdown` does not count frames closed by Pause as
  exits). `func_path` drops an invocation cut by a gap; `path_profile` drops
  the in-flight path. `speedscope` draws a synthetic `[trace gap]` frame
  across the gap in one profile. `sqlite` records `PAUSE`/`RESUME` rows.
  Emulators flush staged events at Pause (exact cycle, like a trap) and
  re-establish their time base at Resume (like a sync); error analyzers do
  not count the gap.
* `scripts/splice_gap.py` cuts a packet range out of a lossless trace and
  splices in a correctly bound Pause/Resume, for testing.

### 9.7 Encoder requirements (not yet implemented)

* Drop only whole messages, upstream of the packet queues; never drop bytes.
* Lossy mode is a control-register bit. In lossy mode the `stall` output to
  the core is constantly deasserted; the existing stall condition becomes the
  **high watermark** that triggers a Pause. Both existing stall rules
  (`bufferDepth - coreStages` and the SRAM reserve) leave more than the one
  free entry Pause needs.
* Pause binds to the *lost* group (`ingress_1`) — unlike Start/Resume/End,
  which bind to the next group (`ingress_0`). This is a second sync binding
  point in the RTL; its PC is the first message slot, not slot 0.
* Count discarded packets from Pause to Resume; report in Resume's
  `trap_addr`.
* Leave the drop state only when queue occupancy is below a **low watermark**
  (hysteresis), so Resume is guaranteed to enqueue.
* On Resume, `prev_time` is the sync cycle (as for any sync); in `BrPredict`
  mode the serial encoder additionally resets the predictor table and the
  pending hit count (or lossy mode is restricted to `bp_mode = 0`).
* Disable while paused → Resume then End (§9.5).
* Expose dropped-packet and pause counters to software.

### 9.8 Open decisions

* **Software pause.** Should a driver-level "pause" ioctl exist that emits
  Pause/Resume (one session, gap semantics, `dropped = 0`) as opposed to
  disable/enable (End/Start, new session)?
* **Per-session decoder configuration.** Concatenated sessions may need
  different binaries / ASID lists / `runtime_cfg`. Out of scope for the
  packet format; the decoder currently rejects a `runtime_cfg` change.
* **Retired-instruction count in the gap.** Every Resume payload field is
  used; would need a new field or a widened Resume. Not in v1.1.
* **Pause `trap_addr`.** Reserved (`0`). A pause-reason code is the obvious
  future use.
* **Periodic.** The Pause/Resume machinery makes lossless periodic resync
  (seekable traces) cheap to add; not in v1.1.

## 10. Worked examples

All values hex. `varint(n)` shown expanded.

| Event | Bytes | Notes |
|---|---|---|
| Taken branch, Δt = 5 | `14` | `(5 << 2) \| 00` |
| Not-taken branch, Δt = 0 (same cycle as previous) | `01` | compressed, delta 0 |
| Inferable jump, Δt = 63 | `FF` | `(63 << 2) \| 11`; legal from the serial encoder only |
| Not-taken branch, Δt = 100 | `06 E4` | full NT; `varint(100) = E4` |
| Taken branch, Δt = 200 | `02 48 81` | `varint(200)`: `200 & 7F = 48`, `200 >> 7 = 1 → 81` |
| `jalr` at `0x8000_1000` → `0x8000_2000`, Δt = 3 | `0A 00 B0 83` | xor `= 0x3000`, `>>1 = 0x1800`, `varint = 00 B0` |
| Exception in U at pc `P`, handler `H`, Δt | `32 88 varint(P>>1) varint((P^H)>>1) varint(Δt)` | `func3=001`; prv `10 001 000` = `88` (to S, from U) |
| `sret` S→U, ASID 117, from `R`, to `T`, Δt | `92 81 F5 varint(R>>1) varint((R^T)>>1) varint(Δt)` | prv `10 000 001` = `81`; ctx `varint(117) = F5` |
| Sync Start in S, ASID 0, parallel encoder, pc `P`, time `T` | `36 88 80 80 varint(P>>1) varint(T)` | ctx `80`; cfg `80` (`bp_mode 0`) |
| Sync End | `76 ...` | same layout as Start; `trap_addr` `80` |
| Sync Pause, M-mode, ASID 0, `pause_pc = 0x10AB4`, `T = 1 000 000` | `96 98 80 80 5A 0A 82 40 04 BD` | prv `10 011 000` = `98`; `trap_addr` `80`; `0x855A → 5A 0A 82`; `0xF4240 → 40 04 BD` |
| Sync Resume, U-mode, ASID 117, 1234 dropped, `pc = 0x10C00`, `T = 1 004 096` | `B6 80 F5 52 89 00 0C 82 40 24 BD` | `varint(1234)`: `1234 & 7F = 52`, `1234 >> 7 = 9 → 89`; `0x8600 → 00 0C 82` |
| Disable while paused | `B6 … 76 …` | Resume bound to group *n*, End to group *n+1* |
