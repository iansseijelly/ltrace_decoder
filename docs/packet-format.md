# TACIT Packet Encoding Specification

**Status:** v1.0 documents the format as implemented today by
`generators/tacit` (encoders) and `software/tacit_decoder` (decoder).
Section 9 is a **proposed** extension (drop / resume) and is not implemented.

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
(defined, never emitted), `011` End. `100` Pause and `101` Resume are proposed
(§9).

If `c_header != CNA`, the byte is a **compressed packet** and bits `[7:2]` are
not a header at all but a 6-bit timestamp delta (§4.1).

## 4. Packet catalog

Payload fields, when present, always appear in this order:

```
header | prv | ctx | trap_addr-slot | target_addr | time
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
header(CNA, f=Sync, func3=type) | prv | ctx: varint | cfg-slot | target_addr: varint | time: varint
```

* `prv`: `from_priv` is always `0`; `to_priv` is the current privilege.
* `ctx`: current ASID, always present.
* `cfg-slot`: occupies the `trap_addr` position. For **Start** it is the
  7-bit `runtime_cfg`, emitted through the varint encoder so it is always
  exactly one byte `0x80 | cfg`:
  `cfg[1:0] = bp_mode`, `cfg[6:2] = log2(bp_entries / 64)`. For **End** the
  encoder writes `0`, i.e. the byte `0x80`; the decoder reads and discards one
  byte. (See §8 for a decoder bug in how Start's slot is parsed, and §9 for the
  proposed reuse of this slot.)
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
  its current PC to `sync_pc` and stops. **Any Sync after Start terminates
  decoding today**, regardless of type (`decoder.rs` breaks on `FSync`;
  `packet.rs` only forbids a second Start).

## 5. Timestamps

* Start (and the proposed Resume) carry **absolute** time. All other packets
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
stream  := SyncStart body SyncEnd
body    := ( compressed | TB | NT | IJ | UJ | Trap )*
```

(§9.2 proposes the v1.1 grammar with multiple sessions and pause/resume.)

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

1. **`bp_entries` is parsed incorrectly.** `read_first_packet` reads the cfg
   slot with `read_u8` and applies `BP_ENTRY_MASK = 0b1111_1100`, which
   includes bit 7 — the varint terminator, always `1`. The decoded table size
   is therefore `(32 + log2(n/64)) * 64`, e.g. `2304` for a 1024-entry
   hardware predictor. Since the decoder's index is `(pc>>1) % num_entries`,
   `BrPredict` decoding is mis-indexed relative to hardware. Harmless in
   `BrTarget` mode (the parallel encoder). Fix: mask with `0b0111_1100`, or
   decode the slot as a varint.
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
7. `SyncPeriodic` is defined on both sides but never emitted, and the decoder
   would treat it as End.
8. `f_header = 110` ("value") is reserved on the RTL side and panics in the
   decoder.

## 9. PROPOSED: pause / resume and multi-session traces (v1.1, not implemented)

Motivation: today, when the packet queues fill, the encoder asserts `stall`
and the core stops committing. The alternative is to stop *tracing* instead
of stopping the *core*. Because of §6, that is only decodable if the loss is
(a) at whole-packet granularity, before serialization, and (b) bracketed by
explicit synchronization packets. This section defines (b). It also defines
how several independently collected traces concatenate into one file.

Design rule: **every distinct semantic gets its own sync type.** Sync type
codes are plentiful (8) and cost nothing; what is scarce is payload slots
(each sync has exactly one spare, the `trap_addr` position). No packet's
meaning depends on a payload value or on what follows it.

### 9.1 Sync types

| `func3` | Name | Binds to | Spare slot | Decoder action on `target_addr` |
|---|---|---|---|---|
| `001` | Start | next retire group | `runtime_cfg` (1 byte) | set PC |
| `010` | Periodic (reserved) | next retire group | `0` (`0x80`) | walk to PC and verify |
| `011` | End | next retire group | `0` (`0x80`) | walk to PC and verify; **session terminal** |
| `100` | **Pause** (new) | the first *uncovered* instruction | `0` (`0x80`) | walk to PC and verify; enter gap |
| `101` | **Resume** (new) | next retire group | `dropped` (varint) | set PC; leave gap |

All five share the §4.5 layout: `header | prv | ctx | slot | target_addr | time`,
with `prv.from = 0`, `ctx` always present, `time` absolute.

### 9.2 Stream grammar

```
trace   := session+
session := Start body ( Pause Resume body )* End
body    := ( compressed | TB | NT | IJ | UJ | Trap | Periodic )*
```

Invariants the decoder enforces:

* Start appears only as the first packet of the file or immediately after End.
* Pause appears only inside a body. Resume appears only immediately after Pause.
* End appears only inside a body (never directly after Pause — see §9.5).
* After End, the next byte is either EOF or a Start.

A **session** is one enable→disable window. Timestamps are monotonic within a
session and **unrelated across sessions** (sessions may come from different
runs or different times; the time base may go backwards). Each Start re-reads
`runtime_cfg`, which may differ per session.

A **gap** is `[pause.time, resume.time)` inside one session: control flow is
unknown in the gap and exact outside it; the time base is continuous across
it.

### 9.3 Pause

```
header(CNA, f=Sync, func3=100) | prv | ctx: varint | 0x80 | target_addr: varint | time: varint
```

Header byte `0x96`.

* `target_addr = pause_pc >> 1` where `pause_pc` is the address of the first
  instruction whose packet was **not** encoded. Every instruction before it is
  covered exactly; it and everything after it until Resume are not.
* `time`: retire cycle of that instruction.
* `prv`, `ctx`: current at that instruction (redundant, kept for layout
  uniformity).
* Decoder: walk from the current PC to `pause_pc` with `step_bb_until` — it
  must land exactly (advisory in `BrPredict` mode, where the walk passes
  through predicted branches); `timestamp := time`; emit
  `Pause { pc, ts }`; enter gap state.

Because enqueue is atomic per retire group (§5), a lost group is lost whole;
`pause_pc` is therefore always the first packet-bearing slot of that group,
and always a control-flow instruction (or a trap point) reachable by a
straight-line walk from the previous event — which is what makes it
verifiable.

### 9.4 Resume

```
header(CNA, f=Sync, func3=101) | prv | ctx: varint | dropped: varint | target_addr: varint | time: varint
```

Header byte `0xB6`.

* Bound exactly like Start: the oldest instruction of the next retire group
  after the encoder decides to resume; `target_addr`, `time`, `prv`, `ctx` are
  absolute state at that point.
* `dropped`: number of packets discarded from the Pause (inclusive of the
  group that triggered it) to this Resume. Varint, may exceed one byte.
* Decoder: no walk; set `pc`, `prv`, `ctx`, `timestamp` from the packet;
  re-evaluate known/unknown context against the ASID list; reset the
  predictor model in `BrPredict`; emit
  `Resume { pc, prv, ctx, ts, dropped, pause_ts }`; leave gap state.

### 9.5 End and multi-session files

End is unchanged from v1.0: slot `0x80`, PC verified by walk, terminal for the
session. After End the decoder emits `SyncEnd` and then **continues reading**:
EOF ends the trace; a Start begins a new session; anything else is an error.

If tracing is disabled while the encoder is paused, the encoder emits
**Resume then End** on consecutive retire groups (a zero-length covered
segment) rather than End directly. This keeps End's walk-verification and zero
slot unconditional and keeps the grammar free of a `Pause End` production.

### 9.6 Decoder / receiver rules

* `packet.rs`: read the slot as a varint for every sync type (Start's byte is
  then masked with `0x7C`, fixing erratum 8.1); accept Pause/Resume/End
  mid-stream; a Start mid-stream is legal only right after End.
* `decoder.rs`: replace the `FSync → break` with the per-type actions above
  and a `gap`/`session` state machine enforcing §9.2.
* Events: existing `SyncStart`/`SyncEnd` now mean *session* boundaries (new
  time base); new `Pause`/`Resume` mean *gap* boundaries (same time base).
  Receivers close open basic blocks / frames at `Pause.ts` (as they already
  do at a Trap boundary) and re-seed at `Resume` without resetting session
  state (e.g. speedscope keeps one profile and draws the gap as a hole).
* End-of-run statistics: sessions, gaps, gap cycles, dropped packets, fraction
  of session time covered.

### 9.7 Encoder requirements (summary; RTL design is out of scope here)

* Drop only whole messages, upstream of the packet queues; never drop bytes.
* Reserve one queue entry in drop mode so that Pause can be enqueued in the
  very cycle the loss is detected. Pause binds to the *lost* group (the
  encoder's `ingress_1` stage) — unlike Start/Resume/End, which bind to the
  next group (`ingress_0`). This is a second sync binding point in the RTL.
* Count discarded packets from Pause to Resume; report in Resume's slot.
* Leave the drop state only when queue occupancy is below a low watermark
  (hysteresis), so Resume is guaranteed to enqueue.
* On Resume, `prev_time` is the sync cycle (as for any sync); the serial
  encoder additionally resets predictor state and the pending hit count.
* Disable while paused → Resume then End (§9.5).
* In drop mode the `stall` output to the core is constantly deasserted.

### 9.8 Open decisions

* **Software pause.** Should a driver-level "pause" ioctl exist that emits
  Pause/Resume (one session, gap semantics, `dropped = 0`) as opposed to
  disable/enable (End/Start, new session)? The encoder already knows the
  difference; it is a question of what the driver exposes.
* **Per-session decoder configuration.** Concatenated sessions may need
  different binaries / ASID lists. Out of scope for the packet format.
* **Retired-instruction count in the gap.** No spare slot; would widen the
  encoder's queue entries. Not in v1.1.
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
| Sync End | `76 ...` | same layout as Start; cfg slot `80` |
| *Proposed* Sync Pause | `96 prv ctx 80 varint(pause_pc>>1) varint(T)` | slot `80`; PC = first uncovered instruction |
| *Proposed* Sync Resume, 1234 packets dropped | `B6 prv ctx D2 89 addr time` | `varint(1234)`: `1234 & 7F = 52 → 52`, `1234 >> 7 = 9 → 89` |
