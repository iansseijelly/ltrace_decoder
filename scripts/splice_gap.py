"""Splice a synthetic Pause..Resume gap into a lossless TACIT trace.

Usage: splice_gap.py trace.bin events.txt N M out.bin
Drops packets N..M-1 (1-based packet index; packet 0 is Start; events.txt line k
is packet k). Emits Pause bound to packet N's instruction and Resume bound to
packet M's target."""
import re, sys

def varint_len(b, i):
    n = 0
    while True:
        n += 1
        if b[i + n - 1] & 0x80: return n

def packet_offsets(b):
    """Return byte offset of every packet (replicates packet.rs lengths)."""
    offs = []; i = 0
    while i < len(b):
      try:
        offs.append(i); h = b[i]; c = h & 3; i += 1
        if c != 2: continue                      # compressed: 1 byte
        f = (h >> 2) & 7; func3 = h >> 5
        if f in (0, 1, 3): i += varint_len(b, i)                   # time
        elif f == 2: i += varint_len(b, i); i += varint_len(b, i)  # UJ
        elif f == 4:                                              # trap
            prv = b[i]; i += 1
            if func3 == 4 and ((prv >> 3) & 7) == 0: i += varint_len(b, i)  # ctx
            for _ in range(3): i += varint_len(b, i)
        elif f == 5:                                              # sync
            i += 1
            for _ in range(4): i += varint_len(b, i)
        else: raise ValueError(f"reserved f_header at {offs[-1]}")
      except IndexError:
        print(f"note: truncated final packet at offset {offs[-1]}"); break
    return offs

def varint(v):
    out = []
    while True:
        g = v & 0x7f; v >>= 7
        if v == 0: out.append(g | 0x80); return bytes(out)
        out.append(g)

def sync(header, prv_to, ctx, trap_addr, pc, ts):
    return bytes([header, 0x80 | (prv_to << 3)]) + varint(ctx) + varint(trap_addr) + varint(pc >> 1) + varint(ts)

LINE = re.compile(r"\[timestamp: (\d+)\] (\w+): (0x[0-9a-f]+) -> (0x[0-9a-f]+)")
PRV = {"PrvUser": 0, "PrvSupervisor": 1, "PrvMachine": 3}

trace, events, N, M, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
b = open(trace, "rb").read()
lines = open(events).read().splitlines()
offs = packet_offsets(b)
assert len(offs) >= len(lines), (len(offs), len(lines))
start = re.match(r"\[timestamp: (\d+)\] SyncStart: (0x[0-9a-f]+) \((\w+) (\d+)\)", lines[0])
prv_to, ctx = PRV[start.group(3)], int(start.group(4))
ts_n, _, pc_n, _ = LINE.match(lines[N]).groups()
ts_m, _, _, pc_m = LINE.match(lines[M]).groups()
pause  = sync(0x96, prv_to, ctx, 0,     int(pc_n, 16), int(ts_n))
resume = sync(0xB6, prv_to, ctx, M - N, int(pc_m, 16), int(ts_m))
spliced = b[:offs[N]] + pause + resume + b[offs[M + 1]:]
open(out, "wb").write(spliced)
print(f"dropped packets {N}..{M} ({M-N+1} events incl. M's), pause@{ts_n} pc={pc_n}, resume@{ts_m} pc={pc_m}")
print("pause :", pause.hex(" ")); print("resume:", resume.hex(" "))
print(f"{len(b)} -> {len(spliced)} bytes")
