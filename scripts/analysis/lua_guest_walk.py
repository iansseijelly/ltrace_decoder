#!/usr/bin/env python3
"""Feasibility probe: reconstruct the guest (Lua) program counter from the
observed handler-visit sequence, by walking the protos' bytecode (luac -l)
alongside the trace. Reports ambiguities/mismatches, and emits a per-source-
line cycle attribution for the walked prefix — the first guest-level profile.

Usage: lua_guest_walk.py <luac_listing.txt> <dispatch_seq.csv> <optab.json>
"""
import json
import re
import sys
from array import array
from collections import defaultdict

CMP_OPS = {'EQ', 'LT', 'LE', 'EQK', 'EQI', 'LTI', 'LEI', 'GTI', 'GEI', 'TEST', 'TESTSET'}
MMB_OPS = {'MMBIN', 'MMBINI', 'MMBINK'}
RET_OPS = {'RETURN', 'RETURN0', 'RETURN1'}


def parse_listing(path):
    protos = []
    cur = None
    for line in open(path):
        m = re.match(r'^(main|function) <(.+):(\d+),(\d+)> \((\d+) instruction', line)
        if m:
            cur = dict(kind=m.group(1), src=f"{m.group(3)},{m.group(4)}",
                       linedefined=int(m.group(3)), insns={})
            protos.append(cur)
            continue
        m = re.match(r'^\t(\d+)\t\[(\d+)\]\t(\w+)\s*\t?([^;]*)(?:; (.*))?$', line.rstrip())
        if m and cur is not None:
            pc, ln, op = int(m.group(1)), int(m.group(2)), m.group(3)
            comment = m.group(5) or ''
            tgt = None
            tm = re.search(r'(?:exit )?to (\d+)', comment)
            if tm:
                tgt = int(tm.group(1))
            cur['insns'][pc] = (ln, op, tgt)
    return protos


class Speedscope:
    """Evented speedscope profile: proto frames > line frames > [C] leaves."""
    def __init__(self, path, names, limit):
        self.path, self.names, self.limit = path, names, limit
        self.frames = {}      # label -> idx
        self.events = []
        self.stack = []       # open frame idx stack
        self.line_open = []   # per proto-frame: open line frame idx or None
        self.start = None

    def fidx(self, label):
        if label not in self.frames:
            self.frames[label] = len(self.frames)
        return self.frames[label]

    def _ev(self, kind, idx, ts):
        self.events.append((kind, idx, ts))

    def open_proto(self, ts, pname):
        if self.start is None:
            self.start = ts
        i = self.fidx(pname)
        self._ev('O', i, ts); self.stack.append(i); self.line_open.append(None)

    def rotate_line(self, ts, pname, line):
        if not self.stack:
            return
        want = self.fidx(f"{pname}:{line}")
        cur = self.line_open[-1]
        if cur == want:
            return
        if cur is not None:
            self._ev('C', cur, ts)
        self._ev('O', want, ts)
        self.line_open[-1] = want

    def close_proto(self, ts):
        if self.line_open and self.line_open[-1] is not None:
            self._ev('C', self.line_open[-1], ts)
        if self.stack:
            self._ev('C', self.stack.pop(), ts)
            self.line_open.pop()

    def ccall(self, ts0, ts1, label):
        i = self.fidx(label)
        self._ev('O', i, ts0); self._ev('C', i, ts1)

    def full(self):
        return len(self.events) >= self.limit

    def finish(self, ts):
        while self.stack:
            self.close_proto(ts)
        frames = [None] * len(self.frames)
        for label, i in self.frames.items():
            frames[i] = label
        with open(self.path, 'w') as f:
            f.write('{"version":"0.0.1",'
                    '"$schema":"https://www.speedscope.app/file-format-schema.json",'
                    '"shared":{"frames":[')
            f.write(','.join('{"name":' + json.dumps(n) + '}' for n in frames))
            f.write(']},"profiles":[{"name":"lua guest","type":"evented","unit":"none",')
            f.write(f'"startValue":{self.start},"endValue":{ts},"events":[')
            f.write(','.join(f'{{"type":"{k}","frame":{i},"at":{t}}}'
                             for k, i, t in self.events))
            f.write(']}]}')


class Walker:
    def __init__(self, protos, seq_ops):
        self.protos = protos
        self.seq = seq_ops          # list of (ts, opname)
        self.i = 0                  # position in seq
        self.stack = []             # frames: [proto_idx, pc, call_pc]
        self.attr = defaultdict(int)  # (proto_idx, line) -> cycles
        self.dist = defaultdict(lambda: array('q'))  # (proto_idx, pc) -> intervals
        self.ambig = 0
        self.max_look = 0
        self.mismatch = None
        self.calls_resolved = 0
        self.ss = None
        self.pnames = []
        self.probe_pcs = set()   # {(proto,pc)} to dump per-instance
        self.probe_rows = []
        self.probe_cap = 300000

    def op_at(self, p, pc):
        ins = self.protos[p]['insns'].get(pc)
        return ins[1] if ins else None

    # candidate next (proto,pc) states after executing insn at (p,pc),
    # given nothing observed yet. Returns list of (kind, proto, pc) where
    # kind describes the choice; caller matches against observation.
    def successors(self, p, pc):
        ln, op, tgt = self.protos[p]['insns'][pc]
        nxt = []
        if op in RET_OPS:
            if len(self.stack) > 1:
                cp, _, caller_call_pc = self.stack[-2]
                nxt.append(('ret', cp, caller_call_pc + 1, None))
            else:
                nxt.append(('exit', None, None, None))
            return nxt
        if op == 'JMP':
            return [('jmp', p, tgt, None)]
        if op == 'FORLOOP':
            return [('loop', p, tgt, None), ('loopexit', p, pc + 1, None)]
        if op == 'FORPREP':
            return [('enter', p, pc + 1, None), ('skip', p, tgt, None)]
        if op in CMP_OPS:
            # Lua 5.4 consumes the following JMP inside the handler
            # (donextjump): on condition match the next DISPATCH is the
            # JMP's target; on mismatch it is pc+2.
            jt = self.protos[p]['insns'].get(pc + 1)
            tgt = jt[2] if jt and jt[1] == 'JMP' else None
            out = [('cmpskip', p, pc + 2, None)]
            if tgt is not None:
                out.append(('cmptake', p, tgt, None))
            return out
        if op in ('CALL', 'TAILCALL'):
            cands = [('call', q, 1, pc) for q in range(len(self.protos))]
            if op == 'CALL':
                cands.append(('ccall', p, pc + 1, None))  # C callee: continue
            return cands
        # default advance, skipping never-dispatched or conditionally-skipped slots
        q = pc + 1
        nop = self.op_at(p, q)
        if nop == 'EXTRAARG':
            return [('adv', p, q + 1, None)]
        if nop in MMB_OPS:
            return [('mmb', p, q, None), ('adv', p, q + 1, None)]
        if op == 'LFALSESKIP':
            return [('adv', p, pc + 2, None)]
        return [('adv', p, q, None)]

    def match(self, cands, i, depth=0):
        """Filter candidates by observation seq[i]; recurse on ties."""
        if i >= len(self.seq):
            return cands[:1]
        obs = self.seq[i][1]
        live = [c for c in cands if c[0] == 'exit' or self.op_at(c[1], c[2]) == obs]
        if not live:
            return live
        # at top level a unique immediate match suffices; inside tie-breaking
        # every chain (even singleton) must keep matching observations
        if depth == 0 and len(live) == 1:
            return live
        if depth >= 16:
            return live
        self.max_look = max(self.max_look, depth + 1)
        survivors = []
        for c in live:
            if c[0] == 'exit':
                survivors.append(c)
                continue
            nxt = self.successors_at(c[1], c[2], c[3])
            if self.match(nxt, i + 1, depth + 1):
                survivors.append(c)
        return survivors

    def successors_at(self, p, pc, call_pc):
        # successors() uses self.stack for returns; good enough for lookahead
        return self.successors(p, pc)

    def run(self, start_proto=0):
        ts0, op0 = self.seq[0]
        if self.op_at(start_proto, 1) != op0:
            self.mismatch = (0, f"first op {op0} != proto start {self.op_at(start_proto,1)}")
            return
        self.stack = [[start_proto, 1, 0]]
        if self.ss:
            self.ss.open_proto(ts0, self.pnames[start_proto])
        while self.i < len(self.seq) - 1:
            p, pc, _ = self.stack[-1]
            ln, op, _t = self.protos[p]['insns'][pc]
            if op != self.seq[self.i][1]:
                self.mismatch = (self.i, f"divergence: walker at proto{p}:{pc} ({op}) "
                                          f"but observed {self.seq[self.i][1]}")
                return
            dt = self.seq[self.i + 1][0] - self.seq[self.i][0]
            self.attr[(p, ln)] += dt
            self.dist[(p, pc)].append(dt)
            cands = self.successors(p, pc)
            if len(cands) > 1:
                pre = len(cands)
                cands = self.match(cands, self.i + 1)
                if pre > 1 and len(cands) > 1:
                    self.ambig += 1
            if not cands:
                self.mismatch = (self.i, f"no successor of {op} at proto{p}:{pc} "
                                          f"matches obs {self.seq[self.i+1][1]}")
                return
            kind, np, npc, ncall = cands[0]
            if kind == 'exit':
                self.mismatch = (self.i, "guest program exited")
                return
            ts_now, ts_next = self.seq[self.i][0], self.seq[self.i + 1][0]
            if (p, pc) in self.probe_pcs and len(self.probe_rows) < self.probe_cap:
                self.probe_rows.append((p, pc, self.i, dt, kind))
            if self.ss:
                self.ss.rotate_line(ts_now, self.pnames[p], ln)
                if kind == 'ccall':
                    self.ss.ccall(ts_now, ts_next, f"[C] call @{self.pnames[p]}:{ln}")
            if kind == 'call':
                self.calls_resolved += 1
                self.stack[-1][2] = ncall
                self.stack.append([np, npc, 0])
                if self.ss:
                    self.ss.open_proto(ts_next, self.pnames[np])
            elif kind == 'ret':
                self.stack.pop()
                self.stack[-1][1] = npc
                if self.ss:
                    self.ss.close_proto(ts_next)
            else:
                self.stack[-1][1] = npc
            self.i += 1
            if self.ss and self.ss.full():
                self.ss.finish(ts_next)
                print(f"speedscope: event budget reached at seq[{self.i}] "
                      f"(ts {ts_next}); profile written")
                self.ss = None


def main():
    listing, seqcsv, optabj = sys.argv[1:4]
    protos = parse_listing(listing)
    optab = json.load(open(optabj))
    seq = []
    with open(seqcsv) as f:
        next(f)
        for line in f:
            ts, h = line.rstrip().split(',')
            seq.append((int(ts), optab[h]))
    print(f"protos: {len(protos)} ({[len(p['insns']) for p in protos]} insns), "
          f"sequence: {len(seq):,} handler visits")

    src_lines = open('../lua-dispatch/bench/nbody.lua').readlines()
    names = []
    for k, pr in enumerate(protos):
        ld = pr.get('linedefined', 0)
        nm = 'main'
        if ld and ld - 1 < len(src_lines):
            mm = re.search(r'(?:local\s+)?function\s+([\w.:]+)', src_lines[ld - 1])
            if mm:
                nm = mm.group(1)
            else:
                nm = f'fn@{ld}'
        names.append(f"{nm} <nbody.lua:{ld}>" if k else "main <nbody.lua>")
    w = Walker(protos, seq)
    w.pnames = names
    if len(sys.argv) > 4 and sys.argv[4] != '-':
        w.ss = Speedscope(sys.argv[4], names, limit=2_000_000)
    w.run()
    if w.ss:
        w.ss.finish(w.seq[min(w.i, len(w.seq) - 1)][0])
    walked = w.i + 1
    print(f"walked: {walked:,}/{len(seq):,} ({walked/len(seq)*100:.2f}%)")
    print(f"ambiguities unresolved: {w.ambig}, max lookahead used: {w.max_look}, "
          f"lua-calls resolved: {w.calls_resolved}")
    if w.mismatch:
        i, why = w.mismatch
        print(f"stopped at seq[{i}]: {why}")
        ctx = ' '.join(op for _, op in seq[max(0,i-6):i+6])
        print(f"  context: ...{ctx}...")

    if len(sys.argv) > 5:
        import numpy as np
        with open(sys.argv[5], 'w') as f:
            f.write("proto,pc,op,line,count,total,min,p50,p90,p99,max,netvar\n")
            for (p_, pc_), arr in sorted(w.dist.items()):
                a = np.frombuffer(arr, dtype=np.int64)
                ln_, op_, _ = w.protos[p_]['insns'][pc_]
                q = np.percentile(a, [50, 90, 99])
                f.write(f"{p_},{pc_},{op_},{ln_},{len(a)},{a.sum()},{a.min()},"
                        f"{q[0]:.0f},{q[1]:.0f},{q[2]:.0f},{a.max()},"
                        f"{a.sum()-int(a.min())*len(a)}\n")
        print(f"per-bytecode distribution written to {sys.argv[5]} ({len(w.dist)} pcs)")
    total = sum(w.attr.values())
    print(f"\n== guest-line cycle attribution (walked prefix, {total:,} cycles) ==")
    src = open('../lua-dispatch/bench/nbody.lua').readlines()
    for (p, ln), cyc in sorted(w.attr.items(), key=lambda kv: -kv[1])[:12]:
        srcline = src[ln-1].strip() if ln-1 < len(src) else '?'
        print(f"  {cyc/total*100:5.1f}%  {cyc:12,} cyc  proto{p} line {ln:3d}: {srcline[:60]}")


if __name__ == '__main__':
    main()
