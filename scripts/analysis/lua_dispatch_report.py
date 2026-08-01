#!/usr/bin/env python3
"""Baseline report for the Lua interpreter-dispatch case study.

Inputs: bb_pair_stats + dispatch_stats CSVs for the four 5s captures,
the dispatch-site list (jr PCs in luaV_execute) and the opcode table.
Run from the tacit_decoder directory.
"""
import bisect
import json
import math

import pandas as pd

SP = 'configs/lua'
OPTAB = json.load(open(f'{SP}/lua_optab.json'))
SITES = set('0x' + l.strip() for l in open(f'{SP}/jr_sites.txt'))
SITE_NAMES = {
    '0x1f966': 'shared head A (9 handler tails)',
    '0x20346': 'shared head B (MUL/MODK chain)',
    '0x1faaa': 'surviving private (TFORLOOP region)',
    '0x1f92c': 'function-entry dispatch',
    '0x20b3a': 'surviving private (monomorphic in nbody)',
}
FLOOR = 3  # predicted-dispatch floor, cycles

BENCH = {  # name -> (pair csv, dispatch csv, window cycles, description)
    'nbody':       ('trace.lua-nbody.bb_pair_stats.csv',       'trace.lua-nbody.dispatch_stats.csv',       4.886e9, 'float/field-access physics loop'),
    'fannkuch':    ('trace.lua-fannkuch2.bb_pair_stats.csv',   'trace.lua-fannkuch2.dispatch_stats.csv',   5.296e9, 'integer permutation/swap kernel'),
    'binarytrees': ('trace.lua-binarytrees.bb_pair_stats.csv', 'trace.lua-binarytrees.dispatch_stats.csv', 3.947e9, 'allocation/GC heavy'),
    'sieve':       ('trace.lua-sieve.bb_pair_stats.csv',       'trace.lua-sieve.dispatch_stats.csv',       4.925e9, 'branchy array walk'),
}


def load_pairs(path):
    df = pd.read_csv(path, skipinitialspace=True)
    for c in ('prev_bb', 'bb'):
        df[c] = df[c].str.strip()
    df['prev_end'] = df['prev_bb'].str.split('-').str[1]
    return df


def site_table(pairs):
    d = pairs[pairs['prev_end'].isin(SITES)].copy()
    d['sum'] = d['count'] * d['mean']
    rows = []
    for s, g in d.groupby('prev_end'):
        n = g['count'].sum()
        if n < 1000:
            continue
        min_site = g['min'].min()
        netvar = g['sum'].sum() - n * min_site
        within = (g['sum'] - g['count'] * g['min']).sum()
        p = g['count'] / n
        rows.append(dict(site=s, N=n, tgts=(g['count'] >= 1000).sum(),
                         H=-(p * p.map(math.log2)).sum(),
                         top=p.max(), netvar=netvar, within=within))
    return pd.DataFrame(rows).sort_values('netvar', ascending=False)


def load_bigram(path):
    d = pd.read_csv(path, skipinitialspace=True)
    d['from'] = d['from_handler'].map(OPTAB)
    d['to'] = d['to_handler'].map(OPTAB)
    d['sum'] = d['count'] * d['mean']
    # collapse alias nodes: handlers whose entries cost ~0 (cross-jumped labels,
    # e.g. EXTRAARG == some handler's merged vmbreak). Reroute X->A->Y to X->Y
    # proportionally, keeping A->Y's timing (the real entry cost of Y).
    inc = d.groupby('to').apply(lambda g: (g['sum'].sum()) / max(g['count'].sum(), 1),
                                include_groups=False)
    aliases = [t for t, c in inc.items() if c < 1.0 and t in set(d['from'])]
    for a in aliases:
        into = d[d['to'] == a]
        outof = d[d['from'] == a]
        n_a = into['count'].sum()
        if n_a == 0 or outof['count'].sum() == 0:
            continue
        new = []
        for _, o in outof.iterrows():
            for _, i in into.iterrows():
                r = o.copy()
                r['from'] = i['from']
                r['count'] = o['count'] * i['count'] / n_a
                r['sum'] = o['sum'] * i['count'] / n_a
                new.append(r)
        d = d[(d['to'] != a) & (d['from'] != a)]
        d = pd.concat([d, pd.DataFrame(new)], ignore_index=True)
    d = d.groupby(['from', 'to'], as_index=False).agg(
        count=('count', 'sum'), sum=('sum', 'sum'),
        min=('min', 'min'), p50=('p50', 'max'), p90=('p90', 'max'))
    return d, aliases


def predict(big):
    """Modal-hit model: post-fix, each handler's private site predicts its
    modal successor; that transition's entry cost drops to its observed min."""
    rec = 0.0
    n_tot = big['count'].sum()
    pred_share = 0.0
    for h, g in big.groupby('from'):
        n_h = g['count'].sum()
        modal = g.loc[g['count'].idxmax()]
        pred_share += modal['count']
        rec += modal['count'] * max(modal['p50'] - max(modal['min'], FLOOR), 0)
    return rec, pred_share / n_tot if n_tot else 0


L = []
L.append("# Lua interpreter dispatch — baseline case-study report\n")
L.append("Platform: FireSim `tacit_mega_boom_v3` (4-wide MegaBoom + tacit, the case-study "
         "bitstream). Workload: static Lua 5.4.7 (`-O2 -g -static`), four benchmarks, "
         "~5 s traced guest window each (tracing enabled only around the lua invocation). "
         "Decode: per-BB timestamps; `bb_pair_stats` at the 15 `jr` dispatch sites of "
         "`luaV_execute`; `dispatch_stats` for handler→handler bigrams (entry-block latency "
         "conditioned on previous handler).\n")

L.append("## 1. Headline: the compiler un-threaded the interpreter, and it costs 8–29% of runtime\n")
L.append("Lua 5.4 auto-enables computed-goto dispatch under GCC (`lvm.c:38-42` + `ljumptab.h`): "
         "every one of the 83 handlers should end with its own private "
         "`vmfetch(); goto *disptab[op]` — 83+ independently predictable indirect branches. "
         "In the shipped `-O2` binary, GCC's **cross-jumping** merged those identical tails "
         "back into a handful of shared dispatch blocks: only **15 `jr` sites** survive, and "
         "two shared heads carry most of the traffic. The BTB then sees one branch juggling "
         "the whole opcode stream instead of per-opcode contexts, and the mispredict tax is "
         "measurable per site, per transition, per instance.\n")

cap = []
cap.append("| benchmark | window | dispatches | dispatch rate | site netvar (cycles) | % of window |")
cap.append("|---|---|---|---|---|---|")
summary = {}
for name, (pcsv, dcsv, cyc, desc) in BENCH.items():
    pairs = load_pairs(pcsv)
    st = site_table(pairs)
    big, aliases = load_bigram(dcsv)
    nv = st['netvar'].sum()
    N = st['N'].sum()
    rec, pshare = predict(big)
    summary[name] = dict(st=st, big=big, aliases=aliases, cyc=cyc, nv=nv, N=N,
                         rec=rec, pshare=pshare, desc=desc)
    cap.append(f"| {name} | {cyc/1e9:.2f} Gcyc | {N:,} | 1 per {cyc/N:.0f} cyc | "
               f"{nv:,.0f} | **{nv/cyc*100:.1f}%** |")
L.append('\n'.join(cap))
L.append("\nSite net variation = Σ(instance − site-min) over all dispatch-target instances at "
         f"the site: the upper bound on cycles recoverable if every dispatch at that site "
         f"predicted perfectly.\n")

L.append("## 2. Where the tax lives (per-site tables)\n")
for name, s in summary.items():
    L.append(f"\n### {name} — {s['desc']}\n")
    L.append("| site | role | N | targets | entropy | top-target | netvar | % window | within-row |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for _, r in s['st'].iterrows():
        L.append(f"| `{r['site']}` | {SITE_NAMES.get(r['site'],'private')} | {r['N']:,} | "
                 f"{r['tgts']} | {r['H']:.2f} b | {r['top']*100:.0f}% | {r['netvar']:,.0f} | "
                 f"{r['netvar']/s['cyc']*100:.1f}% | {r['within']/max(r['netvar'],1)*100:.0f}% |")
L.append("\n`within-row` = share of the site's netvar occurring within a single (site, target) "
         "pair — i.e., the same transition sometimes predicted (≈3 cyc) and sometimes not "
         "(≈14-18 cyc). High values mean the variation is interleaving-driven prediction, not "
         "expensive targets. The monomorphic private site (`0x20b3a`, entropy 0) has ~zero "
         "netvar: a private single-target dispatch is free — the in-binary control case.\n")

L.append("## 3. The mechanism, in one table\n")
L.append("GETFIELD's entry block, by which dispatch site reached it (nbody):\n")
L.append("| via | n | min | p50 | p90 | p99 |")
L.append("|---|---|---|---|---|---|")
gp = load_pairs(BENCH['nbody'][0])
g = gp[gp['bb'].str.startswith('0x20274-')]
for _, r in g.nlargest(3, 'count').iterrows():
    role = SITE_NAMES.get(r['prev_end'], r['prev_end'])
    L.append(f"| {role} | {r['count']:,} | {r['min']:.0f} | {r['p50']:.0f} | {r['p90']:.0f} | {r['p99']:.0f} |")
L.append("\nSame instructions, same target handler: ~5 cycles through a private site "
         "(p50=p99 — always predicted), ~14-15 through the shared heads. The merge is the "
         "mispredict.\n")

L.append("## 4. Handler→handler structure (bigram highlights)\n")
L.append("Per-handler conditional successor distributions (alias labels collapsed — "
         "cross-jumping made e.g. `disptab[EXTRAARG]` coincide with SETFIELD's merged tail; "
         "those 0-cycle label nodes are rerouted proportionally):\n")
for name, s in summary.items():
    big = s['big']
    top = big.nlargest(5, 'count')
    rows = ', '.join(f"{r['from']}→{r['to']} (n={r['count']/1e6:.1f}M, p50 {r['p50']:.0f})"
                     for _, r in top.iterrows())
    L.append(f"- **{name}**: {rows}")
L.append("")

L.append("## 5. The concrete fix, and predicted recovery\n")
L.append("**Recompile `lvm.c` with `-fno-crossjumping`.** Verified on this toolchain: the flag "
         "restores **157** dispatch `jr` sites in `luaV_execute` (one per handler exit path; "
         "build already prepared in `software/lua-dispatch/lua-riscv-ncj/`). Each handler then "
         "owns its dispatch branch, so prediction conditions on the current opcode — exactly "
         "the contexts the bigram table measures.\n")
L.append("Predicted recovery under a conservative **modal-hit model** — after the fix, each "
         "handler's private site correctly predicts only its single most frequent successor "
         "(that transition's entry cost drops from its observed p50 to its observed min); all "
         "non-modal transitions still miss:\n")
pt = []
pt.append("| benchmark | modal share of dispatches | predicted recovery | upper bound (site netvar) |")
pt.append("|---|---|---|---|")
for name, s in summary.items():
    pt.append(f"| {name} | {s['pshare']*100:.0f}% | **{s['rec']/s['cyc']*100:.1f}%** of window | "
              f"{s['nv']/s['cyc']*100:.1f}% |")
L.append('\n'.join(pt))
L.append("\nValidation plan (the Req-6 loop): capture the same four benchmarks with the "
         "`-fno-crossjumping` binary, decode with the same receivers, and compare per-site: "
         "(a) end-to-end speedup vs the predicted recovery; (b) the site tables — the two "
         "shared heads should disappear, replaced by ~157 sites whose per-site top-target "
         "shares match the bigram's conditional distributions. Per-site predicted-vs-measured "
         "is a much stronger validation than a single end-to-end number.\n")

L.append("## 6. Why only this profile could produce this report\n")
L.append("- The diagnosis lives at 3-vs-14-cycle granularity on single basic blocks — below "
         "the resolution floor of sparse-timestamp tracing (our emulation study: ~100% BB-level "
         "error, pair signal ρ≈0.35) and below any practical sampling rate; instrumentation at "
         "the dispatch site costs more than the dispatch.\n"
         "- It needs *per-instance, predecessor-conditioned* timing (the same transition is "
         "bimodal 3/15 by interleaving) — counts or averages cannot separate the merged heads "
         "from the private sites.\n"
         "- The un-threading is invisible in source and in any function-level profile: all of "
         "it is inside `luaV_execute`.\n")

L.append("## Appendix: operational notes\n")
L.append("- fannkuch was recaptured with in-lua repetition after the original window caught "
         "busybox `sh`'s SIGCHLD sigreturn executing through the *mapped-but-hidden* vdso "
         "(`vdso=0` suppresses only the auxv entry; the sigreturn trampoline still uses "
         "`mm->context.vdso`). Options recorded: route sigreturn via the stack trampoline when "
         "vdso is disabled (~5-line kernel patch), log per-process vdso base + map vdso.so in "
         "the decoder, and/or decoder skip-unmapped-region robustness.\n"
         "- Each `./lua` in a shell loop gets a fresh ASID; the per-job `trace-run` drain log "
         "is the authoritative asid→binary map.\n"
         "- Traces auto-collect via per-job `firesim.simulation_outputs` (parent-level is "
         "silently ignored when jobs exist).\n")

open('lua_dispatch_baseline_report.md', 'w').write('\n'.join(L))
print(f"report written ({len(L)} blocks)")
for name, s in summary.items():
    print(f"  {name}: tax {s['nv']/s['cyc']*100:.1f}%, predicted recovery {s['rec']/s['cyc']*100:.1f}%, modal share {s['pshare']*100:.0f}%, aliases collapsed: {s['aliases']}")
