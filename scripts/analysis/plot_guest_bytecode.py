#!/usr/bin/env python3
"""Timing portrait of a guest (Lua) function: per-bytecode-instruction
latency distributions in program order, banded by source line."""
import pandas as pd
import matplotlib.pyplot as plt

S1, S1_LIGHT = "#2a78d6", "#9ec5f4"
INK, INK2, GRID, BAND = "#1a1a19", "#6b6a63", "#e5e4df", "#f2f1ec"
YCAP = 60

d = pd.read_csv('lua_nbody_guest_bytecode.csv')
adv = d[(d['proto'] == 2) & (d['count'] > 1000)].sort_values('pc').reset_index(drop=True)
src = open('../lua-dispatch/bench/nbody.lua').readlines()

fig, ax = plt.subplots(figsize=(12.5, 4.6))
# alternating source-line bands
prev_line, band_start, shade = None, 0, False
bands = []
for i, r in adv.iterrows():
    if r['line'] != prev_line:
        if prev_line is not None:
            bands.append((band_start, i - 0.5, prev_line, shade))
            shade = not shade
        band_start, prev_line = i - 0.5, r['line']
bands.append((band_start, len(adv) - 0.5, prev_line, shade))
for x0, x1, ln, sh in bands:
    if sh:
        ax.axvspan(x0, x1, color=BAND, zorder=0)
    ax.text((x0 + x1) / 2, YCAP * 0.97, f"L{ln}", ha='center', va='top',
            fontsize=8, color=INK2)

for i, r in adv.iterrows():
    p90 = min(r['p90'], YCAP)
    ax.plot([i, i], [r['min'], p90], color=S1_LIGHT, linewidth=3.2,
            solid_capstyle='butt', zorder=2)
    if r['p50'] <= YCAP:
        ax.plot(i, r['p50'], 'o', color=S1, markersize=4.5, zorder=3)
    if r['p90'] > YCAP or r['p50'] > YCAP:
        ax.annotate(f"{r['op']} p50 {r['p50']:.0f}", (i, YCAP * 0.82),
                    fontsize=7.5, color=INK, rotation=90, ha='center', va='top')
        ax.plot(i, YCAP * 0.9, '^', color=S1, markersize=5, zorder=3)

step = max(1, len(adv) // 30)
ax.set_xticks(range(0, len(adv), step))
ax.set_xticklabels(adv['pc'][::step], fontsize=7.5)
ax.set_xlabel("bytecode pc of advance() — program order", color=INK2)
ax.set_ylabel("cycles per instance", color=INK2)
ax.set_ylim(0, YCAP)
ax.set_xlim(-1, len(adv))
for side in ('top', 'right'):
    ax.spines[side].set_visible(False)
for side in ('left', 'bottom'):
    ax.spines[side].set_color(GRID)
ax.tick_params(colors=INK2)
ax.grid(True, axis='y', color=GRID, linewidth=0.6)
ax.set_axisbelow(True)
ax.set_title("Per-bytecode timing distributions of Lua advance() — 625k instances each\n"
             "(bar min–p90, dot p50; reconstructed from hardware trace, zero guest instrumentation)",
             fontsize=11, color=INK, loc='left')
fig.tight_layout()
fig.savefig('lua_advance_bytecode_portrait.png', dpi=200, facecolor='white',
            bbox_inches='tight')
print("wrote lua_advance_bytecode_portrait.png")
