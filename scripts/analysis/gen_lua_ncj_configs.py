#!/usr/bin/env python3
"""Generate decode configs for the ncj (-fno-crossjumping) validation captures.
Usage: gen_lua_ncj_configs.py <results-workload-dir>"""
import json
import sys

R = sys.argv[1]
handlers = sorted(json.load(open('configs/lua/lua_optab_ncj.json')).keys(),
                  key=lambda a: int(a, 16))
LUA_BIN = "../firemarshal/example-workloads/lua-dispatch-ncj/overlay/root/lua-dispatch/lua"
TR_BIN = "../firemarshal/example-workloads/lua-dispatch-ncj/overlay/root/lua-dispatch/trace-run"

for name in ['nbody', 'fannkuch', 'binarytrees', 'sieve']:
    job = f"lua-dispatch-ncj-ncj-{name}-traced"
    img = f"../firemarshal/images/firechip/{job}"
    cfg = {
        "encoded_trace": f"{R}/{job}/tacit0.out",
        "user_binaries": [
            {"binary": LUA_BIN, "asids": [107]},
            {"binary": TR_BIN, "asids": [106]},
        ],
        "machine_binary": f"{img}/{job}-bin",
        "kernel_binary": f"{img}/{job}-bin-dwarf",
        "kernel_jump_label_patch_log": f"{R}/lua-dispatch-ncj-ncj-chores/jump_label_patch_map.txt",
        "driver_binary_entry_tuples": [
            ["../firemarshal/boards/firechip/drivers/tacit-driver/tacit.o", "0xffffffff01b08000"],
            ["../firemarshal/boards/firechip/drivers/iceblk-driver/iceblk.o", "0xffffffff01b88000"],
        ],
        "receivers": {
            "prv_breakdown": {"enabled": True},
            "bb_stats": {"enabled": True, "path": f"trace.lua-ncj-{name}.bb_stats.csv"},
            "bb_pair_stats": {"enabled": True, "path": f"trace.lua-ncj-{name}.bb_pair_stats.csv"},
            "dispatch_stats": {"enabled": True, "path": f"trace.lua-ncj-{name}.dispatch_stats.csv",
                               "handlers": handlers},
        },
    }
    json.dump(cfg, open(f'configs/lua/lua_ncj_{name}.json', 'w'), indent=1)
print("4 ncj configs written")
