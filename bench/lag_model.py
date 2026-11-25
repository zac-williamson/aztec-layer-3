#!/usr/bin/env python3
"""F0->F1 lag model for a batch (SPEC.md §14, P2.28).

Inputs are measured on zac-box (see bench/results/): per-circuit proving times on one 16-thread
prover, and gate counts from bb. Outputs, as Markdown tables:

1. the constraint budget of a 1,024-action batch, merge tree versus Chonk runs;
2. the critical path after a batch closes, by run size, with enough provers;
3. the speedup S of the core prover needed for an F1 lag under 5 minutes at a sustained rate,
   for a pool of N provers.

Usage: python3 bench/lag_model.py bench/results/model-inputs.json
"""
import json
import math
import sys

P = json.load(open(sys.argv[1]))
G = P["gates"]  # circuit -> bb circuit_size
T = P["seconds"]  # circuit or step -> seconds on one 16-thread prover
MIX = P["mix_1024"]  # segments of a 1,024-action batch, by kind (measured batch, scaled)
APPS_PER_KERNEL = 5
MAX_APPS = 45
TARGET = 300.0


def merge_levels(leaves: int) -> int:
    """Merge levels between `leaves` nodes and the root's two children."""
    return max(0, math.ceil(math.log2(leaves)) - 1) if leaves > 2 else 0


def chonk_run_seconds(apps: dict) -> float:
    """One run's accumulation (apps, kernels, padding), tail, hiding and decider."""
    n = sum(apps.values())
    groups = math.ceil(n / APPS_PER_KERNEL)
    pads = groups * APPS_PER_KERNEL - n
    acc = sum(T[f"acc_{k}"] * v for k, v in apps.items())
    return acc + pads * T["acc_pad"] + T["acc_bk_init"] + (groups - 1) * T["acc_bk_inner"] + T["acc_tail_hiding"] + T["decider"]


def split(mix: dict, runs: int) -> list:
    """`runs` runs of near-equal size with the batch's mix (segments interleave in a batch)."""
    n = sum(mix.values())
    sizes = [n // runs + (1 if i < n % runs else 0) for i in range(runs)]
    return [{k: v * s / n for k, v in mix.items()} for s in sizes]


def batch(mix: dict, runs: int) -> dict:
    parts = split(mix, runs)
    run_s = [chonk_run_seconds(p) for p in parts]
    leaves = runs
    merges = max(0, leaves - 2)
    cp = max(run_s) + T["btube"] + merge_levels(leaves) * T["merge"] + T["root"]
    work = sum(run_s) + runs * T["btube"] + merges * T["merge"] + T["root"] + (T["padding"] if leaves == 1 else 0)
    return {"runs": runs, "cp": cp, "work": work, "run_s": max(run_s)}


def merge_tree(mix: dict) -> dict:
    n = sum(mix.values())
    seg = max(T[f"ultra_{k}"] for k in mix)
    cp = seg + merge_levels(n) * T["merge"] + T["root"]
    work = sum(T[f"ultra_{k}"] * v for k, v in mix.items()) + max(0, n - 2) * T["merge"] + T["root"]
    return {"cp": cp, "work": work}


def gates_table():
    n = sum(MIX.values())
    ex_ultra = sum(G[f"seg_{k}"] * v for k, v in MIX.items())
    ex_mega = sum(G[f"app_{k}"] * v for k, v in MIX.items())
    print(f"Execution of {n} segments ({', '.join(f'{v} {k}' for k, v in MIX.items())}): "
          f"{ex_ultra / 1e6:.1f}M gates as UltraHonk segments, {ex_mega / 1e6:.1f}M as Mega apps.\n")
    print("| Aggregation | Per folded proof | Per batch |")
    print("| --- | --- | --- |")
    agg_merge = (n - 2) * G["merge"] + G["root"]
    print(f"| Merge tree ({n - 2} merges + root) | {G['merge'] / 2 / 1e3:.0f}k | {agg_merge / 1e6:.1f}M |")
    for runs in (1, 2, 3, 5):
        if n / runs > MAX_APPS:
            continue
        groups = sum(math.ceil(len_ / APPS_PER_KERNEL) for len_ in [n // runs + (1 if i < n % runs else 0) for i in range(runs)])
        kern = runs * (G["bk_init"] + G["bk_tail"] + G["bk_hiding"]) + (groups - runs) * G["bk_inner"]
        tubes = runs * G["btube"]
        merges = max(0, runs - 2) * G["merge"]
        pad = G["padding"] if runs == 1 else 0
        total = kern + tubes + merges + pad + G["root"]
        print(f"| Chonk, {runs} run(s): kernels {kern / 1e6:.2f}M, batch tubes {tubes / 1e6:.2f}M, merges {merges / 1e6:.2f}M, root {G['root'] / 1e6:.2f}M "
              f"| {(G['bk_inner'] - G['bk_init']) / 1e3:.0f}k | {total / 1e6:.1f}M |")
    print()


def lag_table():
    n = sum(MIX.values())
    m = merge_tree(MIX)
    print("| Aggregation | Critical path after the close | Prover work |")
    print("| --- | --- | --- |")
    print(f"| Merge tree, a prover per segment | {m['cp']:.0f} s | {m['work']:.0f} s |")
    best = None
    for runs in range(math.ceil(n / MAX_APPS), n + 1):
        b = batch(MIX, runs)
        if best is None or b["cp"] < best["cp"]:
            best = b
        if runs in (math.ceil(n / MAX_APPS), 4, 8):
            print(f"| Chonk, {runs} runs | {b['cp']:.0f} s | {b['work']:.0f} s |")
    print(f"| Chonk, best ({best['runs']} runs) | {best['cp']:.0f} s | {best['work']:.0f} s |")
    stream = T["stream_finish"] + T["btube"] + T["root"]
    print(f"| Chonk, streamed (2 runs open as segments arrive) | {stream:.0f} s | as above |")
    print()
    return best


def speedup_table():
    """S such that N provers keep up with rate R, one batch every `period` s, and the streamed critical path fits."""
    n1024 = sum(MIX.values())
    seg_per_action = n1024 / P["actions_1024"]
    acc_per_seg = sum(T[f"acc_{k}"] * v for k, v in MIX.items()) / n1024
    run_fixed = T["acc_bk_init"] + T["acc_tail_hiding"] + T["decider"] + T["btube"]
    period = P["batch_period_s"]
    print(f"Per segment {acc_per_seg:.2f} s of accumulation plus {T['acc_bk_inner'] / APPS_PER_KERNEL:.2f} s of kernel; "
          f"{seg_per_action:.3f} segments an action; per run of 45, {run_fixed:.1f} s; a root every {period:.0f} s.\n")
    pools = P["pools"]
    print("| Rate (actions/s) | Actions a batch | Runs | Streamed path at 1× | " + " | ".join(f"S, N = {p}" for p in pools) + " |")
    print("| --- | --- | --- | --- | " + " | ".join("---" for _ in pools) + " |")
    for r in P["rates"]:
        a = r * period
        segs = a * seg_per_action
        runs = max(1, math.ceil(segs / MAX_APPS))
        work = segs * (acc_per_seg + T["acc_bk_inner"] / APPS_PER_KERNEL) + runs * run_fixed + max(0, runs - 2) * T["merge"] + T["root"]
        path = T["stream_finish"] + T["btube"] + merge_levels(runs) * T["merge"] + T["root"]
        cells = []
        for N in pools:
            s = max(work / (N * period), path / TARGET)
            cells.append(f"{s:.1f}×" if s > 1 else "≤ 1×")
        print(f"| {r:,} | {a:,.0f} | {runs} | {path:.0f} s | " + " | ".join(cells) + " |")
    print()


if __name__ == "__main__":
    gates_table()
    lag_table()
    speedup_table()
