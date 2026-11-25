#!/usr/bin/env bash
# Synthetic prover-throughput circuits (SPEC.md §14): a chain of Poseidon2 permutations sized to
# fill 2^k gates, k = 16..23, plus a mix of arithmetic so the trace is not one gate type only.
set -euo pipefail
cd "$(dirname "$0")"
for k in "$@"; do
  # ~73 gates a permutation plus ~8 arithmetic gates a step; fill ~90% of 2^k.
  n=$(( (1 << k) * 9 / 10 / 81 ))
  d=synth_$k
  mkdir -p $d/src
  printf '[package]\nname = "%s"\ntype = "bin"\nauthors = [""]\n\n[dependencies]\n' $d > $d/Nargo.toml
  cat > $d/src/main.nr <<NR
global N: u32 = $n;
fn main(x: [Field; 4]) -> pub Field {
    let mut s = x;
    let mut acc = 0;
    for i in 0..N {
        s = std::hash::poseidon2_permutation(s);
        acc = acc * s[1] + s[2] * (i as Field) + s[3] * s[0];
    }
    acc + s[0]
}
NR
  printf 'x = ["1", "2", "3", "4"]\n' > $d/Prover.toml
done
