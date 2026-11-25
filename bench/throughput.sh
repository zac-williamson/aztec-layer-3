#!/usr/bin/env bash
# Measures bb's UltraHonk prover on the synthetic circuits: wall time by 2^k and thread count, with
# the host's 1-minute load before each run. Output: one TSV line per run.
#   ./throughput.sh "<ks>" "<threads>" [target]
set -uo pipefail
cd "$(dirname "$0")"
source ~/l3x-env.sh
target=${3:-noir-rollup-no-zk}
out=$(mktemp -d)
for k in $1; do
  vk=synth_$k/target/vk_$target
  [ -f $vk/vk ] || { mkdir -p $vk; aztec-bb write_vk -b synth_$k/target/synth_$k.json -o $vk -t $target >/dev/null 2>&1; }
  for t in $2; do
    load=$(cut -d' ' -f1 /proc/loadavg)
    s=$(date +%s.%N)
    HARDWARE_CONCURRENCY=$t aztec-bb prove -b synth_$k/target/synth_$k.json -w synth_$k/target/synth_$k.gz -o $out -t $target -k $vk/vk >/dev/null 2>&1 || echo "FAIL $k $t"
    e=$(date +%s.%N)
    gates=$(( (1 << k) ))
    printf "%s\t%s\t%s\t%s\t%s\n" "$k" "$t" "$target" "$(python3 -c "print(round($e - $s, 2))")" "$load"
  done
done
rm -rf "$out"
