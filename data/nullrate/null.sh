#!/bin/bash
# Measure the null crash rate: how often does the tool fail on a benign input?
set -u
printf '__global__ void k(){}\n' > /tmp/b.cu
nvcc -cubin /tmp/b.cu -o /tmp/benign.cubin 2>/dev/null || { echo "compile-failed"; exit 0; }
ok=0; bad=0
for i in $(seq 1 20); do
  cuobjdump --dump-elf /tmp/benign.cubin >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then ok=$((ok+1)); else bad=$((bad+1)); echo "run $i rc=$rc"; fi
done
echo "NULLRATE ok=$ok bad=$bad"
