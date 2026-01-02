#!/bin/bash
# Compare CPU traces from UAE and Unicorn to find first divergence

echo "=== Running UAE with 100k instruction trace ==="
EMULATOR_TIMEOUT=60 CPU_TRACE=0-100000 CPU_BACKEND=uae ./macemu-next/build/macemu-next ~/quadra.rom 2>&1 | grep "^\[[0-9]" > /tmp/uae_trace.log

echo "=== Running Unicorn with 100k instruction trace ==="
EMULATOR_TIMEOUT=60 CPU_TRACE=0-100000 CPU_BACKEND=unicorn ./macemu-next/build/macemu-next ~/quadra.rom 2>&1 | grep "^\[[0-9]" > /tmp/unicorn_trace.log

echo "=== Comparing traces ==="
echo "UAE instructions: $(wc -l < /tmp/uae_trace.log)"
echo "Unicorn instructions: $(wc -l < /tmp/unicorn_trace.log)"

echo ""
echo "=== Finding first divergence ==="
diff -u /tmp/uae_trace.log /tmp/unicorn_trace.log | head -50
