#!/bin/bash
# Run UAE, Unicorn, and DualCPU with 250k instruction traces (10 second timeout)
# Saves to uae_250k.log, unicorn_250k.log, and dualcpu_250k.log in current directory

echo "=== Running UAE with 250k instruction trace (10 sec timeout) ==="
EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=uae ./macemu-next/build/macemu-next ~/quadra.rom > uae_250k.log 2>&1
echo "UAE trace saved to uae_250k.log"

echo ""
echo "=== Running Unicorn with 250k instruction trace (10 sec timeout) ==="
EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=unicorn ./macemu-next/build/macemu-next ~/quadra.rom > unicorn_250k.log 2>&1
echo "Unicorn trace saved to unicorn_250k.log"

echo ""
echo "=== Running DualCPU with 250k instruction trace (10 sec timeout) ==="
EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=dualcpu ./macemu-next/build/macemu-next ~/quadra.rom > dualcpu_250k.log 2>&1
echo "DualCPU trace saved to dualcpu_250k.log"

echo ""
echo "=== Trace Statistics ==="
echo "UAE instruction count: $(grep -c "^\[[0-9]" uae_250k.log)"
echo "Unicorn instruction count: $(grep -c "^\[[0-9]" unicorn_250k.log)"
echo "DualCPU instruction count: $(grep -c "^\[[0-9]" dualcpu_250k.log)"
