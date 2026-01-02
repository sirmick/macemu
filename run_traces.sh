#!/bin/bash
# Run UAE and Unicorn with 100k instruction traces (5 second timeout)
# Saves to uae_100k.log and unicorn_100k.log in current directory

echo "=== Running UAE with 100k instruction trace (5 sec timeout) ==="
EMULATOR_TIMEOUT=5 CPU_TRACE=0-100000 CPU_BACKEND=uae ./macemu-next/build/macemu-next ~/quadra.rom > uae_100k.log
echo "UAE trace saved to uae_100k.log"

echo ""
echo "=== Running Unicorn with 100k instruction trace (5 sec timeout) ==="
EMULATOR_TIMEOUT=5 CPU_TRACE=0-100000 CPU_BACKEND=unicorn ./macemu-next/build/macemu-next ~/quadra.rom > unicorn_100k.log
echo "Unicorn trace saved to unicorn_100k.log"

echo ""
echo "=== Trace Statistics ==="
echo "UAE instruction count: $(grep -c "^\[[0-9]" uae_100k.log)"
echo "Unicorn instruction count: $(grep -c "^\[[0-9]" unicorn_100k.log)"
