#!/bin/bash
# Run UAE, Unicorn, and DualCPU with 250k instruction traces (10 second timeout)
# Saves to uae_250k.log, unicorn_250k.log, and dualcpu_250k.log in current directory
#
# Set DEBUG_ON_CRASH=1 to drop into GDB on crash
# Core dumps are always enabled for post-mortem debugging

# Enable core dumps
ulimit -c unlimited

echo "=== Running UAE with 250k instruction trace (10 sec timeout) ==="
EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=uae ./macemu-next/build/macemu-next ~/quadra.rom > uae_250k.log 2>&1
UAE_EXIT=$?
echo "UAE trace saved to uae_250k.log (exit code: $UAE_EXIT)"
if [ $UAE_EXIT -ne 0 ] && [ "$DEBUG_ON_CRASH" = "1" ]; then
    echo "UAE crashed! Dropping into GDB..."
    EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=uae gdb ./macemu-next/build/macemu-next -ex "run ~/quadra.rom"
fi

echo ""
echo "=== Running Unicorn with 250k instruction trace (10 sec timeout) ==="
EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=unicorn ./macemu-next/build/macemu-next ~/quadra.rom > unicorn_250k.log 2>&1
UNICORN_EXIT=$?
echo "Unicorn trace saved to unicorn_250k.log (exit code: $UNICORN_EXIT)"
if [ $UNICORN_EXIT -ne 0 ] && [ "$DEBUG_ON_CRASH" = "1" ]; then
    echo "Unicorn crashed! Dropping into GDB..."
    EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=unicorn gdb ./macemu-next/build/macemu-next -ex "run ~/quadra.rom"
fi

echo ""
echo "=== Running DualCPU with 250k instruction trace (10 sec timeout) ==="
EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=dualcpu ./macemu-next/build/macemu-next ~/quadra.rom > dualcpu_250k.log 2>&1
DUALCPU_EXIT=$?
echo "DualCPU trace saved to dualcpu_250k.log (exit code: $DUALCPU_EXIT)"
if [ $DUALCPU_EXIT -ne 0 ] && [ "$DEBUG_ON_CRASH" = "1" ]; then
    echo "DualCPU crashed! Dropping into GDB..."
    EMULATOR_TIMEOUT=10 CPU_TRACE=0-250000 CPU_BACKEND=dualcpu gdb ./macemu-next/build/macemu-next -ex "run ~/quadra.rom"
fi

echo ""
echo "=== Trace Statistics ==="
echo "UAE instruction count: $(grep -c "^\[[0-9]" uae_250k.log)"
echo "Unicorn instruction count: $(grep -c "^\[[0-9]" unicorn_250k.log)"
echo "DualCPU instruction count: $(grep -c "^\[[0-9]" dualcpu_250k.log)"

echo ""
if [ -f core ]; then
    echo "Core dump available for analysis: core"
    echo "Debug with: gdb ./macemu-next/build/macemu-next core"
fi
