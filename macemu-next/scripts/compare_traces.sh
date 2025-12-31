#!/bin/bash
# Compare UAE and Unicorn traces side-by-side
# Usage: ./compare_traces.sh start-end rom_path

RANGE="${1:-3688-3693}"
ROM="${2:-$HOME/quadra.rom}"

echo "=== Comparing UAE vs Unicorn traces for instructions $RANGE ===" >&2
echo "" >&2

# Run UAE
echo "Running UAE..." >&2
EMULATOR_TIMEOUT=2 CPU_TRACE="$RANGE" CPU_BACKEND=uae ./build/macemu-next "$ROM" 2>&1 | grep '^\[' > /tmp/trace_uae.txt

# Run Unicorn
echo "Running Unicorn..." >&2
EMULATOR_TIMEOUT=2 CPU_TRACE="$RANGE" CPU_BACKEND=unicorn ./build/macemu-next "$ROM" 2>&1 | grep '^\[' > /tmp/trace_unicorn.txt

echo "" >&2
echo "=== Side-by-side comparison ===" >&2
echo "" >&2

# Display side-by-side with diff highlighting
diff --side-by-side --width=200 /tmp/trace_uae.txt /tmp/trace_unicorn.txt || true

echo "" >&2
echo "=== Detailed differences ===" >&2
echo "" >&2

# Show detailed diff
diff -u /tmp/trace_uae.txt /tmp/trace_unicorn.txt || true

echo "" >&2
echo "Trace files saved to:" >&2
echo "  UAE:     /tmp/trace_uae.txt" >&2
echo "  Unicorn: /tmp/trace_unicorn.txt" >&2
