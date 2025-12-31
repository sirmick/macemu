#!/bin/bash
# Diff UAE and Unicorn CPU traces to find first divergence
# Usage: ./diff_cpus.sh <start>-<end> [rom_path]

set -e

RANGE="${1}"
ROM="${2:-$HOME/quadra.rom}"
TIMEOUT="${CPU_TIMEOUT:-2}"

if [ -z "$RANGE" ]; then
    echo "Usage: $0 <start>-<end> [rom_path]" >&2
    echo "Example: $0 3600-3700 ~/quadra.rom" >&2
    exit 1
fi

# Parse range
START=$(echo "$RANGE" | cut -d'-' -f1)
END=$(echo "$RANGE" | cut -d'-' -f2)

echo "=== CPU Trace Comparison ===" >&2
echo "Range: $START-$END" >&2
echo "ROM: $ROM" >&2
echo "" >&2

# Run UAE (suppress all debug output except trace lines)
echo "Running UAE..." >&2
EMULATOR_TIMEOUT=$TIMEOUT CPU_TRACE="$RANGE" CPU_TRACE_QUIET=1 CPU_BACKEND=uae \
    ./build/macemu-next "$ROM" 2>&1 \
    | grep '^\[' \
    > /tmp/trace_uae.txt

# Run Unicorn (suppress all debug output except trace lines)
echo "Running Unicorn..." >&2
EMULATOR_TIMEOUT=$TIMEOUT CPU_TRACE="$RANGE" CPU_TRACE_QUIET=1 CPU_BACKEND=unicorn \
    ./build/macemu-next "$ROM" 2>&1 \
    | grep -v '^\[DEBUG\]' \
    | grep -v '^\[EmulOp' \
    | grep -v '^WARNING:' \
    | grep '^\[' \
    > /tmp/trace_unicorn.txt

echo "Done." >&2
echo "" >&2

# Count instructions
UAE_COUNT=$(wc -l < /tmp/trace_uae.txt)
UC_COUNT=$(wc -l < /tmp/trace_unicorn.txt)

echo "Instructions logged:" >&2
echo "  UAE:     $UAE_COUNT" >&2
echo "  Unicorn: $UC_COUNT" >&2
echo "" >&2

# Find first divergence
echo "=== Finding First Divergence ===" >&2
echo "" >&2

FIRST_DIFF=""
LINE_NUM=1
while IFS= read -r uae_line && IFS= read -r uc_line <&3; do
    if [ "$uae_line" != "$uc_line" ]; then
        FIRST_DIFF=$LINE_NUM
        echo "First divergence at line $LINE_NUM:" >&2
        echo "" >&2
        echo "UAE:     $uae_line" >&2
        echo "Unicorn: $uc_line" >&2
        echo "" >&2

        # Extract instruction number from [NNNNN] prefix
        INSN=$(echo "$uae_line" | sed 's/\[\([0-9]*\)\].*/\1/')
        echo "Instruction #$INSN" >&2

        # Show context (3 lines before)
        if [ $LINE_NUM -gt 3 ]; then
            echo "" >&2
            echo "Context (3 instructions before):" >&2
            echo "" >&2
            head -n $((LINE_NUM - 1)) /tmp/trace_uae.txt | tail -3 | while read -r line; do
                echo "  UAE:     $line" >&2
            done
            head -n $((LINE_NUM - 1)) /tmp/trace_unicorn.txt | tail -3 | while read -r line; do
                echo "  Unicorn: $line" >&2
            done
        fi

        break
    fi
    LINE_NUM=$((LINE_NUM + 1))
done < /tmp/trace_uae.txt 3< /tmp/trace_unicorn.txt

if [ -z "$FIRST_DIFF" ]; then
    echo "No divergence found! Traces are identical." >&2
else
    echo "" >&2
    echo "=== Analysis ===" >&2
    echo "" >&2

    # Parse the divergent lines to show what changed
    uae_line=$(sed -n "${FIRST_DIFF}p" /tmp/trace_uae.txt)
    uc_line=$(sed -n "${FIRST_DIFF}p" /tmp/trace_unicorn.txt)

    # Extract fields (format: [count] PC OP | D0-D7 | A0-A7 | SR flags)
    uae_pc=$(echo "$uae_line" | awk '{print $2}')
    uc_pc=$(echo "$uc_line" | awk '{print $2}')

    uae_op=$(echo "$uae_line" | awk '{print $3}')
    uc_op=$(echo "$uc_line" | awk '{print $3}')

    if [ "$uae_pc" != "$uc_pc" ]; then
        echo "❌ PC diverged: UAE=$uae_pc Unicorn=$uc_pc" >&2
    fi

    if [ "$uae_op" != "$uc_op" ]; then
        echo "❌ Opcode diverged: UAE=$uae_op Unicorn=$uc_op" >&2
        echo "   (CPUs executing different instructions!)" >&2
    else
        echo "ℹ️  Same PC and opcode, but different register state" >&2
    fi
fi

echo "" >&2
echo "Full traces saved to:" >&2
echo "  /tmp/trace_uae.txt" >&2
echo "  /tmp/trace_unicorn.txt" >&2
echo "" >&2
echo "To see full diff:" >&2
echo "  diff -u /tmp/trace_uae.txt /tmp/trace_unicorn.txt | less" >&2
