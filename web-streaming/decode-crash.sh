#!/bin/bash
#
# Decode crash addresses from backtrace
# Usage: ./decode-crash.sh <address1> [address2] [address3] ...
#
# Example from your crash:
#   ./decode-crash.sh 0x6473e482148b 0x6473e481dc4c 0x6473e48218f5
#

BINARY="./build/macemu-webrtc"

if [ ! -f "$BINARY" ]; then
    echo "Error: $BINARY not found!"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Usage: $0 <address1> [address2] ..."
    echo ""
    echo "Example from crash report:"
    echo "  RIP: 0x00006473e482148b  →  $0 0x6473e482148b"
    echo "  [ 2] ./build/macemu-webrtc(+0x1ba48b) [0x6473e482148b]  →  $0 0x6473e482148b"
    echo ""
    echo "You can also use the offset (+0x1ba48b):"
    echo "  $0 0x1ba48b"
    exit 1
fi

echo "Decoding addresses for: $BINARY"
echo "========================================"
echo ""

for addr in "$@"; do
    echo "Address: $addr"
    addr2line -e "$BINARY" -f -C -i "$addr"
    echo ""
done
