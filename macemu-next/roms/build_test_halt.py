#!/usr/bin/env python3
"""
Build test_halt.bin - Minimal ROM with just a STOP instruction

ROM structure:
  0x0000: Initial SP (32-bit) = 0x00002000
  0x0004: Initial PC (32-bit) = 0x00000008 (points to 'start')
  0x0008: STOP #$2700 instruction = 0x4E72 0x2700
"""

import struct

# ROM header (8 bytes)
initial_sp = 0x00002000  # Stack pointer at 8KB
initial_pc = 0x00000008  # PC points to start (right after header)

# STOP #$2700 instruction
# Opcode: 0x4E72 (STOP)
# Immediate: 0x2700 (SR value - supervisor mode, all interrupts masked)
stop_opcode = 0x4E72
stop_immediate = 0x2700

# Build ROM
rom = bytearray()

# Header
rom.extend(struct.pack('>I', initial_sp))  # Big-endian 32-bit
rom.extend(struct.pack('>I', initial_pc))

# Code
rom.extend(struct.pack('>H', stop_opcode))      # Big-endian 16-bit
rom.extend(struct.pack('>H', stop_immediate))

# Pad to at least 16 bytes (for safety)
while len(rom) < 16:
    rom.append(0x00)

# Write ROM file
with open('test_halt.bin', 'wb') as f:
    f.write(rom)

print(f"Created test_halt.bin ({len(rom)} bytes)")
print(f"  Initial SP: 0x{initial_sp:08X}")
print(f"  Initial PC: 0x{initial_pc:08X}")
print(f"  Instruction at 0x{initial_pc:08X}: STOP #${stop_immediate:04X}")
