#!/usr/bin/env python3
"""
Build quadra_halt.rom - Minimal test ROM that looks like Quadra ROM but just HALTs

ROM structure matches real Quadra ROM:
  0x00: Initial SP = 0x420DBFF3 (same as Quadra)
  0x04: Initial PC = 0x0000002A (same as Quadra - entry at offset 0x2A)
  0x08: ROM Version = 0x067C (Quadra ROM version)
  0x10: Test ROM Magic = "TROM" (0x54524F4D) - identifies this as a test ROM
  0x2A: STOP #$2700 instruction

This allows testing with the exact same memory layout as Quadra ROM.
"""

import struct

# ROM size (1MB like Quadra)
ROM_SIZE = 1024 * 1024

# Test ROM magic signature
TEST_ROM_MAGIC = 0x54524F4D  # "TROM" in ASCII

# Create ROM buffer
rom = bytearray(ROM_SIZE)

# Header (same as Quadra ROM)
initial_sp = 0x420DBFF3  # Quadra's initial SP
initial_pc = 0x0000002A  # Entry point at offset 0x2A

# Write header
struct.pack_into('>I', rom, 0x00, initial_sp)  # Initial SP
struct.pack_into('>I', rom, 0x04, initial_pc)  # Initial PC

# ROM version (same as Quadra ROM - required by CheckROM())
rom_version = 0x067C  # Quadra ROM version
struct.pack_into('>H', rom, 0x08, rom_version)

# TEST ROM MAGIC - identifies this as a test ROM (not present in real Mac ROMs)
# Place at offset 0x10 (after ROM version header)
struct.pack_into('>I', rom, 0x10, TEST_ROM_MAGIC)

# Fill padding before entry point with NOPs (0x4E71)
# Skip the magic at 0x10-0x13
for offset in range(0x0A, 0x10, 2):
    struct.pack_into('>H', rom, offset, 0x4E71)  # NOP instruction
for offset in range(0x14, 0x2A, 2):
    struct.pack_into('>H', rom, offset, 0x4E71)  # NOP instruction

# Write STOP instruction at entry point (0x2A)
stop_opcode = 0x4E72      # STOP opcode
stop_immediate = 0x2700   # SR value (supervisor mode, interrupts masked)

struct.pack_into('>H', rom, 0x2A, stop_opcode)
struct.pack_into('>H', rom, 0x2C, stop_immediate)

# Add a few NOPs after STOP for safety
for offset in range(0x2E, 0x40, 2):
    struct.pack_into('>H', rom, offset, 0x4E71)  # NOP

# Write ROM file
with open('quadra_halt.rom', 'wb') as f:
    f.write(rom)

print(f"Created quadra_halt.rom ({ROM_SIZE} bytes)")
print(f"  Initial SP: 0x{initial_sp:08X}")
print(f"  Initial PC: 0x{initial_pc:08X}")
print(f"  ROM Version: 0x{rom_version:04X}")
print(f"  Entry point: offset 0x{initial_pc:X}")
print(f"  Instruction at entry: STOP #$2700")

# Verify
with open('quadra_halt.rom', 'rb') as f:
    header = f.read(20)  # Read through magic
    sp = struct.unpack('>I', header[0:4])[0]
    pc = struct.unpack('>I', header[4:8])[0]
    version = struct.unpack('>H', header[8:10])[0]
    magic = struct.unpack('>I', header[16:20])[0]

    f.seek(0x2A)
    instr = f.read(4)

print(f"\nVerification:")
print(f"  Initial SP: 0x{sp:08X} ✓" if sp == initial_sp else f"  Initial SP: 0x{sp:08X} ✗")
print(f"  Initial PC: 0x{pc:08X} ✓" if pc == initial_pc else f"  Initial PC: 0x{pc:08X} ✗")
print(f"  ROM Version: 0x{version:04X} ✓" if version == rom_version else f"  ROM Version: 0x{version:04X} ✗")
print(f"  Test ROM Magic: 0x{magic:08X} ({magic.to_bytes(4, 'big').decode('ascii')}) ✓" if magic == TEST_ROM_MAGIC else f"  Test ROM Magic: 0x{magic:08X} ✗")
print(f"  Instruction at 0x2A: {instr.hex()}")
print(f"  Expected: 4e722700 (STOP #$2700)")
print(f"  Match: {instr.hex() == '4e722700'} ✓" if instr.hex() == '4e722700' else f"  Match: False ✗")
