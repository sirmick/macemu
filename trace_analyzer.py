#!/usr/bin/env python3
"""
Trace Analyzer - Reads CPU trace files, disassembles instructions, and compares traces

Usage:
    ./trace_analyzer.py <trace_file> [--rom ROM_PATH] [--compare OTHER_TRACE]

Examples:
    # Show trace with disassembly
    ./trace_analyzer.py unicorn_100k.log --rom ~/quadra.rom

    # Compare two traces (only show differences)
    ./trace_analyzer.py unicorn_100k.log --compare uae_100k.log --rom ~/quadra.rom
"""

import re
import subprocess
import sys
import argparse
import tempfile
import os
from collections import defaultdict

class M68kDisassembler:
    """Disassemble M68K ROM using objdump"""

    def __init__(self, rom_path, rom_base=0x02000000):
        self.rom_path = rom_path
        self.rom_base = rom_base
        self.disasm_cache = {}
        self._load_disassembly()

    def _load_disassembly(self):
        """Pre-load entire ROM disassembly for fast lookups"""
        if not os.path.exists(self.rom_path):
            print(f"Warning: ROM file not found: {self.rom_path}")
            return

        print(f"Disassembling ROM from {self.rom_path}...", file=sys.stderr)

        cmd = [
            'm68k-linux-gnu-objdump',
            '-D',
            '-b', 'binary',
            '-m', 'm68k:68040',
            f'--adjust-vma={hex(self.rom_base)}',
            self.rom_path
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Parse objdump output
            for line in result.stdout.splitlines():
                # Match lines like: " 2000780:	a03f      	.short 0xa03f"
                # or:              " 2000782:	4e75      	rts"
                match = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]+)\s+(.+)$', line)
                if match:
                    addr = int(match.group(1), 16)
                    opcode = match.group(2)
                    disasm = match.group(3).strip()

                    # Clean up disassembly
                    # Remove redundant ".short 0xXXXX" and use actual instruction
                    if '\t' in disasm:
                        disasm = disasm.split('\t', 1)[1]

                    self.disasm_cache[addr] = {
                        'opcode': opcode,
                        'disasm': disasm
                    }

            print(f"Loaded {len(self.disasm_cache)} instructions from ROM", file=sys.stderr)

        except subprocess.CalledProcessError as e:
            print(f"Error running objdump: {e}", file=sys.stderr)
        except FileNotFoundError:
            print("Error: m68k-linux-gnu-objdump not found. Install binutils-m68k-linux-gnu", file=sys.stderr)

    def get_instruction(self, pc, opcode_hex=None):
        """Get disassembled instruction for a given PC"""
        if pc in self.disasm_cache:
            return self.disasm_cache[pc]['disasm']

        # If not in ROM, try to disassemble the opcode directly
        if opcode_hex:
            return self._disassemble_opcode(pc, opcode_hex)

        return "<not in ROM>"

    def _disassemble_opcode(self, pc, opcode_hex):
        """Disassemble a single opcode on the fly"""
        try:
            # Create temporary binary file with opcode
            opcode_bytes = bytes.fromhex(opcode_hex)

            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(opcode_bytes)
                temp_file = f.name

            cmd = [
                'm68k-linux-gnu-objdump',
                '-D',
                '-b', 'binary',
                '-m', 'm68k:68040',
                f'--adjust-vma={hex(pc)}',
                temp_file
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            os.unlink(temp_file)

            # Parse the output
            for line in result.stdout.splitlines():
                if hex(pc)[2:] in line:
                    parts = line.split('\t')
                    if len(parts) >= 3:
                        return parts[2].strip()

            return f"<raw: {opcode_hex}>"

        except Exception as e:
            return f"<disasm error: {e}>"


class TraceEntry:
    """Represents a single trace line"""

    def __init__(self, line):
        self.raw = line.strip()
        self.parse()

    def parse(self):
        """Parse trace line format:
        [NNNNN] PC OPCODE | D0-D7 | A0-A7 | SR
        """
        # Match: [00000] 0200002A 4EFA | regs...
        match = re.match(r'\[(\d+)\]\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{4})\s+\|(.*)$', self.raw)

        if match:
            self.valid = True
            self.inst_num = int(match.group(1))
            self.pc = int(match.group(2), 16)
            self.opcode = match.group(3)
            self.rest = match.group(4).strip()

            # Parse registers if present
            parts = [p.strip() for p in self.rest.split('|')]
            if len(parts) >= 3:
                self.d_regs = parts[0].split()[:8]  # D0-D7
                self.a_regs = parts[1].split()[:8]  # A0-A7
                self.sr = parts[2].split()[0] if parts[2].split() else "????"
            else:
                self.d_regs = []
                self.a_regs = []
                self.sr = "????"
        else:
            self.valid = False
            self.inst_num = -1
            self.pc = 0
            self.opcode = "????"
            self.rest = ""
            self.d_regs = []
            self.a_regs = []
            self.sr = "????"

    def __str__(self):
        return self.raw


def read_trace(filename):
    """Read trace file and return list of TraceEntry objects"""
    entries = []

    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('['):
                entry = TraceEntry(line)
                if entry.valid:
                    entries.append(entry)

    return entries


def format_trace_with_disasm(entry, disasm):
    """Format a trace entry with disassembly"""
    # Format: [NNNNN] PC OPCODE | instruction | D0-D7 | A0-A7 | SR
    inst_str = f"{disasm:30s}"

    d_regs_str = ' '.join(entry.d_regs) if entry.d_regs else ""
    a_regs_str = ' '.join(entry.a_regs) if entry.a_regs else ""

    return f"[{entry.inst_num:05d}] {entry.pc:08X} {entry.opcode} | {inst_str} | D: {d_regs_str} | A: {a_regs_str} | SR: {entry.sr}"


def compare_traces_sequential(trace1, trace2, disassembler, max_diff=50, context=3):
    """Compare two traces sequentially to find first divergence point"""

    print(f"\nSequential trace comparison:")
    print(f"Trace 1: {len(trace1)} instructions")
    print(f"Trace 2: {len(trace2)} instructions")
    print("=" * 120)

    # Compare instruction by instruction
    min_len = min(len(trace1), len(trace2))
    diff_count = 0
    first_pc_diff = None
    first_reg_diff = None

    for i in range(min_len):
        e1 = trace1[i]
        e2 = trace2[i]

        # Check if PCs differ
        pc_differs = (e1.pc != e2.pc)

        # Check if register state differs
        reg_differs = (e1.d_regs != e2.d_regs or e1.a_regs != e2.a_regs or e1.sr != e2.sr)

        if pc_differs or reg_differs:
            diff_count += 1

            # Record first divergence
            if first_pc_diff is None and pc_differs:
                first_pc_diff = i
            if first_reg_diff is None and reg_differs:
                first_reg_diff = i

            if diff_count <= max_diff:
                print(f"\n{diff_count}. DIVERGENCE at instruction #{i}:")

                if pc_differs:
                    disasm1 = disassembler.get_instruction(e1.pc, e1.opcode)
                    disasm2 = disassembler.get_instruction(e2.pc, e2.opcode)
                    print(f"   PC DIFFERS!")
                    print(f"   Trace1: {format_trace_with_disasm(e1, disasm1)}")
                    print(f"   Trace2: {format_trace_with_disasm(e2, disasm2)}")
                else:
                    disasm = disassembler.get_instruction(e1.pc, e1.opcode)
                    print(f"   REGISTER STATE DIFFERS at PC={e1.pc:08X}: {disasm}")
                    print(f"   Trace1: {format_trace_with_disasm(e1, disasm)}")
                    print(f"   Trace2: {format_trace_with_disasm(e2, disasm)}")

                    # Show which registers differ
                    if e1.d_regs != e2.d_regs:
                        for j in range(min(len(e1.d_regs), len(e2.d_regs))):
                            if e1.d_regs[j] != e2.d_regs[j]:
                                print(f"      D{j}: {e1.d_regs[j]} vs {e2.d_regs[j]}")

                    if e1.a_regs != e2.a_regs:
                        for j in range(min(len(e1.a_regs), len(e2.a_regs))):
                            if e1.a_regs[j] != e2.a_regs[j]:
                                print(f"      A{j}: {e1.a_regs[j]} vs {e2.a_regs[j]}")

                    if e1.sr != e2.sr:
                        print(f"      SR: {e1.sr} vs {e2.sr}")

    if diff_count > max_diff:
        print(f"\n... and {diff_count - max_diff} more differences (use --max-diff to show more)")

    print(f"\n{'=' * 120}")
    print(f"Total divergences: {diff_count}")

    if first_pc_diff is not None:
        print(f"First PC divergence at instruction #{first_pc_diff}")

    if first_reg_diff is not None:
        print(f"First register divergence at instruction #{first_reg_diff}")

    # Show context around first divergence
    if first_pc_diff is not None or first_reg_diff is not None:
        first_diff = first_pc_diff if first_pc_diff is not None else first_reg_diff
        print(f"\nContext around first divergence (instruction #{first_diff}):")
        print("=" * 120)

        start = max(0, first_diff - context)
        end = min(min_len, first_diff + context + 1)

        for i in range(start, end):
            e1 = trace1[i]
            e2 = trace2[i]
            marker = ">>>" if i == first_diff else "   "

            disasm1 = disassembler.get_instruction(e1.pc, e1.opcode)
            disasm2 = disassembler.get_instruction(e2.pc, e2.opcode)

            print(f"{marker} [{i:05d}]")
            print(f"    T1: {e1.pc:08X} {e1.opcode} | {disasm1:30s} | D0={e1.d_regs[0] if e1.d_regs else '?'}")
            print(f"    T2: {e2.pc:08X} {e2.opcode} | {disasm2:30s} | D0={e2.d_regs[0] if e2.d_regs else '?'}")

    if len(trace1) != len(trace2):
        print(f"\nLength difference: Trace1 has {len(trace1)} instructions, Trace2 has {len(trace2)}")


def compare_traces(trace1, trace2, disassembler, max_diff=50):
    """Compare two traces and show only differences (PC-based comparison)"""

    # Build PC-indexed maps
    trace1_map = {e.pc: e for e in trace1}
    trace2_map = {e.pc: e for e in trace2}

    # Get all unique PCs from both traces
    all_pcs = sorted(set(list(trace1_map.keys()) + list(trace2_map.keys())))

    print(f"\nPC-based trace comparison (showing max {max_diff} differences):")
    print(f"Trace 1: {len(trace1)} instructions, {len(trace1_map)} unique PCs")
    print(f"Trace 2: {len(trace2)} instructions, {len(trace2_map)} unique PCs")
    print("=" * 120)

    diff_count = 0

    for pc in all_pcs:
        entry1 = trace1_map.get(pc)
        entry2 = trace2_map.get(pc)

        # Check if entries differ
        if entry1 and entry2:
            # Compare registers
            if entry1.d_regs != entry2.d_regs or entry1.a_regs != entry2.a_regs or entry1.sr != entry2.sr:
                diff_count += 1
                if diff_count <= max_diff:
                    disasm = disassembler.get_instruction(pc, entry1.opcode)

                    print(f"\n{diff_count}. DIFFERENCE at PC={pc:08X}: {disasm}")
                    print(f"   Trace1: {format_trace_with_disasm(entry1, disasm)}")
                    print(f"   Trace2: {format_trace_with_disasm(entry2, disasm)}")

        elif entry1 and not entry2:
            diff_count += 1
            if diff_count <= max_diff:
                disasm = disassembler.get_instruction(pc, entry1.opcode)
                print(f"\n{diff_count}. ONLY IN TRACE1 at PC={pc:08X}: {disasm}")
                print(f"   {format_trace_with_disasm(entry1, disasm)}")

        elif entry2 and not entry1:
            diff_count += 1
            if diff_count <= max_diff:
                disasm = disassembler.get_instruction(pc, entry2.opcode)
                print(f"\n{diff_count}. ONLY IN TRACE2 at PC={pc:08X}: {disasm}")
                print(f"   {format_trace_with_disasm(entry2, disasm)}")

    if diff_count > max_diff:
        print(f"\n... and {diff_count - max_diff} more differences (use --max-diff to show more)")

    print(f"\n{'=' * 120}")
    print(f"Total differences: {diff_count}")


def show_trace_with_disasm(trace, disassembler, start=0, end=None):
    """Show trace with disassembly"""

    if end is None:
        end = len(trace)

    print(f"\nShowing trace entries {start} to {end}:")
    print("=" * 120)

    for entry in trace[start:end]:
        disasm = disassembler.get_instruction(entry.pc, entry.opcode)
        print(format_trace_with_disasm(entry, disasm))

    print("=" * 120)


def main():
    parser = argparse.ArgumentParser(
        description='Analyze M68K CPU traces with disassembly',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('trace', help='Primary trace file to analyze')
    parser.add_argument('--rom', default=os.path.expanduser('~/quadra.rom'),
                       help='Path to ROM file (default: ~/quadra.rom)')
    parser.add_argument('--compare', metavar='TRACE2',
                       help='Compare with another trace file')
    parser.add_argument('--sequential', action='store_true',
                       help='Use sequential comparison (instruction-by-instruction) instead of PC-based')
    parser.add_argument('--start', type=int, default=0,
                       help='Start line number (default: 0)')
    parser.add_argument('--end', type=int,
                       help='End line number (default: all)')
    parser.add_argument('--max-diff', type=int, default=50,
                       help='Maximum differences to show when comparing (default: 50)')
    parser.add_argument('--context', type=int, default=3,
                       help='Context lines around divergence (sequential mode, default: 3)')
    parser.add_argument('--rom-base', type=lambda x: int(x, 0), default=0x02000000,
                       help='ROM base address (default: 0x02000000)')

    args = parser.parse_args()

    # Load ROM disassembly
    disassembler = M68kDisassembler(args.rom, args.rom_base)

    # Load primary trace
    print(f"Reading trace from {args.trace}...", file=sys.stderr)
    trace1 = read_trace(args.trace)
    print(f"Loaded {len(trace1)} trace entries", file=sys.stderr)

    if args.compare:
        # Compare mode
        print(f"Reading comparison trace from {args.compare}...", file=sys.stderr)
        trace2 = read_trace(args.compare)
        print(f"Loaded {len(trace2)} trace entries", file=sys.stderr)

        if args.sequential:
            compare_traces_sequential(trace1, trace2, disassembler, args.max_diff, args.context)
        else:
            compare_traces(trace1, trace2, disassembler, args.max_diff)
    else:
        # Display mode
        show_trace_with_disasm(trace1, disassembler, args.start, args.end)


if __name__ == '__main__':
    main()
