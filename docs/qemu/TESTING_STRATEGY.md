# QEMU CPU Migration Testing Strategy

## Overview

This document describes the **DualCPU** testing harness - a practical approach to validate QEMU CPU integration by running legacy and QEMU CPUs side-by-side.

## Core Philosophy

**Don't trust, verify.** Instead of months of debugging subtle differences, we:

1. **Run both CPUs on the same code simultaneously**
2. **Compare state after every instruction (or periodically)**
3. **Generate detailed traces for offline analysis**
4. **Pinpoint exact divergence points with full context**

## Testing Phases

### Phase 0: Sanity Check (Week 1)
**Goal:** Verify basic QEMU integration works at all

```bash
# Build minimal test
make test-dualcpu-basic

# Run trivial instruction sequence
./test-dualcpu-basic
```

**Test program:**
```assembly
    MOVE.W  #$1234,D0
    MOVE.W  #$5678,D1
    ADD.W   D1,D0
    STOP    #$2700
```

**Expected:** Both CPUs produce identical results, D0=$68AC

**If fails:** QEMU integration is fundamentally broken, fix before continuing

---

### Phase 1: Instruction-Level Validation (Week 2-3)
**Goal:** Validate every m68k/PPC instruction works identically

#### 1.1 Arithmetic & Logic
```bash
./gen_test_suite --category arithmetic --instructions 10000
./test-dualcpu --mode lockstep --trace tests/arithmetic.bin
```

Test all variants of:
- ADD/SUB/MUL/DIV (byte/word/long, immediate/register/memory)
- AND/OR/XOR/NOT
- Shifts and rotates (LSL/LSR/ASL/ASR/ROL/ROR)
- Bit operations (BTST/BSET/BCLR/BCHG)

**Success metric:** 0 divergences across 10K instructions

#### 1.2 Control Flow
```bash
./gen_test_suite --category branches --instructions 5000
./test-dualcpu --mode lockstep --trace tests/branches.bin
```

Test all condition codes and branch types:
- Bcc (all 16 conditions)
- DBcc (decrement and branch)
- Scc (set on condition)
- TRAP, RTS, RTR, JSR, JMP

**Success metric:** All branches taken/not-taken match

#### 1.3 Memory Operations
```bash
./gen_test_suite --category memory --instructions 5000
./test-dualcpu --mode lockstep --trace tests/memory.bin
```

Test all addressing modes:
- Data register direct (Dn)
- Address register direct (An)
- Address register indirect (An)
- Postincrement (An)+
- Predecrement -(An)
- Displacement (d16,An) and (d8,An,Xn)
- Absolute short/long
- PC-relative

**Success metric:** All memory accesses match (address, value, size)

#### 1.4 Exception Handling
```bash
./gen_test_suite --category exceptions --instructions 1000
./test-dualcpu --mode lockstep --trace tests/exceptions.bin
```

Test exception behavior:
- Illegal instructions
- Privilege violations
- Address errors
- Division by zero
- TRAP instructions

**Success metric:** Exception vectors, stack frames match

---

### Phase 2: ROM Code Execution (Week 4-5)
**Goal:** Run actual Mac ROM code without divergence

#### 2.1 Reset Vector
```bash
./test-dualcpu --rom mac_rom.bin --mode checkpoint \
    --checkpoints 0x0,0x400,0x800,0x1000 \
    --max-instructions 10000
```

**Checkpoints:**
- `0x00000000`: Reset vector
- `0x00000400`: First ROM routine
- `0x00000800`: Early initialization
- `0x00001000`: Memory test start

**Success metric:** Both CPUs reach checkpoint 0x1000 with identical state

#### 2.2 Memory Test
```bash
./test-dualcpu --rom mac_rom.bin --mode checkpoint \
    --start 0x1000 --end 0x3000 \
    --save-divergence
```

**Challenges:**
- Complex addressing modes
- Self-modifying code (ROM patching)
- Timing-dependent loops

**Success metric:** Memory test completes, RAM initialized identically

#### 2.3 Driver Initialization
```bash
./test-dualcpu --rom mac_rom.bin --mode checkpoint \
    --start 0x3000 \
    --emulops-only  # Only check at EmulOp boundaries
```

**Focus:** EmulOp integration
- Video driver init (OP_VIDEO_OPEN)
- Disk driver init (OP_DISK_OPEN)
- Serial driver init (OP_SERIAL_OPEN)

**Success metric:** All drivers initialize, EmulOps called with matching arguments

---

### Phase 3: Full Boot (Week 6-8)
**Goal:** Boot to Finder without divergence

#### 3.1 Trace-Only Boot
```bash
# Generate full traces without comparison (faster)
./test-dualcpu --rom mac_rom.bin --mode trace-only \
    --trace-legacy legacy_boot.trace.lz4 \
    --trace-qemu qemu_boot.trace.lz4 \
    --max-time 60s

# Compare offline
./trace_diff legacy_boot.trace.lz4 qemu_boot.trace.lz4 \
    --output boot_divergence.txt \
    --disassemble
```

**Advantage:** No runtime overhead, can run both at full speed

#### 3.2 Periodic Checkpoint Boot
```bash
# Check every 10K instructions (good balance of speed vs precision)
./test-dualcpu --rom mac_rom.bin --mode periodic \
    --interval 10000 \
    --stop-on-divergence \
    --save-state divergence.state
```

**If divergence:** Binary search to find exact instruction
```bash
# Found divergence around instruction 4,285,000
# Narrow down with lockstep mode
./test-dualcpu --rom mac_rom.bin --mode lockstep \
    --start-instruction 4284000 \
    --end-instruction 4286000
```

#### 3.3 Boot to Finder
```bash
./test-dualcpu --rom mac_rom.bin \
    --disk system_disk.dsk \
    --mode checkpoint \
    --checkpoints-file finder_checkpoints.txt \
    --timeout 300s
```

**finder_checkpoints.txt:**
```
0x00000000  # Reset
0x00400000  # ROM boot complete
0x40001000  # System file loaded
0x40020000  # Finder launched
0x40030000  # Desktop drawn
```

**Success metric:** Reach "Desktop drawn" with identical state

---

### Phase 4: Interactive Testing (Week 9-10)
**Goal:** Ensure interactive operations work correctly

#### 4.1 Dual-Display Mode
Run both CPUs with separate display windows:

```bash
./test-dualcpu --rom mac_rom.bin --disk system.dsk \
    --dual-display \
    --show-legacy left \
    --show-qemu right \
    --sync-input
```

**User actions:**
1. Move mouse → Both displays should show identical cursor
2. Click → Both should respond identically
3. Type → Both should show same text
4. Drag window → Both should track perfectly

**Any visual difference = divergence to investigate**

#### 4.2 Benchmark Mode
```bash
./test-dualcpu --rom mac_rom.bin --disk bench.dsk \
    --mode periodic --interval 100000 \
    --benchmark
```

Run MacBench or other benchmark, compare:
- Final scores (should be identical)
- Execution trace checksums
- Performance (QEMU should be comparable to legacy JIT)

---

## Trace Analysis Tools

### trace_diff - Compare traces
```bash
# Find first divergence
./trace_diff legacy.trace qemu.trace --first

# Show disassembly
./trace_diff legacy.trace qemu.trace --disassemble

# Focus on specific instruction range
./trace_diff legacy.trace qemu.trace \
    --start 1000000 --end 1001000
```

### trace_stats - Analyze trace
```bash
# Instruction frequency
./trace_stats legacy.trace --histogram

# Memory access patterns
./trace_stats legacy.trace --memory-map

# EmulOp statistics
./trace_stats legacy.trace --emulops
```

### trace_replay - Replay trace
```bash
# Debug a specific divergence
./trace_replay divergence.state --step --disassemble
```

---

## Debugging Workflow

When divergence is found:

```
1. Identify divergence point from trace
   ./trace_diff legacy.trace qemu.trace --first

2. Save state before divergence
   ./test-dualcpu --restore divergence.state --save-before before.state

3. Single-step through divergence
   ./trace_replay before.state --step --compare qemu

4. Examine difference
   - Register dump
   - Memory dump
   - Disassembly
   - Call stack

5. Fix QEMU integration

6. Re-run test to verify fix
   ./test-dualcpu --restore before.state --count 100

7. Continue from divergence point
   ./test-dualcpu --start-from divergence.state
```

---

## Performance Expectations

| Mode | Overhead | Use Case |
|------|----------|----------|
| Lockstep | 100-200% | Precise divergence location |
| Periodic (N=1000) | 20-40% | Good balance |
| Periodic (N=10000) | 5-10% | Fast validation |
| Checkpoint | 1-2% | Long-running tests |
| Trace-Only | <1% | Full boot traces |

---

## Success Criteria by Phase

| Phase | Criterion | Timeline |
|-------|-----------|----------|
| 0 | Basic instructions work | End of Week 1 |
| 1 | All instructions validated | End of Week 3 |
| 2 | ROM code runs to driver init | End of Week 5 |
| 3 | Boot to Finder | End of Week 8 |
| 4 | Interactive use works | End of Week 10 |

---

## Continuous Integration

Set up automated testing:

```bash
# Run nightly test suite
./run_regression_tests.sh

# Tests:
# - All instruction categories (Phase 1)
# - ROM boot to checkpoints (Phase 2.1, 2.2)
# - Quick boot test (Phase 3.2, 30s timeout)
# - Known-good application launches

# Any regression = block commits
```

---

## Key Insights

1. **Start small**: Validate individual instructions before ROM code
2. **Binary search**: Use periodic checks to narrow divergence range
3. **Trace offline**: Generate traces separately, compare later (faster)
4. **Checkpoint liberally**: Save state frequently during long runs
5. **Automate everything**: CI catches regressions immediately

With this harness, you can validate QEMU integration **empirically** rather than hoping it works. Any divergence is caught immediately with full context for debugging.
