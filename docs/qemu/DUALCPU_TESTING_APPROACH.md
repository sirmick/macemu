# DualCPU Testing Approach: Eliminating "Months of Fucking Around"

## The Problem

When migrating to QEMU CPUs, the traditional approach would be:
1. Integrate QEMU
2. Try to boot
3. Something doesn't work
4. Spend weeks debugging subtle differences
5. Fix one issue
6. Discover another issue
7. Repeat for months

**This sucks.** We need a better way.

## The Solution: Side-by-Side Execution

Run **both CPUs simultaneously** on the same code, comparing their execution step-by-step:

```
┌──────────────┐    ┌──────────────┐
│  Legacy CPU  │    │   QEMU CPU   │
│  (UAE/KPX)   │    │  (m68k/PPC)  │
└──────┬───────┘    └──────┬───────┘
       │                    │
       │   Same input       │
       │   Same code        │
       │   Same memory      │
       │                    │
       ↓                    ↓
  Execute one          Execute one
  instruction          instruction
       │                    │
       ↓                    ↓
   Snapshot             Snapshot
   CPU state            CPU state
       │                    │
       └────────┬───────────┘
                ↓
         Compare states
                │
        ┌───────┴────────┐
        ↓                ↓
     Match?          Diverge?
   Continue          STOP!
                       ↓
              Pinpoint exact
              divergence with
              full context
```

## Core Concept

### Execution Modes

#### 1. Lockstep Mode (Slowest, Most Precise)
Compare after **every single instruction**.

```cpp
while (true) {
    CPUSnapshot before_legacy = snapshot(legacy_cpu);
    CPUSnapshot before_qemu = snapshot(qemu_cpu);

    legacy_cpu.execute_one();
    qemu_cpu.execute_one();

    CPUSnapshot after_legacy = snapshot(legacy_cpu);
    CPUSnapshot after_qemu = snapshot(qemu_cpu);

    if (!states_match(after_legacy, after_qemu)) {
        printf("DIVERGENCE at instruction %llu!\n", count);
        save_state("divergence.state");
        dump_context(before_legacy, after_legacy, after_qemu);
        abort();
    }
    count++;
}
```

**Use when:** Finding the exact instruction where divergence occurs
**Overhead:** 100-200% slower
**Precision:** Exact instruction

#### 2. Periodic Mode (Balanced)
Compare every N instructions.

```cpp
while (true) {
    // Execute N instructions on both
    for (int i = 0; i < 1000; i++) {
        legacy_cpu.execute_one();
        qemu_cpu.execute_one();
    }

    // Now compare
    if (!states_match(legacy_cpu, qemu_cpu)) {
        // Divergence somewhere in last 1000 instructions
        // Narrow down with lockstep
        rollback(1000);
        run_lockstep(1000);
    }
}
```

**Use when:** General validation, good performance/precision balance
**Overhead:** 10-50% slower (depending on N)
**Precision:** Within N instructions

#### 3. Checkpoint Mode (Fastest)
Compare only at specific PC values.

```cpp
uint32_t checkpoints[] = {
    0x00000000,  // Reset vector
    0x00000400,  // ROM routine 1
    0x00001000,  // Memory test
    0x00002000,  // Driver init
};

void on_checkpoint(uint32_t pc) {
    if (is_checkpoint(pc)) {
        if (!states_match(legacy_cpu, qemu_cpu)) {
            printf("Divergence before checkpoint %08x\n", pc);
            // Rewind and use periodic mode to narrow down
        }
    }
}
```

**Use when:** Long runs (full boot), known checkpoints
**Overhead:** 1-5% slower
**Precision:** Between checkpoints

#### 4. Trace-Only Mode (No Comparison)
Record full execution trace, compare offline.

```cpp
// Run both CPUs at full speed, no comparison
FILE *legacy_trace = fopen("legacy.trace", "wb");
FILE *qemu_trace = fopen("qemu.trace", "wb");

while (true) {
    legacy_cpu.execute_one();
    write_trace(legacy_trace, snapshot(legacy_cpu));

    qemu_cpu.execute_one();
    write_trace(qemu_trace, snapshot(qemu_cpu));
}

// Later: compare traces offline
$ trace_diff legacy.trace qemu.trace
```

**Use when:** Full boot traces, no runtime overhead
**Overhead:** <1% slower
**Precision:** Offline analysis

## What Gets Compared

### CPU State Snapshot

```c
struct CPUSnapshot {
    // Identity
    uint64_t seq_number;        // Instruction count

    // CPU registers (after instruction execution)
    uint32_t pc;                // Program counter
    uint32_t registers[32];     // GPRs (D0-D7, A0-A7 or R0-R31)
    uint32_t sr_ccr;           // Status/condition register
    uint32_t sp;               // Stack pointer

    // FPU state (if applicable)
    double fpu_registers[16];

    // Memory access (if any this instruction)
    uint8_t  mem_access_type;   // 0=none, 1=read, 2=write, 3=rmw
    uint32_t mem_address;
    uint32_t mem_value;
    uint8_t  mem_size;

    // Exception info
    uint8_t  exception_vector;  // 0=none, 1-255=exception number

    // EmulOp info
    bool     is_emulop;
    uint16_t emulop_selector;
};
```

### Comparison Logic

```cpp
bool states_match(const CPUSnapshot *legacy, const CPUSnapshot *qemu) {
    // PC must match
    if (legacy->pc != qemu->pc) {
        printf("PC differs: %08x vs %08x\n", legacy->pc, qemu->pc);
        return false;
    }

    // All registers must match
    for (int i = 0; i < num_regs; i++) {
        if (legacy->registers[i] != qemu->registers[i]) {
            printf("Register %d differs\n", i);
            return false;
        }
    }

    // Status register
    if (legacy->sr_ccr != qemu->sr_ccr) {
        printf("SR/CCR differs\n");
        return false;
    }

    // Memory access (if any)
    if (legacy->mem_access_type != qemu->mem_access_type) {
        printf("Memory access type differs\n");
        return false;
    }

    if (legacy->mem_access_type != 0) {
        if (legacy->mem_address != qemu->mem_address ||
            legacy->mem_value != qemu->mem_value) {
            printf("Memory access differs\n");
            return false;
        }
    }

    // Exceptions
    if (legacy->exception_vector != qemu->exception_vector) {
        printf("Exception differs\n");
        return false;
    }

    // EmulOps
    if (legacy->is_emulop != qemu->is_emulop) {
        printf("EmulOp flag differs\n");
        return false;
    }

    return true;
}
```

## Workflow Examples

### Example 1: Find First Divergence in ROM Boot

```bash
# Step 1: Run in checkpoint mode (fast)
$ ./dualcpu --rom mac.rom --mode checkpoint \
    --checkpoints 0x0,0x400,0x800,0x1000,0x2000

# Output:
# ✓ Checkpoint 0x00000000 - Match
# ✓ Checkpoint 0x00000400 - Match
# ✓ Checkpoint 0x00000800 - Match
# ✗ Checkpoint 0x00001000 - DIVERGENCE!
#   Divergence occurred between 0x800 and 0x1000

# Step 2: Narrow down with periodic mode
$ ./dualcpu --rom mac.rom --mode periodic --interval 1000 \
    --start-pc 0x800 --end-pc 0x1000

# Output:
# Divergence between instruction 42000 and 43000

# Step 3: Find exact instruction with lockstep
$ ./dualcpu --rom mac.rom --mode lockstep \
    --start-instruction 42000 --end-instruction 43000

# Output:
# DIVERGENCE at instruction 42,127!
# PC: 0x00000a3c
# Opcode: 51c8fffc (DBF D0,$a38)
#
# Legacy: D0=00000001 -> PC=00000a38 (branch taken)
# QEMU:   D0=00000001 -> PC=00000a40 (branch NOT taken)
#
# State saved to: divergence_42127.state
```

### Example 2: Validate Instruction Set

```bash
# Generate test suite for all m68k instructions
$ ./gen_test_suite --architecture m68k --all --count 10000

# Run in lockstep (catch any divergence immediately)
$ ./dualcpu --test instruction_suite.bin --mode lockstep

# Output (if successful):
# Executed 10,000 instructions
# Divergences: 0
# ✓ All instructions match perfectly!

# Output (if divergence):
# DIVERGENCE at instruction 1,247
# Test: ALU/ADD_B_IMMEDIATE
# Legacy: D0=00000012, Z=0, N=0, V=0, C=0
# QEMU:   D0=00000012, Z=1, N=0, V=0, C=0
#         ^^^ Zero flag incorrectly set!
```

### Example 3: Trace Full Boot for Analysis

```bash
# Step 1: Generate traces (fast, no comparison overhead)
$ ./dualcpu --rom mac.rom --disk system.dsk \
    --mode trace-only \
    --trace-legacy boot_legacy.trace.lz4 \
    --trace-qemu boot_qemu.trace.lz4 \
    --max-time 60s

# Output:
# Legacy CPU: 45.2M instructions in 60s (753K IPS)
# QEMU CPU:   38.7M instructions in 60s (645K IPS)
# Traces written (compressed: 842MB + 798MB)

# Step 2: Compare offline
$ ./trace_diff boot_legacy.trace.lz4 boot_qemu.trace.lz4 \
    --output boot_divergence.txt

# Output:
# Comparing traces...
# [............] 1M instructions
# [............] 2M instructions
# ...
# [........✗...] 4M instructions
#
# DIVERGENCE #1 at instruction 4,285,127
# See boot_divergence.txt for details

# Step 3: Examine divergence
$ less boot_divergence.txt

# Shows full context:
# [004285127] PC=0040a3c2 SR=2004
#             OPCODE: 51c8fffc  DBF D0,$40a3c0
#             D0=00000001 ...
#             Legacy: branch taken
#             QEMU:   branch NOT taken
```

### Example 4: Debug Specific Divergence

```bash
# Load saved state from divergence
$ ./trace_replay divergence_42127.state

# Interactive debugger
(dbg) info regs
Legacy:
  PC: 00000a3c  SR: 2004
  D0: 00000001  D1: 00000000  ...

QEMU:
  PC: 00000a3c  SR: 2004
  D0: 00000001  D1: 00000000  ...

(dbg) disasm
00000a3c: 51c8fffc    DBF D0,$a38

(dbg) step
# Execute instruction on both

Legacy:
  PC: 00000a38  (branch taken, D0 was 1, now 0)

QEMU:
  PC: 00000a40  (branch NOT taken, D0 still 1!)

(dbg) # Aha! QEMU isn't decrementing D0!
```

## Trace File Format

### Binary Format (Compact, Fast)

```c
// 128 bytes per entry (cache-aligned)
struct TraceEntry {
    uint64_t seq_number;
    uint32_t pc;
    uint32_t opcode;
    uint32_t registers[16];
    uint32_t sr_ccr;
    uint32_t sp;
    uint8_t  mem_access_type;
    uint32_t mem_address;
    uint32_t mem_value;
    uint8_t  mem_size;
    uint8_t  exception;
    uint8_t  is_emulop;
    uint16_t emulop_selector;
    uint8_t  padding[48];
} __attribute__((packed));
```

**File size:** ~100 bytes/instruction × 1M instructions = 100MB
**Compressed (LZ4):** ~10-20MB

### Text Format (Human-Readable)

```
[0000042127] PC=00000a3c SR=2004 D0=00000001 D1=00000000 ...
             OPCODE: 51c8fffc    DBF D0,$a38

[0000042128] PC=00000a38 SR=2004 D0=00000000 D1=00000000 ...
             OPCODE: 4e710000    NOP
             MEM_READ: 00000a38 = 4e710000 (4 bytes)
```

## Tooling

### trace_diff - Compare Traces

```bash
# Find first divergence
$ trace_diff legacy.trace qemu.trace --first

# Show disassembly
$ trace_diff legacy.trace qemu.trace --disassemble

# Focus on range
$ trace_diff legacy.trace qemu.trace --start 1000000 --end 2000000

# Stop on first
$ trace_diff legacy.trace qemu.trace --first --save-state div.state
```

### trace_stats - Analyze Trace

```bash
# Instruction histogram
$ trace_stats legacy.trace --histogram
MOVE:  23.4%
ADD:   12.1%
JSR:    8.7%
...

# Memory access patterns
$ trace_stats legacy.trace --memory-map
0x00000000-0x000fffff: RAM   (42.3M accesses)
0x00f00000-0x00ffffff: ROM   ( 8.1M accesses)
0x50000000-0x50ffffff: Video ( 2.8M accesses)

# EmulOp statistics
$ trace_stats legacy.trace --emulops
VIDEO_OPEN:     23 calls
DISK_PRIME:    142 calls
ETHER_READ:     89 calls
```

### trace_replay - Debug Divergence

```bash
# Load and step through
$ trace_replay divergence.state --step

# Compare with QEMU
$ trace_replay divergence.state --compare qemu --step

# Disassemble around divergence
$ trace_replay divergence.state --disasm --context 10
```

## Performance Characteristics

| Mode | Overhead | Instructions/sec | Use Case |
|------|----------|------------------|----------|
| **Trace-only** | <1% | ~700K | Full boot traces |
| **Checkpoint** | 1-5% | ~650K | Long runs |
| **Periodic (10K)** | 5-10% | ~550K | Fast validation |
| **Periodic (1K)** | 20-40% | ~400K | Good balance |
| **Lockstep** | 100-200% | ~250K | Exact divergence |

Baseline: ~750K instructions/sec on legacy CPU without dual mode

## Key Advantages

### 1. **Immediate Feedback**
No guessing, no "try and see" - divergences are caught **immediately** with full context.

### 2. **Binary Search**
Use fast modes to find approximate divergence, then narrow down:
```
Checkpoint mode (1-5% overhead)
  → Found between checkpoint A and B
    → Periodic mode (20% overhead)
      → Found between instruction N and N+10K
        → Lockstep mode (100% overhead)
          → Found exact instruction: N+4,127
```

### 3. **Reproducible**
Save state at any point, replay exact execution:
```bash
# Save state
$ dualcpu --save-state checkpoint_1000.state --checkpoint-instruction 1000

# Later: resume from exact state
$ dualcpu --load-state checkpoint_1000.state --step
```

### 4. **Offline Analysis**
Generate traces during work hours, analyze overnight:
```bash
# Day: generate traces (fast)
$ dualcpu --mode trace-only --trace-legacy day1.trace &

# Night: compare and analyze
$ trace_diff day1_legacy.trace day1_qemu.trace > divergences.txt
$ trace_stats day1_legacy.trace --all > stats.txt
```

### 5. **Regression Prevention**
Add passing tests to CI:
```bash
#!/bin/bash
# regression_test.sh

# Test 1: Instruction suite
./dualcpu --test instructions.bin --mode lockstep || exit 1

# Test 2: ROM boot to checkpoint
./dualcpu --rom mac.rom --mode checkpoint \
    --checkpoints-file checkpoints.txt || exit 1

# Test 3: Known-good app launch
./dualcpu --rom mac.rom --disk test.dsk \
    --mode periodic --interval 10000 \
    --max-instructions 10000000 || exit 1

echo "✓ All regression tests passed"
```

## Common Patterns

### Pattern 1: Condition Code Bugs

```
DIVERGENCE at instruction 42,127
Instruction: SUBQ.W #1,D0
Legacy: D0=00000000, Z=1, N=0, V=0, C=0
QEMU:   D0=00000000, Z=0, N=0, V=0, C=0
                     ^^^ Bug: Zero flag not set
```

**Fix:** QEMU's condition code calculation for SUBQ is wrong

### Pattern 2: Branch Prediction Errors

```
DIVERGENCE at instruction 89,451
Instruction: BEQ.S $1234
Legacy: Z=1 → PC=00001234 (branch taken)
QEMU:   Z=1 → PC=00001236 (branch NOT taken!)
```

**Fix:** QEMU's BEQ implementation doesn't check Z flag correctly

### Pattern 3: Memory Access Issues

```
DIVERGENCE at instruction 156,892
Instruction: MOVE.L (A0)+,D0
Legacy: D0=12345678, A0=00001004, MEM_READ: 00001000=12345678
QEMU:   D0=12345678, A0=00001000, MEM_READ: 00001000=12345678
                     ^^^ Bug: A0 not incremented
```

**Fix:** QEMU's post-increment addressing mode broken

### Pattern 4: EmulOp Issues

```
DIVERGENCE at instruction 234,567
Instruction: EMUL_OP VIDEO_CONTROL
Legacy: EmulOp called, D0=00000001 (success)
QEMU:   Exception 4 (illegal instruction)
```

**Fix:** QEMU illegal instruction handler not catching EmulOps

## Timeline Integration

### Week 1: Build Harness
- Implement basic snapshot/compare
- Test with trivial programs (MOVE, ADD, NOP)

### Week 2-3: Instruction Validation
- Generate comprehensive test suite
- Run in lockstep mode
- Fix all instruction-level divergences

### Week 4-5: ROM Execution
- Run ROM boot in checkpoint mode
- Narrow divergences with periodic mode
- Fix all ROM-level issues

### Week 6-8: Full Boot
- Run full boot in trace-only mode
- Compare traces offline
- Fix remaining issues

### Week 9-10: Production
- Integrate into CI
- Add regression tests
- Performance tuning

## Conclusion

The DualCPU testing harness transforms QEMU migration from:
- ❌ "Hope it works, debug for months"

To:
- ✅ "Know exactly where it breaks, fix immediately"

**Key insight:** Running both CPUs side-by-side gives you **empirical validation** at whatever granularity you need (instruction-level, periodic, checkpoint, or offline traces).

This eliminates the "months of fucking around" and replaces it with **systematic, rapid convergence to a working implementation**.
