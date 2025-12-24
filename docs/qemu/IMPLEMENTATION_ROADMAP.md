# QEMU CPU Migration - Implementation Roadmap

## Overview

This document provides a practical, week-by-week roadmap for migrating BasiliskII and SheepShaver to QEMU CPU emulation.

**Timeline:** 16 weeks (4 months)
**Target:** BasiliskII m68k first, then SheepShaver PPC
**Approach:** Empirical validation with DualCPU testing harness

## Prerequisites

### Skills Required
- C/C++ programming
- Understanding of CPU architecture (m68k or PPC basics)
- QEMU basics (can be learned during Week 1)
- Git for version control

### Tools
- Linux development environment (macOS or WSL2 works too)
- GCC or Clang
- GDB for debugging
- LZ4 library (for trace compression)
- QEMU source code

## Phase 1: Foundation (Weeks 1-2)

### Week 1: QEMU Integration Prototype

**Goal:** Get QEMU running as a library, execute first instruction

**Tasks:**
1. **Download and build QEMU**
   ```bash
   git clone https://github.com/qemu/qemu.git
   cd qemu
   git checkout v8.2.0  # Use stable version
   mkdir build && cd build
   ../configure --target-list=m68k-softmmu \
                --enable-debug \
                --enable-pie \
                --disable-docs
   make -j$(nproc)
   ```

2. **Create minimal adapter**
   ```cpp
   // File: qemu_cpu_adapter.cpp
   #include "qemu/osdep.h"
   #include "cpu.h"
   #include "exec/exec-all.h"

   static CPUM68KState *qemu_m68k_cpu;

   void qemu_cpu_init() {
       qemu_m68k_cpu = cpu_m68k_init("m68040");
       if (!qemu_m68k_cpu) {
           fprintf(stderr, "Failed to initialize QEMU m68k CPU\n");
           exit(1);
       }
   }

   void qemu_cpu_execute_one() {
       cpu_exec(CPU(qemu_m68k_cpu));
   }
   ```

3. **Test with trivial program**
   ```cpp
   // Load simple test: MOVE.W #$1234,D0; STOP
   uint8_t test_code[] = {
       0x30, 0x3c, 0x12, 0x34,  // MOVE.W #$1234,D0
       0x4e, 0x72, 0x27, 0x00   // STOP #$2700
   };

   // Copy to QEMU memory
   cpu_physical_memory_write(0x1000, test_code, sizeof(test_code));

   // Set PC
   qemu_m68k_cpu->pc = 0x1000;

   // Execute
   qemu_cpu_execute_one();

   // Check result
   assert(qemu_m68k_cpu->dregs[0] == 0x1234);
   printf("✓ QEMU executed first instruction!\n");
   ```

**Deliverable:** QEMU can execute a simple program

**Decision Point:** If this doesn't work by end of week, investigate blocking issues

---

### Week 2: DualCPU Harness + Performance Benchmark

**Goal:** Build testing framework, verify performance is acceptable

**Tasks:**
1. **Implement DualCPU harness core**
   ```cpp
   // File: test/dual_cpu_harness.cpp
   struct DualCPUHarness {
       // Legacy CPU (UAE)
       uae_cpu *legacy_cpu;

       // QEMU CPU
       CPUM68KState *qemu_cpu;

       // Configuration
       DualCPUConfig config;

       // Statistics
       uint64_t instructions_executed;
       uint64_t divergences_found;
   };

   DualCPUHarness *dualcpu_init(DualCPUConfig *config) {
       DualCPUHarness *h = calloc(1, sizeof(*h));

       h->legacy_cpu = uae_cpu_init();
       h->qemu_cpu = cpu_m68k_init("m68040");
       h->config = *config;

       return h;
   }
   ```

2. **Implement snapshot comparison**
   ```cpp
   bool compare_snapshots(CPUSnapshot *legacy, CPUSnapshot *qemu) {
       if (legacy->pc != qemu->pc) return false;
       for (int i = 0; i < 16; i++)
           if (legacy->registers[i] != qemu->registers[i])
               return false;
       if (legacy->sr_ccr != qemu->sr_ccr) return false;
       return true;
   }
   ```

3. **Benchmark performance**
   ```bash
   # Run 1M instructions on legacy CPU
   time ./basilisk_legacy --benchmark 1000000
   # ~2.2 seconds (450K IPS)

   # Run 1M instructions on QEMU
   time ./basilisk_qemu --benchmark 1000000
   # ~3.5 seconds (285K IPS)

   # Ratio: 1.6x slower (acceptable)
   ```

**Deliverable:** DualCPU harness working, performance acceptable

**Go/No-Go Decision:** If QEMU is >3x slower, abort or investigate optimization

---

## Phase 2: Instruction Validation (Weeks 3-8)

### Week 3: Basic Arithmetic & Logic

**Goal:** Validate ADD, SUB, AND, OR, XOR, NOT, etc.

**Tasks:**
1. **Generate test suite**
   ```cpp
   // test/gen_instruction_tests.cpp
   void gen_add_tests() {
       // ADD.B D0,D1
       for (int i = 0; i < 256; i++) {
           for (int j = 0; j < 256; j++) {
               emit_test("ADD.B", {
                   .opcode = {0xd200},  // ADD.B D0,D1
                   .setup = {{"D0", i}, {"D1", j}},
                   .expect = {{"D1", (i+j) & 0xff}, {"CCR", calc_ccr(i+j)}}
               });
           }
       }
   }
   ```

2. **Run in lockstep mode**
   ```bash
   ./dualcpu --test arithmetic_tests.bin --mode lockstep
   # Output: 50,000 instructions, 0 divergences ✓
   ```

3. **Fix any divergences**
   ```
   DIVERGENCE at instruction 1,247
   Instruction: ADD.B #$FF,D0
   Legacy: D0=000000FE, Z=0, N=1, V=0, C=1
   QEMU:   D0=000000FE, Z=0, N=1, V=1, C=1
                                    ^^^ Wrong V flag
   ```

**Deliverable:** All basic ALU instructions validated

---

### Week 4: Memory Operations

**Goal:** Validate all addressing modes

**Tasks:**
1. **Test addressing modes**
   - Register direct (Dn, An)
   - Address register indirect (An)
   - Postincrement (An)+
   - Predecrement -(An)
   - Displacement (d16,An), (d8,An,Xn)
   - Absolute short/long
   - PC-relative

2. **Edge cases**
   - Boundary conditions (address 0xFFFFFFFF)
   - Unaligned access
   - Self-modifying code

**Deliverable:** All addressing modes work identically

---

### Week 5-6: Control Flow & Branches

**Goal:** Validate all branch/jump instructions

**Tasks:**
1. **Conditional branches (Bcc)**
   - All 16 conditions (T, F, HI, LS, CC, CS, NE, EQ, VC, VS, PL, MI, GE, LT, GT, LE)
   - Branch taken/not taken
   - Forward/backward branches

2. **DBcc (decrement and branch)**
   - All conditions
   - Counter reaching -1
   - Branch behavior

3. **Subroutines**
   - JSR/RTS
   - BSR
   - Nested calls
   - Stack behavior

**Deliverable:** All control flow validated

---

### Week 7-8: Exception Handling & FPU

**Goal:** Validate exceptions and floating-point

**Tasks:**
1. **Exceptions**
   - Illegal instructions
   - Privilege violations
   - Address errors
   - Division by zero
   - TRAP instructions
   - Stack frame format

2. **FPU (if needed for your ROM)**
   - Basic arithmetic (FADD, FSUB, FMUL, FDIV)
   - Transcendentals (FSIN, FCOS, FTAN, etc.)
   - FPU exceptions

**Deliverable:** Exception handling matches, FPU validated

---

## Phase 3: ROM Execution (Weeks 9-12)

### Week 9: Memory System Integration

**Goal:** Connect QEMU to BasiliskII memory

**Tasks:**
1. **Option A: Memory adapter**
   ```cpp
   static uint64_t mac_mem_read(void *opaque, hwaddr addr, unsigned size) {
       switch (size) {
           case 1: return ReadMacInt8(addr);
           case 2: return ReadMacInt16(addr);
           case 4: return ReadMacInt32(addr);
       }
   }

   static void mac_mem_write(void *opaque, hwaddr addr,
                            uint64_t val, unsigned size) {
       switch (size) {
           case 1: WriteMacInt8(addr, val); break;
           case 2: WriteMacInt16(addr, val); break;
           case 4: WriteMacInt32(addr, val); break;
       }
   }

   static const MemoryRegionOps mac_ram_ops = {
       .read = mac_mem_read,
       .write = mac_mem_write,
   };
   ```

2. **Option B: Direct mapping (if faster)**
   ```cpp
   void setup_memory() {
       MemoryRegion *ram = g_new(MemoryRegion, 1);
       memory_region_init_ram_ptr(ram, NULL, "mac.ram",
                                  RAMSize, RAMBaseHost);
       memory_region_add_subregion(system_memory, 0, ram);
   }
   ```

3. **Test memory access**
   ```bash
   ./dualcpu --test memory_stress.bin --mode periodic --interval 1000
   # All memory accesses should match
   ```

**Deliverable:** Memory system integrated and validated

---

### Week 10: EmulOp Integration

**Goal:** Connect QEMU illegal instruction handler to EmulOp system

**Tasks:**
1. **Register illegal instruction handler**
   ```cpp
   // In QEMU m68k target code
   void m68k_illegal_instruction(CPUM68KState *env, uint16_t opcode) {
       // Check if it's an EmulOp (0x71xx range)
       if ((opcode & 0xFF00) == 0x7100) {
           uint16_t selector = opcode & 0xFF;

           // Convert QEMU CPU state to M68kRegisters
           M68kRegisters regs;
           for (int i = 0; i < 8; i++) {
               regs.d[i] = env->dregs[i];
               regs.a[i] = env->aregs[i];
           }
           regs.sr = env->sr;

           // Call EmulOp handler
           EmulOp(selector, &regs);

           // Convert back
           for (int i = 0; i < 8; i++) {
               env->dregs[i] = regs.d[i];
               env->aregs[i] = regs.a[i];
           }
           env->sr = regs.sr;

           return;  // Handled
       }

       // Otherwise, real illegal instruction
       m68k_exception(env, EXCP_ILLEGAL);
   }
   ```

2. **Test EmulOps**
   ```cpp
   // Inject EMUL_OP_DEBUG_STR
   uint8_t test[] = {
       0x71, M68K_EMUL_OP_DEBUG_STR,
   };

   // Execute
   dualcpu_step();

   // Verify EmulOp was called with correct selector
   assert(last_emulop_called == M68K_EMUL_OP_DEBUG_STR);
   ```

**Deliverable:** EmulOps working through QEMU

---

### Week 11: ROM Boot Sequence

**Goal:** Boot ROM to driver initialization

**Tasks:**
1. **Run ROM boot in checkpoint mode**
   ```bash
   ./dualcpu --rom mac_rom.bin --mode checkpoint \
       --checkpoints 0x0,0x400,0x800,0x1000,0x2000
   ```

2. **Debug divergences**
   - Use binary search (checkpoint → periodic → lockstep)
   - Save state at divergence
   - Examine with trace_replay

3. **Fix ROM-specific issues**
   - Self-modifying code (ROM patches)
   - Timing-dependent loops
   - Hardware initialization

**Deliverable:** ROM boots to driver init without divergence

---

### Week 12: Full Boot to Finder

**Goal:** Complete boot to desktop

**Tasks:**
1. **Run full boot**
   ```bash
   # First pass: generate traces
   ./dualcpu --rom mac.rom --disk system.dsk \
       --mode trace-only \
       --trace-legacy boot_legacy.trace.lz4 \
       --trace-qemu boot_qemu.trace.lz4

   # Compare offline
   ./trace_diff boot_legacy.trace.lz4 boot_qemu.trace.lz4
   ```

2. **Fix remaining issues**
   - Device driver EmulOps
   - Video operations
   - Disk I/O
   - Interrupt handling

3. **Verify desktop appears**
   ```bash
   ./basilisk_qemu --rom mac.rom --disk system.dsk
   # Should see desktop with QEMU CPU!
   ```

**Deliverable:** BasiliskII boots to Finder with QEMU

**Go/No-Go Decision:** If not booting by end of Week 12, reassess

---

## Phase 4: Polish & SheepShaver (Weeks 13-16)

### Week 13: Performance Tuning

**Goal:** Optimize QEMU integration for performance

**Tasks:**
1. **Profile hot paths**
   ```bash
   perf record -g ./basilisk_qemu --benchmark
   perf report
   ```

2. **Optimize memory access**
   - Switch to direct mapping if adapter is slow
   - Reduce snapshot overhead in DualCPU mode

3. **QEMU configuration tuning**
   - TCG flags
   - TB (translation block) cache size

**Deliverable:** Performance within 2x of legacy JIT

---

### Week 14: Regression Testing

**Goal:** Build comprehensive test suite for CI

**Tasks:**
1. **Create test suite**
   ```bash
   # test/regression_suite.sh
   #!/bin/bash

   # Test 1: Instruction validation
   ./dualcpu --test instructions.bin --mode lockstep || exit 1

   # Test 2: ROM boot checkpoints
   ./dualcpu --rom mac.rom --mode checkpoint \
       --checkpoints-file boot_checkpoints.txt || exit 1

   # Test 3: Known applications
   ./dualcpu --rom mac.rom --disk test_app.dsk \
       --mode periodic --interval 10000 \
       --max-instructions 50000000 || exit 1

   echo "✓ All tests passed"
   ```

2. **Integrate with CI**
   ```yaml
   # .github/workflows/qemu_tests.yml
   name: QEMU CPU Tests
   on: [push, pull_request]
   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v2
         - name: Build QEMU
           run: make qemu
         - name: Run regression tests
           run: make test-qemu
   ```

**Deliverable:** Automated regression testing

---

### Week 15-16: SheepShaver PPC

**Goal:** Apply lessons to SheepShaver

**Tasks:**
1. **Repeat process for PPC**
   - Build QEMU PPC integration
   - Instruction validation suite
   - ROM boot
   - EmulOp integration (PPC NativeOps)

2. **Handle 68k ↔ PPC switching**
   ```cpp
   // Maintain two CPUState structures
   CPUM68KState *m68k_cpu;
   CPUPPCState *ppc_cpu;

   void execute_68k(uint32_t entry, M68kRegisters *r) {
       // Convert registers to m68k
       copy_to_m68k(m68k_cpu, r);

       // Execute until EXEC_RETURN
       m68k_cpu->pc = entry;
       cpu_exec(CPU(m68k_cpu));

       // Convert back
       copy_from_m68k(r, m68k_cpu);
   }
   ```

3. **Test PPC-specific features**
   - AltiVec (if used)
   - PPC exceptions
   - Mixed-mode applications

**Deliverable:** SheepShaver working with QEMU

---

## Milestones & Decision Points

| Week | Milestone | Go/No-Go |
|------|-----------|----------|
| 1 | QEMU executes first instruction | ✓ |
| 2 | DualCPU harness works, performance OK | ✓ Go/No-Go #1 |
| 4 | All addressing modes validated | |
| 6 | All instructions validated | |
| 8 | Exception handling works | ✓ Go/No-Go #2 |
| 10 | EmulOps integrated | |
| 12 | Boots to Finder | ✓ Go/No-Go #3 |
| 14 | Regression tests passing | |
| 16 | SheepShaver working | ✓ Final |

## Risk Management

### Week 2: Performance Too Slow
**Symptom:** QEMU >3x slower than legacy
**Action:** Investigate TCG flags, memory access optimization, or abort

### Week 8: Too Many Divergences
**Symptom:** Hundreds of instruction-level bugs
**Action:** Re-evaluate QEMU m68k target quality, consider upstream contribution

### Week 12: Doesn't Boot
**Symptom:** Crash or hang before desktop
**Action:** Use trace analysis to find divergence, may need more time

## Success Criteria

### Must Have
- ✓ Boots to Finder on BasiliskII
- ✓ All instruction tests pass
- ✓ Performance within 2x of legacy
- ✓ No known divergences in normal operation

### Should Have
- ✓ SheepShaver working
- ✓ CI regression tests
- ✓ Documentation complete

### Nice to Have
- ✓ Performance parity with legacy JIT
- ✓ ARM64 builds working
- ✓ Contribution to QEMU upstream (bug fixes found)

## Post-Migration

### Month 5: Production Hardening
- Beta testing with users
- Bug reports and fixes
- Performance profiling

### Month 6: ARM64 Support
- Test on ARM64 hardware
- Optimize for Apple Silicon
- Release ARM64 builds

### Month 7+: Maintenance
- Keep QEMU dependency updated
- Contribute bug fixes upstream
- Add more test coverage

## Resources Required

### Hardware
- x86-64 development machine
- ARM64 machine (for testing, Month 6)

### Software
- QEMU 8.2 or later
- GCC/Clang toolchain
- GDB
- LZ4 library
- Git

### Time
- 16 weeks × 20 hours/week = 320 hours
- Or 8 weeks full-time

### Backup Plan
If migration fails at any go/no-go point:
- Keep QEMU integration as experimental (`--enable-qemu-cpu` flag)
- Fall back to legacy CPU by default
- Document findings for future attempt

## Deliverables

1. **Code**
   - QEMU adapter layer
   - DualCPU testing harness
   - Instruction test generator
   - Trace analysis tools

2. **Documentation**
   - Integration guide
   - Testing procedures
   - Performance benchmarks
   - Troubleshooting guide

3. **Tests**
   - Instruction validation suite
   - ROM boot tests
   - Regression tests
   - CI integration

## Conclusion

This 16-week roadmap provides a structured, empirically-validated path to QEMU CPU migration. The DualCPU testing harness ensures we catch all divergences immediately, avoiding "months of fucking around" with mysterious bugs.

**Key principle:** Validate continuously, fix immediately, progress systematically.
