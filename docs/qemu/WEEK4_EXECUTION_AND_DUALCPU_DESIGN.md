# Week 4: Execution Loop and DualCPU Design (CORRECTED)

**Date**: December 24, 2025
**Status**: 📋 **DESIGN PHASE - REVISED**
**Session**: 4
**Revision**: 2 - Corrected memory architecture and JIT approach

## Critical Design Corrections

**Two major architectural clarifications:**

1. **DualCPU MUST use separate memory** - Not shared memory
   - Each CPU needs independent RAM/ROM copies
   - Prevents false positives from memory side effects
   - Enables true validation of memory operations

2. **JIT disabled during validation** - Interpreter-only for DualCPU
   - DualCPU testing: Interpreter mode only (deterministic)
   - Production: QEMU with JIT enabled (after validation)
   - Don't validate QEMU's JIT - it's battle-tested

---

## Part 1: QEMU Execution Loop

### Current UAE Architecture (Baseline)

From [BasiliskII/src/uae_cpu/basilisk_glue.cpp](../../BasiliskII/src/uae_cpu/basilisk_glue.cpp):

```cpp
// UAE execution flow
void Start680x0(void) {
    m68k_reset();           // Reset CPU state
#if USE_JIT
    if (UseJIT)
        m68k_compile_execute();  // JIT execution loop
    else
#endif
        m68k_execute();     // Interpreter loop (never returns)
}
```

**Key observations**:
- `Start680x0()` **does not return** - it's the main loop
- UAE has two execution modes: interpreter and JIT
- `quit_program` flag is used to exit the loop
- EmulOps are handled via `m68k_emulop()` callback

### QEMU Execution Loop Design

**For Weeks 4-12: Interpreter mode only, JIT disabled**

```cpp
// Ensure JIT is disabled during validation
#if USE_JIT
#error "DualCPU testing requires JIT disabled! Set USE_JIT=0"
#endif
```

#### API Functions to Implement

```cpp
/*
 * Start QEMU CPU execution (main loop)
 * Interpreter mode only during validation phase
 */
void Start680x0_QEMU(void);

/*
 * Execute ONE instruction and return (for DualCPU)
 * This is the key for lockstep validation
 */
void QEMU_ExecuteOne(void);

/*
 * Execute 68k subroutine (from EmulOp handlers)
 */
void Execute68k_QEMU(uint32 addr, M68kRegisters *r);

/*
 * Execute 68k trap (from EmulOp handlers)
 */
void Execute68kTrap_QEMU(uint16 trap, M68kRegisters *r);
```

#### Implementation: QEMU_ExecuteOne()

**This is the critical function for DualCPU testing:**

```cpp
void QEMU_ExecuteOne(void)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    // Force single-step mode (one instruction only)
    CPUState *cpu = CPU(qemu_cpu);
    cpu->singlestep_enabled = true;

    // Execute exactly ONE instruction
    cpu_exec(cpu);

    // cpu_exec returns immediately after one instruction
    // when singlestep_enabled is true
}
```

#### Implementation: Start680x0_QEMU()

```cpp
void Start680x0_QEMU(void)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    D(bug("Start680x0_QEMU: Starting INTERPRETER execution loop\n"));

    // Verify JIT is disabled
    #if USE_JIT
    fprintf(stderr, "ERROR: JIT must be disabled for initial validation!\n");
    return;
    #endif

    // Set initial PC from ROM reset vector
    uint32_t initial_sp = ReadMacInt32(0x00400000);
    uint32_t initial_pc = ReadMacInt32(0x00400004);

    qemu_env->aregs[7] = initial_sp;
    qemu_env->pc = initial_pc;
    qemu_env->sr = 0x2700;

    D(bug("QEMU: Initial SP=0x%08x PC=0x%08x\n", initial_sp, initial_pc));

    quit_program = false;

    while (!quit_program) {
        // Execute in blocks (when not in DualCPU mode)
        int ret = cpu_exec(CPU(qemu_cpu));

        if (ret == EXCP_INTERRUPT) {
            continue;
        } else if (ret == EXCP_HLT) {
            D(bug("QEMU: CPU halted\n"));
        } else if (ret < 0) {
            fprintf(stderr, "QEMU: cpu_exec error %d\n", ret);
            quit_program = true;
        }
    }

    D(bug("Start680x0_QEMU: Execution loop exited\n"));
}
```

#### EmulOp Hook Updates

```cpp
static bool emulop_hook_handler(CPUM68KState *env, uint16_t opcode)
{
    if ((opcode & 0xFF00) != 0x7100) {
        return false;
    }

    uint16_t selector = opcode & 0xFF;

    // Handle M68K_EXEC_RETURN (0x7100)
    if (selector == 0x00) {
        D(bug("EmulOp: M68K_EXEC_RETURN\n"));
        quit_program = true;
        env->pc += 2;
        return true;
    }

    // Regular EmulOp handling
    M68kRegisters regs;
    copy_regs_from_qemu(&regs, env);
    EmulOp(selector, &regs);
    copy_regs_to_qemu(env, &regs);
    env->pc += 2;

    return true;
}
```

---

## Part 2: DualCPU Testing Harness (CORRECTED)

### Architecture Overview - Separate Memory!

**Critical: Each CPU has its own memory copy**

```
┌─────────────────────────────────────────────────────────────┐
│              DualCPU Main Loop (single thread)               │
│                  (Interpreter mode only)                     │
└────────────┬────────────────────────────┬────────────────────┘
             │                            │
             ↓                            ↓
  ┌──────────────────────┐    ┌──────────────────────┐
  │     UAE CPU          │    │     QEMU CPU         │
  │  (Interpreter)       │    │  (Interpreter)       │
  ├──────────────────────┤    ├──────────────────────┤
  │ • Own registers      │    │ • Own registers      │
  │ • Own RAM copy       │    │ • Own RAM copy       │
  │ • Own ROM copy       │    │ • Own ROM copy       │
  │ • Execute ONE instr  │    │ • Execute ONE instr  │
  └──────────┬───────────┘    └──────────┬───────────┘
             │                           │
             │  Independent memory       │
             │  (no interference!)       │
             └────────────┬──────────────┘
                          ↓
               ┌──────────────────────┐
               │  Comparison Engine   │
               ├──────────────────────┤
               │ • Compare PC         │
               │ • Compare registers  │
               │ • Compare SR         │
               │ • Compare MEMORY     │ ← NEW!
               └──────────────────────┘
```

### DualCPU Memory Architecture

```cpp
struct DualCPUMemory {
    // UAE's memory (separate allocation)
    uint8_t *uae_ram;
    uint8_t *uae_rom;
    uint32_t ram_size;
    uint32_t rom_size;

    // QEMU's memory (separate allocation)
    uint8_t *qemu_ram;
    uint8_t *qemu_rom;

    // Memory comparison stats
    uint32_t num_memory_divergences;
    uint32_t first_divergence_addr;
};
```

### DualCPU State Structure

```cpp
struct DualCPUState {
    // Execution mode (interpreter only!)
    bool interpreter_mode;  // MUST be true

    // Memory (separate for each CPU)
    DualCPUMemory memory;

    // CPU states (separate for each CPU)
    struct regstruct *uae_regs;   // UAE's register state
    CPUM68KState *qemu_env;       // QEMU's register state

    // Comparison control
    uint64_t instr_count;
    bool diverged;
    bool abort_on_divergence;

    // Statistics
    uint64_t register_divergences;
    uint64_t memory_divergences;
    uint64_t pc_divergences;
};
```

### DualCPU Initialization (CORRECTED)

```cpp
bool DualCPU_Init(void)
{
    printf("Initializing DualCPU testing harness\n");

    // Verify JIT is disabled
    #if USE_JIT
    fprintf(stderr, "ERROR: DualCPU requires JIT disabled!\n");
    fprintf(stderr, "       Rebuild with USE_JIT=0\n");
    return false;
    #endif

    // Allocate SEPARATE memory for each CPU
    dualcpu.memory.ram_size = RAMSize;
    dualcpu.memory.rom_size = ROMSize;

    // UAE's memory
    dualcpu.memory.uae_ram = (uint8_t *)malloc(RAMSize);
    dualcpu.memory.uae_rom = (uint8_t *)malloc(ROMSize);

    // QEMU's memory (separate allocation!)
    dualcpu.memory.qemu_ram = (uint8_t *)malloc(RAMSize);
    dualcpu.memory.qemu_rom = (uint8_t *)malloc(ROMSize);

    if (!dualcpu.memory.uae_ram || !dualcpu.memory.qemu_ram ||
        !dualcpu.memory.uae_rom || !dualcpu.memory.qemu_rom) {
        fprintf(stderr, "ERROR: Failed to allocate DualCPU memory\n");
        return false;
    }

    // Load ROM image into temporary buffer
    uint8_t *rom_image = load_rom_image();

    // Copy SAME initial state to both CPUs
    memset(dualcpu.memory.uae_ram, 0, RAMSize);
    memset(dualcpu.memory.qemu_ram, 0, RAMSize);
    memcpy(dualcpu.memory.uae_rom, rom_image, ROMSize);
    memcpy(dualcpu.memory.qemu_rom, rom_image, ROMSize);

    printf("DualCPU: Allocated separate memory:\n");
    printf("  UAE  RAM: %p (size 0x%x)\n", dualcpu.memory.uae_ram, RAMSize);
    printf("  QEMU RAM: %p (size 0x%x)\n", dualcpu.memory.qemu_ram, RAMSize);
    printf("  Memory copies are INDEPENDENT\n");

    // Initialize UAE CPU with its memory
    RAMBaseHost = dualcpu.memory.uae_ram;
    ROMBaseHost = dualcpu.memory.uae_rom;
    UseJIT = false;  // Force interpreter
    Init680x0();

    // Initialize QEMU CPU with its memory (separate!)
    Init680x0_QEMU();
    QEMU_SetupMemory(dualcpu.memory.qemu_ram, RAMSize,
                     dualcpu.memory.qemu_rom, ROMSize);

    // Set both CPUs to SAME initial state
    uint32_t initial_sp = ReadMacInt32_UAE(0x00400000);  // From UAE's ROM
    uint32_t initial_pc = ReadMacInt32_UAE(0x00400004);

    // UAE initial state
    m68k_setpc(initial_pc);
    m68k_areg(regs, 7) = initial_sp;
    regs.sr = 0x2700;

    // QEMU initial state (SAME values)
    qemu_env->pc = initial_pc;
    qemu_env->aregs[7] = initial_sp;
    qemu_env->sr = 0x2700;

    // Verify initial memory is identical
    if (memcmp(dualcpu.memory.uae_ram, dualcpu.memory.qemu_ram, RAMSize) != 0) {
        fprintf(stderr, "ERROR: Initial RAM not identical!\n");
        return false;
    }

    printf("DualCPU: Both CPUs initialized to PC=0x%08x SP=0x%08x\n",
           initial_pc, initial_sp);
    printf("DualCPU: Ready for lockstep execution\n");

    dualcpu.interpreter_mode = true;
    dualcpu.instr_count = 0;
    dualcpu.diverged = false;

    return true;
}
```

### DualCPU Main Loop (CORRECTED)

```cpp
void Start680x0_DualCPU(void)
{
    printf("Starting DualCPU lockstep validation\n");
    printf("Mode: Interpreter only (JIT disabled)\n\n");

    quit_program = false;

    while (!quit_program) {
        // Execute ONE instruction on UAE (interpreter)
        UAE_ExecuteOne();

        // Execute ONE instruction on QEMU (interpreter)
        QEMU_ExecuteOne();

        dualcpu.instr_count++;

        // Compare CPU states
        if (!DualCPU_CompareStates()) {
            printf("\n╔══════════════════════════════════════════╗\n");
            printf("║  CPU STATE DIVERGENCE at instr %llu    ║\n",
                   dualcpu.instr_count);
            printf("╚══════════════════════════════════════════╝\n");

            DualCPU_DumpDivergence();

            if (dualcpu.abort_on_divergence) {
                abort();
            }

            dualcpu.diverged = true;
        }

        // Compare memory (every N instructions to reduce overhead)
        if (dualcpu.instr_count % 1000 == 0) {
            if (!DualCPU_CompareMemory()) {
                printf("\n╔══════════════════════════════════════════╗\n");
                printf("║  MEMORY DIVERGENCE at instr %llu       ║\n",
                       dualcpu.instr_count);
                printf("╚══════════════════════════════════════════╝\n");

                DualCPU_DumpMemoryDivergence();

                if (dualcpu.abort_on_divergence) {
                    abort();
                }

                dualcpu.diverged = true;
            }
        }

        // Progress indicator
        if (dualcpu.instr_count % 10000 == 0) {
            printf("\r  %llu instructions - states match", dualcpu.instr_count);
            fflush(stdout);
        }
    }

    printf("\n\nDualCPU execution completed:\n");
    printf("  Total instructions: %llu\n", dualcpu.instr_count);
    printf("  Register divergences: %llu\n", dualcpu.register_divergences);
    printf("  Memory divergences: %llu\n", dualcpu.memory_divergences);

    if (!dualcpu.diverged) {
        printf("\n✓ SUCCESS: UAE and QEMU execution IDENTICAL!\n");
    }
}
```

### Memory Comparison

```cpp
bool DualCPU_CompareMemory(void)
{
    // Compare entire RAM
    if (memcmp(dualcpu.memory.uae_ram,
               dualcpu.memory.qemu_ram,
               dualcpu.memory.ram_size) == 0) {
        return true;  // Identical
    }

    // Find divergences
    dualcpu.memory.num_memory_divergences = 0;

    for (uint32_t addr = 0; addr < dualcpu.memory.ram_size; addr++) {
        if (dualcpu.memory.uae_ram[addr] != dualcpu.memory.qemu_ram[addr]) {
            if (dualcpu.memory.num_memory_divergences == 0) {
                dualcpu.memory.first_divergence_addr = addr;
            }
            dualcpu.memory.num_memory_divergences++;
        }
    }

    dualcpu.memory_divergences++;
    return false;
}

void DualCPU_DumpMemoryDivergence(void)
{
    printf("\nMemory divergence details:\n");
    printf("  Total different bytes: %u\n",
           dualcpu.memory.num_memory_divergences);
    printf("  First divergence at: 0x%08x\n",
           dualcpu.memory.first_divergence_addr);

    // Show first 10 divergences
    uint32_t count = 0;
    for (uint32_t addr = 0; addr < dualcpu.memory.ram_size && count < 10; addr++) {
        if (dualcpu.memory.uae_ram[addr] != dualcpu.memory.qemu_ram[addr]) {
            printf("  0x%08x: UAE=0x%02x QEMU=0x%02x\n",
                   addr,
                   dualcpu.memory.uae_ram[addr],
                   dualcpu.memory.qemu_ram[addr]);
            count++;
        }
    }

    if (dualcpu.memory.num_memory_divergences > 10) {
        printf("  ... and %u more\n",
               dualcpu.memory.num_memory_divergences - 10);
    }
}
```

### UAE Single-Step Function

```cpp
void UAE_ExecuteOne(void)
{
    // UAE's internal single-step execution
    // This already exists in UAE as m68k_do_execute()

    uae_u16 opcode = get_iword(0);  // Fetch from PC
    regs.pc += 2;                    // Advance PC

    // Execute instruction handler
    (*cpufunctbl[opcode])(opcode);

    // Returns after ONE instruction
}
```

---

## JIT Strategy (Revised)

### Phase 1: Interpreter Validation (Weeks 4-12)

**All testing with JIT DISABLED:**

```cpp
// Build configuration for validation phase
#define USE_JIT 0           // Disable UAE JIT
#define USE_QEMU_CPU 1      // Enable QEMU
#define USE_DUALCPU 1       // Enable DualCPU testing

// Both CPUs use pure interpreters
// Deterministic, lockstep execution
// Perfect for validation
```

### Phase 2: QEMU Production (Weeks 13-16)

**Switch to QEMU with JIT enabled:**

```cpp
// Build configuration for production
#define USE_JIT 0           // Still no UAE (we're migrating away)
#define USE_QEMU_CPU 1      // QEMU only
#define USE_DUALCPU 0       // DualCPU testing complete

// QEMU's TCG JIT automatically enabled
// Full performance
// Validation already complete
```

### Why This Works

**Interpreter validation is sufficient:**
- ✅ If QEMU interpreter matches UAE interpreter → CPU emulation is correct
- ✅ QEMU's TCG JIT is proven technology (used by millions)
- ✅ Don't need to validate QEMU's JIT ourselves
- ✅ JIT is optimization, not correctness feature

**Production with QEMU JIT:**
- QEMU's TCG generates optimized native code
- ARM64 JIT works automatically
- Performance comparable to UAE's JIT
- Battle-tested across many architectures

---

## Implementation Checklist (Updated)

### Week 4 Tasks - QEMU Execution Loop

- [x] Research UAE execution loop ✅
- [ ] Implement `QEMU_ExecuteOne()` (single-step)
- [ ] Implement `Start680x0_QEMU()` (interpreter mode)
- [ ] Implement `Execute68k_QEMU()`
- [ ] Implement `Execute68kTrap_QEMU()`
- [ ] Update EmulOp hook for M68K_EXEC_RETURN
- [ ] Verify JIT is disabled in build

### Week 5 Tasks - DualCPU Harness

- [ ] Create `dualcpu_harness.cpp`
- [ ] Implement separate memory allocation
- [ ] Implement `DualCPU_Init()` with memory setup
- [ ] Implement `DualCPU_CompareStates()`
- [ ] Implement `DualCPU_CompareMemory()`
- [ ] Implement `Start680x0_DualCPU()` main loop
- [ ] Test with simple instruction sequence

### Week 6-8 Tasks - Instruction Validation

- [ ] Run comprehensive instruction tests
- [ ] Validate all addressing modes
- [ ] Validate all arithmetic operations
- [ ] Validate branch instructions
- [ ] Document any divergences found

### Week 9-12 Tasks - ROM Boot

- [ ] Boot Mac ROM with DualCPU
- [ ] Compare at key checkpoints
- [ ] Debug any divergences
- [ ] Full boot to Finder validation

### Week 13+ Tasks - Production

- [ ] Disable DualCPU
- [ ] Enable QEMU TCG JIT
- [ ] Performance benchmarking
- [ ] Production testing

---

## Testing Strategy (Updated)

### Phase 1: Simple Execution (Week 4)

```cpp
// Test: MOVE, ADD, RTS
uint8_t test[] = {
    0x30, 0x3c, 0x12, 0x34,  // MOVE.W #$1234,D0
    0x32, 0x3c, 0x56, 0x78,  // MOVE.W #$5678,D1
    0xD0, 0x41,              // ADD.W  D1,D0
    0x71, 0x00               // M68K_EXEC_RETURN
};

// Load to BOTH memory copies
memcpy(uae_ram + 0x1000, test, sizeof(test));
memcpy(qemu_ram + 0x1000, test, sizeof(test));

// Execute with DualCPU
Start680x0_DualCPU();

// Expected: Both CPUs produce identical results
// D0 = 0x68AC, memory unchanged
```

### Phase 2: Memory Operations (Week 5)

```cpp
// Test: Memory read/write
uint8_t test[] = {
    0x21, 0xFC, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x20, 0x00,
    // MOVE.L #$DEADBEEF,$2000

    0x20, 0x38, 0x20, 0x00,  // MOVE.L $2000,D0
    0x71, 0x00               // M68K_EXEC_RETURN
};

// After execution, both memories should have:
// - Address 0x2000: 0xDEADBEEF
// - D0: 0xDEADBEEF
```

### Phase 3: Full Instruction Set (Weeks 6-8)

Comprehensive validation of all m68k instructions with DualCPU.

---

## Performance Considerations (Updated)

### DualCPU Overhead

| Mode | Overhead | Reason |
|------|----------|--------|
| Interpreter only | ~3x slower | Normal interpreter penalty |
| DualCPU lockstep | ~6x slower | 2x CPUs + comparison overhead |
| Memory comparison | +10% | memcmp every 1000 instructions |

**This is acceptable for validation!** Not used in production.

### Production Performance

| Mode | Speed | Notes |
|------|-------|-------|
| UAE interpreter | 1x (baseline) | Reference speed |
| UAE JIT | 5-10x | Current production |
| QEMU interpreter | ~1x | Similar to UAE |
| QEMU TCG JIT | 5-10x | Target production |

---

## Summary of Changes

**Major corrections:**

1. **Separate memory architecture**
   - Each CPU has independent RAM/ROM copies
   - Prevents false positives from memory interference
   - Enables true validation of memory operations
   - Added `DualCPU_CompareMemory()`

2. **Interpreter-only for validation**
   - JIT disabled during Weeks 4-12
   - DualCPU works with deterministic interpreters
   - QEMU JIT enabled Week 13+ for production
   - Don't need to validate QEMU's JIT

3. **Single-step execution**
   - Added `UAE_ExecuteOne()` and `QEMU_ExecuteOne()`
   - One main loop calls both in lockstep
   - Not two separate loops running in parallel

**Ready for implementation!** 🚀

---

## References

- [BasiliskII UAE CPU](../../BasiliskII/src/uae_cpu/basilisk_glue.cpp)
- [QEMU m68k Target](../../qemu/target/m68k/)
- [DualCPU Testing Approach](DUALCPU_TESTING_APPROACH.md)
- [Week 3 Memory Integration](WEEK3_MEMORY_INTEGRATION.md)
