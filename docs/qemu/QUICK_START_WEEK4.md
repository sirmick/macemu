# Quick Start: Week 4 Implementation

**Goal**: Implement QEMU execution loop and create first working execution test

## Step 1: Implement Start680x0_QEMU() (30 min)

Edit [qemu-cpu/qemu_m68k_adapter.cpp](../../qemu-cpu/qemu_m68k_adapter.cpp):

```cpp
// Add at top with other externs
extern bool quit_program;

// Replace stub Start680x0_QEMU() function (around line 257)
void Start680x0_QEMU(void)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    D(bug("Start680x0_QEMU: Starting main execution loop\n"));

    // Set initial PC from ROM reset vector
    uint32_t initial_sp = ReadMacInt32(0x00400000);
    uint32_t initial_pc = ReadMacInt32(0x00400004);

    qemu_env->aregs[7] = initial_sp;
    qemu_env->pc = initial_pc;
    qemu_env->sr = 0x2700;

    D(bug("QEMU: Initial SP=0x%08x PC=0x%08x\n", initial_sp, initial_pc));

    quit_program = false;

    while (!quit_program) {
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

## Step 2: Update EmulOp Hook (15 min)

Update `emulop_hook_handler()` in same file (around line 55):

```cpp
static bool emulop_hook_handler(CPUM68KState *env, uint16_t opcode)
{
    if ((opcode & 0xFF00) != 0x7100) {
        return false;
    }

    uint16_t selector = opcode & 0xFF;

    // NEW: Handle M68K_EXEC_RETURN (0x7100)
    if (selector == 0x00) {
        D(bug("EmulOp: M68K_EXEC_RETURN\n"));
        quit_program = true;
        env->pc += 2;
        return true;
    }

    // Rest of existing code...
    D(bug("EmulOp: 0x%04x selector=0x%02x\n", opcode, selector));

    M68kRegisters regs;
    copy_regs_from_qemu(&regs, env);
    EmulOp(selector, &regs);
    copy_regs_to_qemu(env, &regs);
    env->pc += 2;

    return true;
}
```

## Step 3: Implement Execute68k_QEMU() (30 min)

Replace stub (around line 278):

```cpp
void Execute68k_QEMU(uint32 addr, M68kRegisters *r)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    D(bug("Execute68k_QEMU: addr=0x%08x\n", addr));

    uint32_t old_pc = qemu_env->pc;

    copy_regs_to_qemu(qemu_env, r);

    // Push M68K_EXEC_RETURN and return address
    qemu_env->aregs[7] -= 2;
    WriteMacInt16(qemu_env->aregs[7], M68K_EXEC_RETURN);
    qemu_env->aregs[7] -= 4;
    WriteMacInt32(qemu_env->aregs[7], qemu_env->aregs[7] + 4);

    qemu_env->pc = addr;

    quit_program = false;

    while (!quit_program) {
        int ret = cpu_exec(CPU(qemu_cpu));
        if (ret < 0 && ret != EXCP_INTERRUPT && ret != EXCP_HLT) {
            fprintf(stderr, "QEMU: Execute68k failed: %d\n", ret);
            break;
        }
    }

    // Clean up stack
    qemu_env->aregs[7] += 2;
    qemu_env->pc = old_pc;

    copy_regs_from_qemu(r, qemu_env);
    quit_program = false;
}
```

## Step 4: Implement Execute68kTrap_QEMU() (15 min)

Replace stub (around line 305):

```cpp
void Execute68kTrap_QEMU(uint16 trap, M68kRegisters *r)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    D(bug("Execute68kTrap_QEMU: trap=0x%04x\n", trap));

    uint32_t old_pc = qemu_env->pc;

    copy_regs_to_qemu(qemu_env, r);

    // Push trap and M68K_EXEC_RETURN
    qemu_env->aregs[7] -= 2;
    WriteMacInt16(qemu_env->aregs[7], M68K_EXEC_RETURN);
    qemu_env->aregs[7] -= 2;
    WriteMacInt16(qemu_env->aregs[7], trap);

    qemu_env->pc = qemu_env->aregs[7];

    quit_program = false;

    while (!quit_program) {
        int ret = cpu_exec(CPU(qemu_cpu));
        if (ret < 0 && ret != EXCP_INTERRUPT && ret != EXCP_HLT) {
            fprintf(stderr, "QEMU: Execute68kTrap failed: %d\n", ret);
            break;
        }
    }

    qemu_env->aregs[7] += 4;
    qemu_env->pc = old_pc;

    copy_regs_from_qemu(r, qemu_env);
    quit_program = false;
}
```

## Step 5: Implement TriggerInterrupt_QEMU() (10 min)

Replace stubs (around line 327):

```cpp
void TriggerInterrupt_QEMU(void)
{
    if (!qemu_env) {
        return;
    }

    D(bug("TriggerInterrupt_QEMU\n"));
    cpu_interrupt(CPU(qemu_cpu), CPU_INTERRUPT_HARD);
}

void TriggerNMI_QEMU(void)
{
    if (!qemu_env) {
        return;
    }

    D(bug("TriggerNMI_QEMU\n"));
    cpu_interrupt(CPU(qemu_cpu), CPU_INTERRUPT_HARD);
}
```

## Step 6: Create Test Program (20 min)

Create [test/qemu-poc/test_execution.c](../../test/qemu-poc/test_execution.c):

```c
/*
 * QEMU Execution Loop Test
 * Tests basic m68k code execution via Execute68k_QEMU()
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

// Minimal BasiliskII types
typedef uint32_t uint32;
typedef uint16_t uint16;
typedef uint8_t uint8;

struct M68kRegisters {
    uint32 d[8];
    uint32 a[8];
    uint16 sr;
};

// Adapter functions
extern bool Init680x0_QEMU(void);
extern void Exit680x0_QEMU(void);
extern void QEMU_SetupMemory(uint8 *ram, uint32 ram_size,
                             uint8 *rom, uint32 rom_size);
extern void Execute68k_QEMU(uint32 addr, struct M68kRegisters *r);

// Memory
#define RAM_SIZE (16 * 1024 * 1024)
#define ROM_SIZE (1 * 1024 * 1024)

uint8 *RAMBaseHost;
uint8 *ROMBaseHost;

// Simple helpers
static void WriteMacInt16(uint32 addr, uint16 val) {
    RAMBaseHost[addr] = val >> 8;
    RAMBaseHost[addr+1] = val & 0xFF;
}

int main(void)
{
    printf("=== QEMU Execution Loop Test ===\n\n");

    // Allocate memory
    RAMBaseHost = malloc(RAM_SIZE);
    ROMBaseHost = malloc(ROM_SIZE);
    memset(RAMBaseHost, 0, RAM_SIZE);
    memset(ROMBaseHost, 0, ROM_SIZE);

    // Initialize QEMU
    if (!Init680x0_QEMU()) {
        fprintf(stderr, "Failed to init QEMU\n");
        return 1;
    }

    QEMU_SetupMemory(RAMBaseHost, RAM_SIZE, ROMBaseHost, ROM_SIZE);

    // Test program: MOVE.W #$1234,D0; MOVE.W #$5678,D1; ADD.W D1,D0; RTS
    uint8_t test[] = {
        0x30, 0x3c, 0x12, 0x34,  // MOVE.W #$1234,D0
        0x32, 0x3c, 0x56, 0x78,  // MOVE.W #$5678,D1
        0xD0, 0x41,              // ADD.W  D1,D0
        0x71, 0x00               // M68K_EXEC_RETURN (0x7100)
    };

    // Copy to RAM at 0x1000
    memcpy(RAMBaseHost + 0x1000, test, sizeof(test));

    printf("Test program loaded at 0x1000\n");
    printf("Executing...\n\n");

    // Execute
    struct M68kRegisters regs = {0};
    Execute68k_QEMU(0x1000, &regs);

    printf("Results:\n");
    printf("  D0 = 0x%08x (expected 0x00001234 initially)\n", regs.d[0]);
    printf("  D1 = 0x%08x (expected 0x00005678)\n", regs.d[1]);
    printf("  After ADD.W D1,D0: D0 should be 0x000068AC\n\n");

    // Verify
    if (regs.d[0] == 0x68AC && regs.d[1] == 0x5678) {
        printf("✓ TEST PASSED!\n");
        printf("  QEMU correctly executed m68k instructions\n");
    } else {
        printf("✗ TEST FAILED!\n");
        printf("  D0 = 0x%08x (expected 0x68AC)\n", regs.d[0]);
        printf("  D1 = 0x%08x (expected 0x5678)\n", regs.d[1]);
    }

    Exit680x0_QEMU();
    free(RAMBaseHost);
    free(ROMBaseHost);

    return (regs.d[0] == 0x68AC) ? 0 : 1;
}
```

## Step 7: Update Makefile (10 min)

Add to [test/qemu-poc/Makefile](../../test/qemu-poc/Makefile):

```makefile
# Execution test (compile only for now)
test_execution_compile:
	@echo "Compiling execution test..."
	$(CC) $(CFLAGS) -I../../qemu-cpu -c test_execution.c -o test_execution.o
	@echo "✓ Execution test compiles!"
```

## Step 8: Test Compilation (5 min)

```bash
cd test/qemu-poc
make test_execution_compile
```

## Total Time: ~2 hours

## Success Criteria

After these steps:
- ✅ All code compiles without errors
- ✅ Execution functions implemented
- ✅ EmulOp hook handles M68K_EXEC_RETURN
- ✅ Test program ready

## Next Steps

1. **Build system integration** - Link test program with QEMU libs
2. **Run test** - Execute and verify results
3. **Debug** - Fix any issues
4. **Document** - Update WEEK4 docs with results

## Troubleshooting

**Problem**: `quit_program` not declared
- **Solution**: Add `extern bool quit_program;` at top of file

**Problem**: `cpu_exec` not found
- **Solution**: Check QEMU includes, may need `#include "exec/cpu-all.h"`

**Problem**: `M68K_EXEC_RETURN` not defined
- **Solution**: Add `#define M68K_EXEC_RETURN 0x7100` or include emul_op.h

**Problem**: Test compilation fails
- **Solution**: This is expected - full linking needs build system integration

## References

- [WEEK4_EXECUTION_AND_DUALCPU_DESIGN.md](WEEK4_EXECUTION_AND_DUALCPU_DESIGN.md) - Complete design
- [qemu_m68k_adapter.cpp](../../qemu-cpu/qemu_m68k_adapter.cpp) - File to edit
- [UAE basilisk_glue.cpp](../../BasiliskII/src/uae_cpu/basilisk_glue.cpp) - Reference implementation

---

**Ready to code!** 🚀
