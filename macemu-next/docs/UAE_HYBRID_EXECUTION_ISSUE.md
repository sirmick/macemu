# UAE Hybrid Execution Issue - 175k Crash Root Cause

## Problem
Unicorn backend crashes at exactly 175,170 instructions with SIGSEGV. The crash location is **not** at 0xFFFFFFFE/0xFFFFFFFC as initially thought.

## Root Cause - NOT Unmapped Memory

The unmapped memory hypothesis was incorrect. The crash is **NOT** from Unicorn trying to access unmapped addresses. GDB stack trace reveals the true issue:

```
Thread 1 "macemu-next" received signal SIGSEGV, Segmentation fault.
0x000055555572613a in m68k_do_execute () at ../src/cpu/uae_cpu/newcpu.cpp:1451
1451			uae_u32 opcode = GET_OPCODE;

#0  m68k_do_execute() at newcpu.cpp:1451       <- UAE CPU executing
#1  m68k_execute()
#2  Execute68kTrap() at basilisk_glue.cpp:216   <- UAE trap handler
#3  InstallDrivers(pb=16779798) at rom_patches.cpp:718
#4  EmulOp(opcode=28938) at emul_op.cpp:342     <- EmulOp 0x712A (28938)
#5  unicorn_platform_emulop_handler()
#6  hook_insn_invalid()                         <- Unicorn EmulOp hook
#7  cpu_exec_m68k()                             <- Unicorn internals
#8  uc_emu_start()
#9  unicorn_execute_one()
#10 unicorn_backend_execute_one()
```

## The Real Issue: Hybrid Execution

### Execution Flow:
1. **Unicorn** is running at instruction 175,165
2. **Unicorn** encounters EmulOp 0x712A at PC=0x02009A08
3. **unicorn_platform_emulop_handler()** calls `EmulOp(0x712A, regs)`
4. **EmulOp()** routes to `InstallDrivers()` (ROM patch code)
5. **InstallDrivers()** calls `Execute68kTrap()` to execute M68K trap
6. **Execute68kTrap()** **switches to UAE CPU** to run the trap handler
7. **UAE's m68k_do_execute()** tries to fetch opcode via `GET_OPCODE`
8. **CRASH** - UAE's memory system isn't initialized

### Why UAE Memory System Fails:

When running in Unicorn-only mode (`CPU_BACKEND=unicorn`):
- Unicorn has its own memory system (via `uc_mem_map`, `uc_mem_read`, `uc_mem_write`)
- UAE CPU backend is **not initialized** (no `memory_init()` called)
- UAE's `mem_banks[]` array is **uninitialized/invalid**
- When `Execute68kTrap()` calls into UAE, `GET_OPCODE` macro tries to read from `mem_banks[]`
- This accesses invalid memory → SIGSEGV

### The Hybrid Execution Pattern:

Some EmulOps need to execute 68K code (traps, ROM patches). The code uses `Execute68kTrap()` which assumes UAE CPU backend is available:

**[src/cpu/uae_cpu/basilisk_glue.cpp:216](macemu-next/src/cpu/uae_cpu/basilisk_glue.cpp#L216)**:
```cpp
void Execute68kTrap(uint16_t trap, M68kRegisters *r) {
    // ... setup registers ...
    m68k_execute();  // Execute UAE CPU!
    // ... copy registers back ...
}
```

This works fine when:
- Running pure UAE backend (`CPU_BACKEND=uae`)
- Running DualCPU backend (both UAE and Unicorn initialized)

This **crashes** when:
- Running pure Unicorn backend (`CPU_BACKEND=unicorn`)
- UAE memory system not initialized
- `Execute68kTrap()` called from EmulOp handler

## Evidence

### Instruction Trace:
```
[175165] 02009A18 4E75  <- RTS from previous function
[175166] 0200038A 43FA  <- Returns to caller
[175167] 0200038E 4E75  <- RTS
[175168] 0200113E 2149  <- Back in ROM code
[175169] 02001142 710A  <- Move #10 to D1
[CRASH - never reaches instruction 175170]
```

### Last EmulOp Before Crash:
```
EmulOp 712c
RTC write op 13, d1 00000035 d2 ffffffd5
```

EmulOp 0x712C calls `InstallDrivers()` which tries to execute a 68K trap via UAE.

## Solution Options

### Option 1: Always Initialize UAE Memory System (Simplest)
Even when running `CPU_BACKEND=unicorn`, initialize UAE's memory system:
- Call `memory_init()` to set up `mem_banks[]`
- Map RAM/ROM into UAE's address space
- This allows `Execute68kTrap()` to work

**Pros**: Minimal code changes, fixes hybrid execution
**Cons**: Memory overhead (UAE and Unicorn both have full memory maps)

### Option 2: Implement Trap Execution in Unicorn
Replace `Execute68kTrap()` with Unicorn-native trap execution:
- When Unicorn backend is active, use `uc_emu_start()` for traps
- Don't call into UAE code at all

**Pros**: Clean separation, no UAE dependency
**Cons**: Significant refactoring required

### Option 3: Avoid EmulOps That Need Traps (Hack)
Skip or stub out EmulOps that call `Execute68kTrap()`:
- Detect 0x712C and other problematic EmulOps
- Return early without executing trap

**Pros**: Quick workaround
**Cons**: ROM patches may not work, incomplete emulation

## Recommended Approach

**Option 1** is recommended:
1. Initialize UAE memory system even for Unicorn-only mode
2. This maintains compatibility with existing ROM patch code
3. Memory overhead is acceptable (virtual memory makes it cheap)
4. Allows all EmulOps to work correctly

## Related Files

- [src/cpu/uae_cpu/basilisk_glue.cpp:216](macemu-next/src/cpu/uae_cpu/basilisk_glue.cpp#L216) - `Execute68kTrap()` implementation
- [src/cpu/uae_cpu/newcpu.cpp:1451](macemu-next/src/cpu/uae_cpu/newcpu.cpp#L1451) - UAE opcode fetch (crash location)
- [src/cpu/uae_cpu/memory.cpp:584](macemu-next/src/cpu/uae_cpu/memory.cpp#L584) - `memory_init()` function
- [src/core/emul_op.cpp:342](macemu-next/src/core/emul_op.cpp#L342) - EmulOp 0x712C handler
- [src/core/rom_patches.cpp:718](macemu-next/src/core/rom_patches.cpp#L718) - `InstallDrivers()` function

## Next Steps

1. Modify Unicorn backend init to also initialize UAE memory system
2. Test that Execute68kTrap() works correctly
3. Verify Unicorn can complete 250k+ instruction traces
4. Document memory overhead and performance impact
