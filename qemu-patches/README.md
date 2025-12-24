# QEMU Patches for BasiliskII/SheepShaver Integration

This directory contains minimal patches to QEMU that enable BasiliskII and SheepShaver to use QEMU's CPU emulation.

## Patches

### 0001-m68k-add-illegal-instruction-hook.patch

**Purpose**: Adds a hook to intercept illegal m68k instructions in the 0x71xx range.

**What it does**:
- Adds a function pointer `m68k_illegal_insn_hook` in `target/m68k/cpu.h`
- Checks this hook before raising an illegal instruction exception in `target/m68k/op_helper.c`
- If the hook returns `true`, skips the exception and continues execution

**BasiliskII usage**:
- BasiliskII patches Mac ROM to replace hardware I/O with 0x71xx opcodes
- These opcodes are illegal MOVEQ instructions (MOVEQ requires bit 0 = 0)
- The hook intercepts them and calls EmulOp() handlers

**Size**: ~18 lines of code

---

### 0002-ppc-add-illegal-instruction-hook.patch

**Purpose**: Adds a hook to intercept illegal PPC instructions (opcode 6, 0x18000000 range).

**What it does**:
- Adds a function pointer `ppc_illegal_insn_hook` in `target/ppc/cpu.h`
- Checks this hook when POWERPC_EXCP_PROGRAM/POWERPC_EXCP_INVAL exception occurs
- If the hook returns `true`, skips the exception and continues execution

**SheepShaver usage**:
- SheepShaver uses opcode 6 (reserved) for EmulOps and NativeOps
- Format: `0x18xxxxxx` where `xxxxxx` encodes the operation type
- The hook intercepts them and calls appropriate handlers

**Size**: ~19 lines of code

---

## Applying the Patches

### Method 1: Apply to QEMU submodule

```bash
cd qemu
git am ../qemu-patches/0001-m68k-add-illegal-instruction-hook.patch
git am ../qemu-patches/0002-ppc-add-illegal-instruction-hook.patch
```

### Method 2: Apply without committing (for testing)

```bash
cd qemu
git apply ../qemu-patches/0001-m68k-add-illegal-instruction-hook.patch
git apply ../qemu-patches/0002-ppc-add-illegal-instruction-hook.patch
```

### Method 3: Patch command

```bash
cd qemu
patch -p1 < ../qemu-patches/0001-m68k-add-illegal-instruction-hook.patch
patch -p1 < ../qemu-patches/0002-ppc-add-illegal-instruction-hook.patch
```

## Rebuilding QEMU After Patching

```bash
cd qemu/build
ninja
```

The build should be incremental - only the modified files will recompile (~30 seconds).

## Testing the Patches

After applying and rebuilding, you can verify the hooks are present:

```bash
# Check m68k hook is defined
nm qemu/build/qemu-system-m68k | grep m68k_illegal_insn_hook

# Check PPC hook is defined
nm qemu/build/qemu-system-ppc | grep ppc_illegal_insn_hook
```

Expected output:
```
0000000000xxxxxx B m68k_illegal_insn_hook
0000000000xxxxxx B ppc_illegal_insn_hook
```

## Using the Hooks from BasiliskII/SheepShaver

### Example for m68k (BasiliskII)

```c
// In your BasiliskII code
#include "target/m68k/cpu.h"

// Your EmulOp handler
bool handle_basilisk_emulop(CPUM68KState *env, uint16_t opcode) {
    // Check if it's actually an EmulOp (0x71xx range)
    if ((opcode & 0xFF00) != 0x7100) {
        return false;  // Not an EmulOp, let QEMU handle it normally
    }

    uint16_t selector = opcode & 0xFF;

    // Convert QEMU CPU state to BasiliskII format
    M68kRegisters regs;
    for (int i = 0; i < 8; i++) {
        regs.d[i] = env->dregs[i];
        regs.a[i] = env->aregs[i];
    }
    regs.sr = env->sr;

    // Call existing EmulOp handler
    EmulOp(selector, &regs);

    // Convert back
    for (int i = 0; i < 8; i++) {
        env->dregs[i] = regs.d[i];
        env->aregs[i] = regs.a[i];
    }
    env->sr = regs.sr;

    // Advance PC past the illegal instruction
    env->pc += 2;

    return true;  // We handled it
}

// During initialization
void init_qemu_cpu() {
    // ... QEMU initialization ...

    // Register our hook
    m68k_illegal_insn_hook = handle_basilisk_emulop;
}
```

### Example for PPC (SheepShaver)

```c
// In your SheepShaver code
#include "target/ppc/cpu.h"

bool handle_sheepshaver_op(CPUPPCState *env, uint32_t opcode) {
    // Check if it's opcode 6 (SheepShaver range)
    if ((opcode >> 26) != 6) {
        return false;  // Not our opcode
    }

    // Decode SheepShaver opcode format
    // ... (your existing code)

    // Handle EmulOp or NativeOp
    // ... (your existing code)

    // Advance PC past the instruction
    env->nip += 4;

    return true;  // We handled it
}

// During initialization
void init_qemu_cpu() {
    // ... QEMU initialization ...

    // Register our hook
    ppc_illegal_insn_hook = handle_sheepshaver_op;
}
```

## Patch Maintenance

### When Updating QEMU

These patches are designed to be minimal and stable:
- They only add code, don't modify existing logic
- They touch exception handling code which rarely changes
- They should apply cleanly to future QEMU versions

If patches fail to apply after QEMU update:
1. Check which files changed in QEMU
2. Manually apply the changes (they're only ~20 lines each)
3. Update patch files with `git format-patch`

### Contributing Upstream

These patches could potentially be submitted to QEMU upstream as:
- "Add illegal instruction hooks for external emulators"
- Rationale: Useful for projects embedding QEMU (Unicorn, Android Emulator, etc.)
- Precedent: QEMU already has semihosting hooks for similar purposes

## Architecture

```
Mac ROM Code
    ↓
Regular 68k instruction → QEMU executes normally
    ↓
0x71xx illegal opcode → QEMU detects illegal instruction
    ↓
Before exception: Check m68k_illegal_insn_hook
    ↓
Hook returns true? → Skip exception, continue
Hook returns false? → Raise exception normally
```

## Technical Details

### Why Not Use TRAP Instructions?

Alternative approaches considered:
1. **Modify ROM to use TRAP instead of illegal opcodes** ❌
   - Would require rewriting all ROM patches
   - Changes semantics (TRAP vs illegal instruction)
   - More invasive than ~20 line QEMU patch

2. **Use QEMU's existing semihosting** ❌
   - Designed for different use case (syscalls)
   - Requires specific instruction sequences
   - Not compatible with existing ROM patches

3. **Illegal instruction hook** ✅
   - Minimal QEMU changes (~40 lines total)
   - No ROM changes needed
   - Clean, isolated patch

### Performance Impact

The hook adds one function pointer check to the exception path:
- Only checked when illegal instruction exception occurs
- Modern CPUs branch-predict this well (NULL check)
- Negligible impact on normal execution

## License

These patches are released under the same license as QEMU (GPL v2 or later).

## Authors

- MacEmu Project Contributors
- Based on analysis of BasiliskII/SheepShaver EmulOp system

## See Also

- `../docs/qemu/QEMU_MODIFICATION_REQUIREMENTS.md` - Design rationale
- `../docs/qemu/QEMU_LINKING_STRATEGY.md` - How to link QEMU into macemu
- `../docs/qemu/IMPLEMENTATION_ROADMAP.md` - Full migration plan
