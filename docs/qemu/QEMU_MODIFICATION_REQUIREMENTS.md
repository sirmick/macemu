# QEMU Modification Requirements

## TL;DR

**Answer: Minimal QEMU patch required (~10-15 lines)**

After examining the actual source code, BasiliskII uses **illegal MOVEQ opcodes (0x71xx)**, not TRAP instructions. This means **Option B (minimal patch) is required**.

You have **two viable options**:

1. **✅ Option B: Minimal QEMU patch for illegal instruction handler** (~10-15 lines) **RECOMMENDED**
2. **⚠️ Option A: Modify ROM patches to use TRAP instead** (No QEMU changes, but more invasive to ROM patching)
3. **❌ Option C: Fork and modify QEMU heavily** (Not recommended)

## Background: The EmulOp Problem

BasiliskII and SheepShaver use special "illegal" opcodes to trap into emulator code:

**BasiliskII (m68k):**
```
0x71xx opcodes (illegal MOVEQ instructions)
→ Trap to EmulOp handler
→ Execute device emulation (video, disk, etc.)

Source: BasiliskII/src/include/emul_op.h:37
M68K_EXEC_RETURN = 0x7100, // Extended opcodes (illegal moveq form)

MOVEQ requires bit 0 = 0, so 0x71xx is illegal and triggers exception.
```

**SheepShaver (PPC):**
```
0x18000000 opcodes (opcode 6, reserved)
→ Trap to EMUL_OP/NATIVE_OP handler
→ Execute device emulation or native routines
```

**The question:** How do we intercept these in QEMU?

---

## Option B: Minimal QEMU Patch ✅ **RECOMMENDED**

**Reality check:** BasiliskII uses illegal MOVEQ opcodes (0x71xx), not TRAP. To keep ROM patches unchanged, we need a small QEMU patch.

This is the **recommended approach** because:
- ✅ Keeps existing ROM patches unchanged
- ✅ Minimal QEMU modification (~10-15 lines)
- ✅ Easy to maintain and rebase
- ✅ Could be upstreamed to QEMU

### What to Patch

Create a hook in QEMU's illegal instruction handler:

#### m68k Patch

**File:** `target/m68k/op_helper.c`

```c
// Add this function pointer (can be set from outside QEMU)
void (*m68k_illegal_insn_hook)(CPUM68KState *env, uint16_t opcode) = NULL;

void HELPER(illegal_op)(CPUM68KState *env, uint32_t insn)
{
    uint16_t opcode = insn & 0xFFFF;

    // Check if external handler wants to handle this (0x71xx range)
    if (m68k_illegal_insn_hook && (opcode & 0xFF00) == 0x7100) {
        m68k_illegal_insn_hook(env, opcode);
        return;  // Handler dealt with it
    }

    // Otherwise, raise illegal instruction exception as normal
    cs_exception(env, EXCP_ILLEGAL);
}
```

**File:** `target/m68k/cpu.h`

```c
// Expose the hook
extern void (*m68k_illegal_insn_hook)(CPUM68KState *env, uint16_t opcode);
```

**Your adapter code:**

```c
#include "target/m68k/cpu.h"

void my_emulop_handler(CPUM68KState *env, uint16_t opcode) {
    uint16_t selector = opcode & 0xFF;

    // Convert QEMU state to M68kRegisters
    M68kRegisters regs;
    for (int i = 0; i < 8; i++) {
        regs.d[i] = env->dregs[i];
        regs.a[i] = env->aregs[i];
    }

    // Call existing EmulOp handler (unchanged!)
    EmulOp(selector, &regs);

    // Convert back
    for (int i = 0; i < 8; i++) {
        env->dregs[i] = regs.d[i];
        env->aregs[i] = regs.a[i];
    }
}

void init_qemu() {
    m68k_illegal_insn_hook = my_emulop_handler;
}
```

**Patch size:** ~10 lines in QEMU

#### PPC Patch

**File:** `target/ppc/excp_helper.c`

```c
void (*ppc_illegal_insn_hook)(CPUPPCState *env, uint32_t opcode) = NULL;

void helper_raise_exception_err(CPUPPCState *env, uint32_t exception, uint32_t error_code)
{
    CPUState *cs = env_cpu(env);

    if (exception == POWERPC_EXCP_PROGRAM && error_code == POWERPC_EXCP_INVAL) {
        // Get the opcode that caused the exception
        uint32_t opcode = /* read from env->nip */;

        if (ppc_illegal_insn_hook && (opcode >> 26) == 6) {  // Opcode 6 = SheepShaver
            ppc_illegal_insn_hook(env, opcode);
            return;  // Handled
        }
    }

    // Normal exception handling
    raise_exception_err_ra(env, exception, error_code, 0);
}
```

**Patch size:** ~15 lines in QEMU

### Maintaining the Patch

**Option 1: Carry patch locally** (Simplest)
```bash
# Apply patch to QEMU
cd qemu
git apply ../macemu-qemu-hooks.patch
```

**Option 2: Contribute upstream** (Best long-term)
```
Submit patch to QEMU mailing list as:
"Add hook for external illegal instruction handlers"

Rationale: Useful for emulators that need custom trap handling
Precedent: QEMU already has semihosting hooks for ARM/RISC-V
```

**Option 3: Use QEMU stable branch and rebase patch**
```bash
# When updating QEMU
git fetch upstream
git rebase upstream/stable-8.2
# Fix any conflicts in the small patch (unlikely - helper functions are stable)
```

---

## Option A: Use QEMU As-Is (Alternative Approach)

**Trade-off:** No QEMU changes, but requires modifying ROM patching logic.

Instead of illegal opcodes, **patch the ROM to use TRAP instructions**:

### How It Works

QEMU's user-mode emulation already has infrastructure to handle "syscalls" from guest to host. We can abuse this for EmulOps.

#### For m68k (BasiliskII)

QEMU's m68k target already handles TRAP instructions for syscalls. We can register our EmulOps as syscalls.

```c
// In your adapter code (NOT in QEMU)
void qemu_m68k_trap_handler(CPUM68KState *env) {
    uint16_t trap_vector = env->sr & 0xF;  // Get trap number

    // If it's our special range (e.g., TRAP #1 with specific D0 value)
    if (env->dregs[0] >= EMULOP_BASE) {
        uint16_t selector = env->dregs[0] - EMULOP_BASE;

        // Convert QEMU state to M68kRegisters
        M68kRegisters regs;
        for (int i = 0; i < 8; i++) {
            regs.d[i] = env->dregs[i];
            regs.a[i] = env->aregs[i];
        }

        // Call existing EmulOp handler
        EmulOp(selector, &regs);

        // Convert back
        for (int i = 0; i < 8; i++) {
            env->dregs[i] = regs.d[i];
            env->aregs[i] = regs.a[i];
        }

        return;  // Handled
    }

    // Otherwise, let QEMU handle it normally
}
```

**QEMU modification:** ZERO - just register a callback

#### For PPC (SheepShaver)

Similar approach using QEMU's existing syscall infrastructure:

```c
// In your adapter code
void qemu_ppc_syscall_handler(CPUPPCState *env) {
    uint32_t syscall_num = env->gpr[0];

    if (syscall_num == SHEEPSHAVER_SYSCALL_MAGIC) {
        uint32_t opcode = env->gpr[3];  // Get full instruction

        // Extract EMUL_OP or NATIVE_OP
        uint32_t type = (opcode >> 26) & 0x3f;
        if (type == 6) {  // SheepShaver extended opcode
            uint32_t fn = (opcode >> 19) & 1;
            uint32_t op = (opcode >> 20) & 0x3f;

            // Call existing handler
            execute_sheep_op(env, opcode);
        }

        return;
    }
}
```

**QEMU modification:** ZERO - use existing syscall hooks

### Implementation Strategy

Instead of using illegal opcodes (0x71xx for m68k), **patch the ROM to use TRAP instructions** pointing to known syscall numbers:

```
Before (illegal opcode):
    DC.W $7100    ; Illegal MOVEQ, traps to EmulOp

After (legal TRAP):
    TRAP #1       ; Legal instruction, QEMU handles this
    DC.W $00      ; Selector follows
```

**Advantage:** QEMU handles TRAP normally, you just register a handler.

**Disadvantage:**
- Need to modify ROM patching logic throughout the codebase
- Changes semantics from illegal instruction to syscall
- More invasive changes to existing code

---

## Option C: Fork QEMU ❌ **NOT RECOMMENDED**

You could fork QEMU and make extensive modifications, but this is:
- ❌ High maintenance burden
- ❌ Difficult to update
- ❌ Diverges from upstream
- ❌ Unnecessary for this use case

**Don't do this.**

---

## Comparison

| Aspect | Option B (Minimal Patch) ✅ | Option A (TRAP Approach) | Option C (Fork) ❌ |
|--------|---------------------------|--------------------------|-------------------|
| **QEMU changes** | ~10-15 lines | Zero | Many |
| **ROM changes** | None | Extensive (replace all 0x71xx) | None |
| **Code changes** | Minimal adapter (~50 lines) | ROM patching rewrite (~500+ lines) | Many |
| **Maintenance** | Easy (small stable patch) | Medium (maintain ROM changes) | Hard (maintain fork) |
| **Upstream** | Works with patched QEMU | Works with any QEMU | Custom QEMU |
| **Risk** | Low (isolated change) | Medium (pervasive ROM changes) | High (fork divergence) |
| **Testing** | Easy (patch is isolated) | Complex (all ROM patches) | Very complex |

---

## Recommended Approach

**Use Option B (minimal QEMU patch) - it's the pragmatic choice.**

### Implementation Plan (Week 1-2)

**Step 1: Create the patch** (1 day)

Create `macemu-qemu-hooks.patch`:

```diff
diff --git a/target/m68k/op_helper.c b/target/m68k/op_helper.c
index 1234567..abcdefg 100644
--- a/target/m68k/op_helper.c
+++ b/target/m68k/op_helper.c
@@ -20,8 +20,15 @@
 #include "exec/helper-proto.h"
 #include "exec/cpu_ldst.h"

+void (*m68k_illegal_insn_hook)(CPUM68KState *env, uint16_t opcode) = NULL;
+
 void HELPER(illegal_op)(CPUM68KState *env, uint32_t insn)
 {
+    uint16_t opcode = insn & 0xFFFF;
+    if (m68k_illegal_insn_hook && (opcode & 0xFF00) == 0x7100) {
+        m68k_illegal_insn_hook(env, opcode);
+        return;
+    }
     cs_exception(env, EXCP_ILLEGAL);
 }

diff --git a/target/m68k/cpu.h b/target/m68k/cpu.h
index 1234567..abcdefg 100644
--- a/target/m68k/cpu.h
+++ b/target/m68k/cpu.h
@@ -200,4 +200,7 @@ void m68k_cpu_list(void);

 void register_m68k_insns(CPUM68KState *env);

+/* Hook for external illegal instruction handler */
+extern void (*m68k_illegal_insn_hook)(CPUM68KState *env, uint16_t opcode);
+
 #endif
```

**Step 2: Build QEMU with patch** (1 day)

```bash
cd qemu
git apply ../macemu-qemu-hooks.patch
./configure --target-list=m68k-softmmu,ppc-softmmu
make -j$(nproc)
```

**Step 3: Create adapter code** (2-3 days)

```c
// qemu_m68k_adapter.c
#include "target/m68k/cpu.h"

void emulop_illegal_handler(CPUM68KState *env, uint16_t opcode) {
    uint16_t selector = opcode & 0xFF;

    M68kRegisters regs;
    // Copy state from QEMU to legacy format
    for (int i = 0; i < 8; i++) {
        regs.d[i] = env->dregs[i];
        regs.a[i] = env->aregs[i];
    }

    // Call existing EmulOp handler (unchanged!)
    EmulOp(selector, &regs);

    // Copy state back
    for (int i = 0; i < 8; i++) {
        env->dregs[i] = regs.d[i];
        env->aregs[i] = regs.a[i];
    }
}

void init_qemu_m68k() {
    m68k_illegal_insn_hook = emulop_illegal_handler;
}
```

**Step 4: Test with DualCPU harness** (1 week)

Use the DualCPU testing approach to validate both CPUs execute identically.

---

## Other QEMU Modifications Needed?

### Memory Access

**Do we need to modify QEMU?** No.

QEMU's `MemoryRegion` API is flexible enough:

```c
// Option A: Adapter callbacks
static const MemoryRegionOps mac_ram_ops = {
    .read = mac_ram_read,   // Calls your ReadMacInt*()
    .write = mac_ram_write, // Calls your WriteMacInt*()
};

// Option B: Direct mapping
memory_region_init_ram_ptr(ram, NULL, "mac.ram", RAMSize, RAMBaseHost);
```

**QEMU modification:** Zero

### CPU State Access

**Do we need to modify QEMU?** No.

QEMU exposes CPU state directly:

```c
CPUM68KState *cpu = ...;

// Read registers
uint32_t d0 = cpu->dregs[0];
uint32_t a7 = cpu->aregs[7];
uint32_t pc = cpu->pc;

// Write registers
cpu->dregs[0] = value;
cpu->pc = new_pc;
```

**QEMU modification:** Zero

### Interrupt Handling

**Do we need to modify QEMU?** No.

QEMU has standard interrupt API:

```c
// Raise interrupt
cpu_interrupt(CPU(cpu), CPU_INTERRUPT_HARD);

// Check if interrupt pending
if (cpu->interrupt_request & CPU_INTERRUPT_HARD) {
    // Handle it
}
```

**QEMU modification:** Zero

---

## Summary

### Recommended: Option B (Minimal QEMU Patch) ✅

**QEMU modifications:** ~10-15 lines (one small, stable patch)

**Your code changes:**
- Register illegal instruction hook (~50 lines)
- Keep existing ROM patches (zero changes)
- Keep existing EmulOp handlers (zero changes)

**Total effort:** 1-2 weeks

**Why this is best:**
- ✅ Minimal changes to proven code
- ✅ ROM patches stay exactly as-is
- ✅ EmulOp handlers stay exactly as-is
- ✅ Small, stable QEMU patch (~10 lines)
- ✅ Easy to rebase when updating QEMU
- ✅ Could be upstreamed to QEMU

### Alternative: Option A (No QEMU Changes)

**QEMU modifications:** ZERO

**Your code changes:**
- Rewrite ROM patching to use TRAP instead of 0x71xx (~500+ lines)
- Register TRAP handler with QEMU (~100 lines)
- Test all ROM patches extensively

**Total effort:** 3-4 weeks

**Trade-off:** More invasive changes to your code to avoid patching QEMU.

### Bottom Line

**Use Option B.** The ~10-line QEMU patch is far less risky than rewriting hundreds of lines of ROM patching logic.

The QEMU patch is:
- Small and isolated
- Unlikely to conflict with QEMU updates
- Could be contributed upstream
- Much lower risk than changing ROM patches

---

## Integration Example (Option B - Recommended)

```c
// File: qemu_m68k_adapter.c
#include "target/m68k/cpu.h"
#include "emul_op.h"  // Your existing EmulOp definitions

static CPUM68KState *m68k_cpu;

// This is called by QEMU when it hits 0x71xx opcodes
void emulop_illegal_handler(CPUM68KState *env, uint16_t opcode) {
    uint16_t selector = opcode & 0xFF;

    // Convert QEMU state to your existing M68kRegisters format
    M68kRegisters regs;
    for (int i = 0; i < 8; i++) {
        regs.d[i] = env->dregs[i];
        regs.a[i] = env->aregs[i];
    }
    regs.pc = env->pc;
    regs.sr = env->sr;

    // Call your existing EmulOp handler (unchanged!)
    EmulOp(selector, &regs);

    // Convert back
    for (int i = 0; i < 8; i++) {
        env->dregs[i] = regs.d[i];
        env->aregs[i] = regs.a[i];
    }
    env->pc = regs.pc;
    env->sr = regs.sr;
}

// Initialize QEMU with the hook
void qemu_m68k_init() {
    m68k_cpu = cpu_m68k_init("m68040");

    // Set up memory regions (separate topic)
    setup_memory(m68k_cpu);

    // Register our illegal instruction hook
    m68k_illegal_insn_hook = emulop_illegal_handler;
}

// Execute one instruction (for DualCPU testing)
void qemu_m68k_execute_one() {
    cpu_exec_step(m68k_cpu);
}
```

**QEMU modified:** ~10 lines (one small patch)
**Existing code modified:** None (EmulOp handlers stay as-is)
**New code:** ~100 lines adapter

---

## Conclusion

**A minimal QEMU patch (~10-15 lines) is the recommended approach.**

After examining the actual source code:
- ✅ BasiliskII uses illegal MOVEQ opcodes (0x71xx), not TRAP
- ✅ Minimal QEMU patch keeps all existing code unchanged
- ✅ Alternative (TRAP approach) requires rewriting ROM patching logic
- ✅ The QEMU patch is small, stable, and easy to maintain

**This is NOT a QEMU fork** - just a tiny hook for illegal instruction handling that could even be contributed upstream.
