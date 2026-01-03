# A-line/F-line Exception Handling - Status

## Current State (2025-12-29)

### ✅ Implemented
- **Exception simulation code** ([unicorn_exception.c](../src/cpu/unicorn_exception.c)): Complete implementation of M68K exception handling including:
  - Stack frame construction (68020+ format: SR, PC, vector offset)
  - Supervisor mode switching (USP/ISP handling)
  - Vector table lookup (VBR support)
  - Trace flag clearing
  - Big-endian memory access helpers

- **Unicorn wrapper hooks** ([unicorn_wrapper.c](../src/cpu/unicorn_wrapper.c)):
  - `ExceptionHandler` callback typedef
  - A-line (0xAxxx) and F-line (0xFxxx) detection in `hook_invalid_insn()`
  - `unicorn_set_exception_handler()` API
  - `unicorn_get_uc()` to expose uc_engine pointer

- **DualCPU validation workaround** ([unicorn_validation.cpp](../src/cpu/unicorn_validation.cpp)):
  - Separate handling for EmulOps (0x71xx) vs A-line/F-line
  - Both execute on UAE only, then sync full state to Unicorn
  - Full RAM sync after special instruction execution

### ⚠️ Known Issue: UC_HOOK_INSN_INVALID Doesn't Fire

**Problem**: Unicorn's `UC_HOOK_INSN_INVALID` hook does **NOT** trigger for A-line (0xAxxx) or F-line (0xFxxx) instructions. Instead, these instructions cause `UC_ERR_EXCEPTION`.

**Evidence**:
```
[23250] UNICORN EXECUTION FAILED
PC: 0x02003E08, Opcode: 0xA247 (A-line trap - SetToolTrap)
Error: Unhandled CPU exception (UC_ERR_EXCEPTION)
```

**Root Cause**: Unicorn treats 0xAxxx and 0xFxxx as architecturally valid M68K instructions that generate exceptions, not as "invalid" opcodes. The hook mechanism is designed for truly invalid/undefined instructions.

**Current Workaround**: Execute A-line/F-line on UAE only, sync state to Unicorn (same as EmulOps).

### ✅ DualCPU Validation Now Passing A-line Traps

With the workaround in place:
- **Instructions executed**: 23,275 (previously stopped at 23,250)
- **A-line traps**: Successfully handled via UAE-only execution
- **EmulOps**: Successfully handled via UAE-only execution
- **Current divergence**: Different issue - MOVEC instruction at 23,275 (control register emulation difference)

## Future Work

### Option 1: Accept the Workaround
**Pros**:
- Already working
- Simple and maintainable
- UAE is the "golden reference" anyway

**Cons**:
- Defeats purpose of dual-CPU validation for A-line/F-line instructions
- Exception handling code written but unused

### Option 2: Investigate Alternative Unicorn Hooks
Potential approaches:
1. **Hook execution errors**: Catch `UC_ERR_EXCEPTION` and manually invoke exception handler
2. **Pre-execution hook**: Check opcode before execution, handle A-line/F-line manually
3. **Memory hook**: Detect PC at A-line/F-line instruction, intercept execution

**Example**:
```c
// In unicorn_execute_one():
uc_err err = uc_emu_start(...);
if (err == UC_ERR_EXCEPTION) {
    uint16_t opcode = read_opcode_at_pc(cpu);
    if ((opcode & 0xF000) == 0xA000 || (opcode & 0xF000) == 0xF000) {
        cpu->exception_handler(cpu, vector_nr, opcode);
        return true;  // Handled
    }
}
```

### Option 3: Unicorn Configuration
Investigate if Unicorn can be configured to treat A-line/F-line as invalid instructions rather than exceptions. (Likely not possible without modifying Unicorn itself.)

## Recommendation

**Accept the workaround** for now. Reasons:
1. DualCPU is primarily for validating normal instruction execution, not exception handling
2. Exception handling is inherently platform-specific (BasiliskII patches ROM to avoid many traps)
3. UAE's exception handling is battle-tested and known-good
4. The exception simulation code remains available if needed for future Unicorn-only backend

The next priority should be investigating the **MOVEC divergence** at instruction 23,275 (control register emulation differences between UAE and Unicorn).

## Code Structure

```
src/cpu/
├── unicorn_exception.c     # Exception simulation (ready but unused)
├── unicorn_exception.h     # Header with extern "C" guards
├── unicorn_wrapper.c       # Hook infrastructure (detection works, invocation doesn't)
├── unicorn_wrapper.h       # ExceptionHandler API
└── unicorn_validation.cpp  # DualCPU workaround (UAE-only execution + sync)
```

## Testing

Run DualCPU validation:
```bash
cd macemu-next
EMULATOR_TIMEOUT=2 CPU_BACKEND=dualcpu ./build/macemu-next ~/quadra.rom
```

Expected output:
```
=== DualCPU Divergence ===
Instructions executed: 23275
```

Check validation log:
```bash
tail cpu_validation.log
```

Expected divergence:
```
[23275] D1 DIVERGENCE at 0x02009A7C (opcode 0x4E7A)
UAE D1: 0x000091C0 → 0x00000001
UC  D1: 0x000091C0 → 0x00000000
```
