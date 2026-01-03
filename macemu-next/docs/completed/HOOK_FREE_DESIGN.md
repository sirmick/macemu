# Hook-Free Architecture Design for Unicorn Backend

## Problem Statement

**Current Issue**: Using `UC_HOOK_CODE` for EmulOps/traps has severe performance penalty (~10x slower)
- Hook fires **before every instruction**
- Forces PC synchronization
- Breaks JIT optimization
- Cannot keep PC in registers

**Register Modification Issue**: After `UC_ERR_INSN_INVALID`, register writes don't persist due to JIT cache

## Research Findings

### Available Unicorn Hooks (from our version)

1. **UC_HOOK_INSN_INVALID** ✅ Available!
   - Callback: `typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);`
   - Return `true` to continue, `false` to stop
   - Called when invalid instruction is encountered
   - **Key**: Can we modify registers here and return true?

2. **UC_HOOK_BLOCK** ✅ Available!
   - Called at basic block boundaries
   - Much faster than UC_HOOK_CODE
   - Perfect for interrupt checking

3. **uc_ctl_remove_cache()** ✅ Available!
   - Invalidates translation block cache
   - Required after code/register modification
   - Takes address range: `(uint64_t start, uint64_t end)`

### Critical Insight from Unicorn FAQ

> To ensure modifications take effect:
> 1. Call `uc_ctl_remove_cache` on the target address
> 2. Call `uc_reg_write` to write current PC to PC register
> 3. This restarts emulation (but doesn't quit uc_emu_start) on current address to re-translate the block

## Proposed Architecture

### Solution 1: UC_HOOK_INSN_INVALID + Cache Invalidation

```
┌─────────────────────────────────────────────────────────┐
│ Unicorn JIT Execution                                    │
│                                                          │
│  ┌────────────────┐                                     │
│  │ Basic Block    │ ← UC_HOOK_BLOCK checks interrupts   │
│  │ (many instrs)  │                                     │
│  └────────────────┘                                     │
│          ↓                                               │
│  ┌────────────────┐                                     │
│  │ Illegal 0x71xx │ ← Triggers UC_HOOK_INSN_INVALID    │
│  └────────────────┘                                     │
│          ↓                                               │
│  ╔════════════════════════════════════════╗            │
│  ║ UC_HOOK_INSN_INVALID Handler:         ║            │
│  ║ 1. Read PC (at illegal instruction)    ║            │
│  ║ 2. Call platform EmulOp handler        ║            │
│  ║ 3. Modify registers (D0-D7, A0-A7, SR) ║            │
│  ║ 4. uc_ctl_remove_cache(PC, PC+2)      ║            │
│  ║ 5. uc_reg_write(PC, new_pc)           ║            │
│  ║ 6. return true to continue             ║            │
│  ╚════════════════════════════════════════╝            │
│          ↓                                               │
│  Execution continues with modified registers!           │
└─────────────────────────────────────────────────────────┘
```

**Advantages:**
- ✅ No per-instruction overhead
- ✅ Registers can be modified
- ✅ Cache invalidation ensures changes persist
- ✅ Clean separation: BLOCK for interrupts, INSN_INVALID for EmulOps

**Risk:**
- ❓ Will `uc_ctl_remove_cache + uc_reg_write(PC)` work inside UC_HOOK_INSN_INVALID callback?
- ❓ Need to test if returning `true` continues execution correctly

### Solution 2: Fallback - UC_ERR_INSN_INVALID in Error Path

If Solution 1 doesn't work, fallback to handling after `uc_emu_start` returns:

```
while (running) {
    err = uc_emu_start(cpu->uc, pc, ...);

    if (err == UC_ERR_INSN_INVALID) {
        // Read PC to see what illegal instruction was
        uc_reg_read(cpu->uc, UC_M68K_REG_PC, &pc);

        // Read opcode at PC
        uint16_t opcode;
        uc_mem_read(cpu->uc, pc, &opcode, 2);
        opcode = swap_bytes(opcode);

        if ((opcode & 0xFF00) == 0x7100) {
            // EmulOp!
            platform.emulop_handler(opcode);

            // Get new registers from platform
            for (int i = 0; i < 8; i++) {
                uint32_t d = platform.cpu_get_dreg(i);
                uint32_t a = platform.cpu_get_areg(i);
                uc_reg_write(cpu->uc, UC_M68K_REG_D0 + i, &d);
                uc_reg_write(cpu->uc, UC_M68K_REG_A0 + i, &a);
            }

            // Advance PC and invalidate cache
            pc += 2;
            uc_ctl_remove_cache(cpu->uc, UC_CTL_TB_REMOVE_CACHE, pc - 2, pc + 2);
            uc_reg_write(cpu->uc, UC_M68K_REG_PC, &pc);

            // Continue execution
            continue;
        }
        // else: real invalid instruction, propagate error
    }
}
```

**Advantages:**
- ✅ Guaranteed to work (no hook uncertainty)
- ✅ Cache invalidation in known-good context
- ✅ Clear error handling

**Disadvantages:**
- ⚠️ Breaks out of JIT for every EmulOp
- ⚠️ More overhead than Solution 1 (if Solution 1 works)

## Implementation Plan

### Phase 1: Test UC_HOOK_INSN_INVALID (Preferred)

1. **Create test hook handler**:
```c
static bool hook_insn_invalid(uc_engine *uc, void *user_data) {
    UnicornCPU *cpu = (UnicornCPU *)user_data;

    // Read PC
    uint32_t pc;
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);

    // Read opcode
    uint16_t opcode;
    uc_mem_read(uc, pc, &opcode, sizeof(opcode));
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    opcode = __builtin_bswap16(opcode);
    #endif

    // Check if it's an EmulOp (0x71xx)
    if ((opcode & 0xFF00) == 0x7100) {
        if (g_platform.emulop_handler) {
            // Call platform handler
            bool pc_advanced = g_platform.emulop_handler(opcode, false);

            // Sync ALL registers back from platform to Unicorn
            for (int i = 0; i < 8; i++) {
                uint32_t d = g_platform.cpu_get_dreg(i);
                uint32_t a = g_platform.cpu_get_areg(i);
                uc_reg_write(uc, UC_M68K_REG_D0 + i, &d);
                uc_reg_write(uc, UC_M68K_REG_A0 + i, &a);
            }

            if (g_platform.cpu_get_sr) {
                uint16_t sr = g_platform.cpu_get_sr();
                uc_reg_write(uc, UC_M68K_REG_SR, &sr);
            }

            // Advance PC if handler didn't
            if (!pc_advanced) {
                pc += 2;
            }

            // CRITICAL: Invalidate cache and update PC
            uc_ctl_remove_cache(uc, UC_CTL_TB_REMOVE_CACHE, pc - 2, pc + 2);
            uc_reg_write(uc, UC_M68K_REG_PC, &pc);

            // Return true to continue execution
            return true;
        }
    }

    // Check for traps (0xAxxx, 0xFxxx)
    if ((opcode & 0xF000) == 0xA000 || (opcode & 0xF000) == 0xF000) {
        // Similar handling for traps
        // ... (trap handler code)
        return true;
    }

    // Real invalid instruction - stop execution
    return false;
}
```

2. **Register the hook**:
```c
uc_hook_add(cpu->uc, &cpu->insn_invalid_hook, UC_HOOK_INSN_INVALID,
            (void*)hook_insn_invalid, cpu, 1, 0);
```

3. **Remove UC_HOOK_CODE completely**

4. **Test**:
   - Does it catch EmulOps?
   - Do register modifications persist?
   - Does execution continue correctly?

### Phase 2: Add UC_HOOK_BLOCK for Interrupts

1. **Create hook_block handler** (same as designed before)

2. **Register UC_HOOK_BLOCK**:
```c
uc_hook_add(cpu->uc, &cpu->block_hook, UC_HOOK_BLOCK,
            (void*)hook_block, cpu, 1, 0);
```

3. **Test interrupt handling at block boundaries**

### Phase 3: Fallback if Needed

If UC_HOOK_INSN_INVALID doesn't allow register modifications:
- Implement Solution 2 (error path handling)
- Keep UC_HOOK_BLOCK for interrupts

## Testing Strategy

1. **Unit Test**: Simple EmulOp execution
   - Execute single 0x71xx instruction
   - Verify registers modified
   - Verify execution continues

2. **Integration Test**: Boot sequence
   - Run Unicorn backend with ROM
   - Monitor for EmulOps and interrupts
   - Compare traces with UAE

3. **Performance Test**: Measure improvement
   - Before: UC_HOOK_CODE (~10x slower)
   - After: UC_HOOK_INSN_INVALID + UC_HOOK_BLOCK (near-native JIT)
   - Expected: 5-10x speed improvement

## Expected Results

- **Performance**: Near-native JIT speed (no per-instruction overhead)
- **Correctness**: EmulOps handled, interrupts processed
- **Convergence**: UAE and Unicorn traces should stay synchronized much longer

## Files to Modify

1. `macemu-next/src/cpu/unicorn_wrapper.c`:
   - Remove `hook_code` or make it minimal
   - Add `hook_insn_invalid`
   - Add `hook_block` for interrupts
   - Update struct to add `insn_invalid_hook` and `block_hook` handles

2. `macemu-next/src/cpu/unicorn_wrapper.h`:
   - No API changes needed (internal only)

## Risk Mitigation

**If UC_HOOK_INSN_INVALID doesn't work**:
- Fall back to error path handling (Solution 2)
- Still much better than current UC_HOOK_CODE approach
- Still get UC_HOOK_BLOCK for interrupts (major win)

## Next Steps

1. **Immediate**: Test UC_HOOK_INSN_INVALID with simple case
2. **If successful**: Implement full solution
3. **If not**: Implement fallback (still better than current)
4. **Always**: Move interrupts to UC_HOOK_BLOCK (easy win)
