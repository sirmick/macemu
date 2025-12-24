# Week 4 Planning Summary (REVISED)

**Date**: December 24, 2025
**Status**: ✅ **PLANNING COMPLETE - CORRECTED**
**Revision**: 2 - Fixed memory architecture and JIT strategy

## Critical Corrections Made

**Two major architectural fixes based on review:**

1. **Separate Memory Architecture** ✅
   - Each CPU MUST have independent RAM/ROM copies
   - Prevents false positives from memory side effects
   - Enables true validation of memory operations
   - Added comprehensive memory comparison

2. **Interpreter-Only Validation** ✅
   - JIT disabled for all DualCPU testing (Weeks 4-12)
   - Production uses QEMU's battle-tested TCG JIT (Week 13+)
   - Don't need to validate QEMU's JIT ourselves
   - Focus on correctness first, performance later

---

## What We Planned

### 1. QEMU Execution Loop

**Functions to implement:**
- `Start680x0_QEMU()` - Main execution loop (interpreter mode)
- `QEMU_ExecuteOne()` - **NEW** - Single-step for DualCPU
- `Execute68k_QEMU()` - Execute subroutine
- `Execute68kTrap_QEMU()` - Execute trap
- Updated EmulOp hook for `M68K_EXEC_RETURN`

**Key design:**
- Interpreter mode ONLY during validation
- JIT explicitly disabled
- Single-step capability for lockstep testing

### 2. DualCPU Testing Harness (CORRECTED)

**Core architecture:**
```
One loop, two CPUs, separate memory:

DualCPU_Init():
  - Allocate UAE RAM (separate)
  - Allocate QEMU RAM (separate)
  - Copy same ROM to both
  - Init both CPUs with own memory

Start680x0_DualCPU():
  while (!quit) {
    UAE_ExecuteOne()    // Execute 1 instruction
    QEMU_ExecuteOne()   // Execute 1 instruction
    Compare states      // Registers + Memory
    if (diverged) abort()
  }
```

**Memory strategy:**
- Each CPU: Own 16MB RAM + 1MB ROM
- Start with identical content
- Execute independently
- Compare memory every 1000 instructions
- Catch memory divergences immediately

---

## Documentation Created

- **[WEEK4_EXECUTION_AND_DUALCPU_DESIGN.md](WEEK4_EXECUTION_AND_DUALCPU_DESIGN.md)** (703 lines) - Complete corrected architecture
- **WEEK4_SUMMARY.md** (this file) - Executive overview
- **[QUICK_START_WEEK4.md](QUICK_START_WEEK4.md)** - Implementation guide

---

## Implementation Roadmap (CORRECTED)

### Week 4: QEMU Execution Loop
- Implement single-step `QEMU_ExecuteOne()`
- Implement `Start680x0_QEMU()` interpreter loop
- JIT disabled, interpreter mode only
- Test with simple MOVE/ADD program

### Week 5: DualCPU Harness
- Allocate **separate** RAM/ROM for each CPU
- Implement lockstep execution loop
- Memory comparison every 1000 instructions
- Test with simple instructions

### Weeks 6-12: Validation
- Instruction set validation
- ROM boot testing
- All with DualCPU, interpreter mode

### Week 13+: Production
- Disable DualCPU
- Enable QEMU TCG JIT
- Delete UAE code!

---

## Key Insights

### Why Separate Memory

**Wrong (shared):**
```cpp
UAE writes: RAM[0x1000] = 0xFF
QEMU reads: RAM[0x1000]  // Gets UAE's value - FALSE POSITIVE!
```

**Right (separate):**
```cpp
UAE writes:  uae_ram[0x1000] = 0xFF   // Independent
QEMU writes: qemu_ram[0x1000] = 0xFF  // Independent
memcmp(uae_ram, qemu_ram, SIZE)       // True validation!
```

### Why Interpreter-Only

- JIT is non-deterministic
- Can't single-step through JIT blocks
- Interpreter is fully deterministic
- Perfect for lockstep comparison
- QEMU's JIT is already proven

**Strategy**: Validate with interpreters, run production with QEMU JIT.

---

## Success Metrics

**Week 4:** QEMU executes simple program ✓
**Week 5:** DualCPU lockstep works with separate memory ✓
**Week 12:** Full boot validated, zero divergences ✓
**Week 16:** Production QEMU with JIT, UAE deleted ✓

---

## Current Status

**Completed:**
- ✅ Weeks 1-3: Foundation (QEMU, hooks, memory)
- ✅ Week 4: Planning complete (CORRECTED)

**Next:**
- 📋 Week 4: Implement execution loop
- 📋 Week 5: Implement DualCPU harness
- 📋 Weeks 6-12: Validation
- 📋 Week 13+: Production

**Timeline:** On track for 16-week migration!

---

## References

- [WEEK4_EXECUTION_AND_DUALCPU_DESIGN.md](WEEK4_EXECUTION_AND_DUALCPU_DESIGN.md) - Full design
- [Week 3 Memory Integration](WEEK3_MEMORY_INTEGRATION.md)
- [DualCPU Testing Approach](DUALCPU_TESTING_APPROACH.md)

---

**Ready for implementation!** 🚀
