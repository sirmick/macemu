# QEMU CPU Migration - Executive Summary

## TL;DR

**Replace BasiliskII/SheepShaver custom CPUs with QEMU's m68k/PPC emulation.**

- ✅ **Feasible**: Clean integration points (EmulOps, ROM patching orthogonal)
- ✅ **Testable**: DualCPU harness validates correctness empirically
- ⏱️ **Timeline**: 3-4 months with robust testing (not "months of fucking around")
- 🎁 **Payoff**: ARM64 JIT, better maintenance, multi-architecture support

---

## Why QEMU?

| Current (UAE/KheperX) | With QEMU |
|----------------------|-----------|
| x86/x64 JIT only | **ARM64, RISC-V, etc. JIT** |
| ~30K lines CPU code to maintain | QEMU team maintains it |
| Dyngen (outdated, pre-2005) | Modern TCG (actively developed) |
| Single-threaded only | MTTCG support available |
| Custom optimizations | Sophisticated TCG optimization passes |

---

## Key Insight: Clean Boundaries

The emulator has **three orthogonal layers**:

```
┌──────────────────────────────────────┐
│  Emulated Devices (video, disk, etc) │ ← NO CHANGES
├──────────────────────────────────────┤
│  EmulOp/ROM Patch Layer              │ ← MINIMAL CHANGES
├──────────────────────────────────────┤
│  CPU Emulation                        │ ← SWAP UAE/KheperX → QEMU
└──────────────────────────────────────┘
```

### Integration Points

**1. EmulOps (Illegal Instruction Traps)**
- Current: UAE catches 0x71xx opcodes → calls `EmulOp()`
- QEMU: Register illegal instruction handler → calls `EmulOp()`
- **Effort**: ~1 week

**2. Memory Access**
- Current: Direct pointer (`RAMBaseHost + addr`)
- QEMU: Memory API (`cpu_physical_memory_read/write`)
- **Options**:
  - Adapter layer (1 week)
  - Use QEMU's direct-mapped mode (2 days)
- **Effort**: ~1 week

**3. ROM Patching**
- Current: Patch ROM before CPU sees it
- QEMU: **Identical** - patch before passing to QEMU
- **Effort**: 0 days (no changes!)

**4. Device Emulation**
- Current: Called from EmulOp handlers
- QEMU: Called from EmulOp handlers (via different path)
- **Effort**: 0 days (no changes!)

---

## The Testing Solution: DualCPU Harness

Instead of "months of fiddly details", we **validate empirically**:

### Architecture
```
┌─────────────┐  ┌─────────────┐
│ Legacy CPU  │  │  QEMU CPU   │
│ (UAE/       │  │  (m68k/PPC) │
│  KheperX)   │  │             │
└──────┬──────┘  └──────┬──────┘
       │                 │
       └────────┬────────┘
                ↓
       ┌────────────────┐
       │ Dual Harness   │
       │ - Compare      │
       │ - Trace        │
       │ - Divergence   │
       └────────────────┘
```

### Testing Phases (10 weeks)

| Week | Phase | Goal | Success |
|------|-------|------|---------|
| 1 | Sanity | Basic instructions work | MOVE/ADD execute |
| 2-3 | Instructions | Validate all opcodes | 10K instructions, 0 divergences |
| 4-5 | ROM Boot | Run actual ROM code | Reach driver init |
| 6-8 | Full Boot | Boot to Finder | Desktop appears |
| 9-10 | Interactive | User input works | Mouse/keyboard identical |

### Key Features

**1. Multiple Comparison Modes**
- **Lockstep**: Compare every instruction (slow, precise)
- **Periodic**: Compare every Nth instruction (fast, good balance)
- **Checkpoint**: Compare at key PCs (very fast)
- **Trace-only**: Record for offline analysis (fastest)

**2. Trace Format**
```
[000042891] PC=0040a3c2 SR=2004 D0=00000001
            OPCODE: 51c8fffc  DBF D0,$40a3c0

DIVERGENCE: Legacy branched, QEMU didn't
  Legacy PC: 0040a3c0
  QEMU PC:   0040a3c4
```

**3. Binary Search for Divergences**
```bash
# Found divergence around instruction 4,285,000
# Narrow down:
./test-dualcpu --mode lockstep \
    --start 4284000 --end 4286000

# Exact divergence: instruction 4,285,127
./trace_replay --instruction 4285127 --debug
```

---

## Practical Timeline

### Month 1: QEMU Integration Core
- Week 1: Build QEMU as library, basic adapter
- Week 2: Memory system bridge
- Week 3: EmulOp handler registration
- Week 4: First boot attempt, debug

### Month 2: Instruction Validation
- Week 5-6: Run instruction test suite (Phase 1)
- Week 7-8: Debug divergences, fix edge cases

### Month 3: ROM Execution
- Week 9-10: ROM boot sequence (Phase 2)
- Week 11-12: Full boot to Finder (Phase 3)

### Month 4: Polish & Performance
- Week 13-14: Interactive testing (Phase 4)
- Week 15-16: Performance tuning, regression tests

**Total: 4 months (not "months of fucking around")**

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| "QEMU might be slower" | Benchmark early (Week 2), abort if >2x slower |
| "Subtle bugs hard to find" | DualCPU catches them immediately |
| "QEMU integration complex" | Start with m68k (simpler), then PPC |
| "What if it doesn't work?" | Keep legacy CPU, make QEMU opt-in (`--enable-qemu`) |

---

## Deliverables

### Code
```
macemu/
├── qemu-cpu/                    # QEMU integration
│   ├── qemu_adapter.cpp        # Main adapter
│   ├── qemu_helpers.c          # EmulOp/NativeOp helpers
│   └── qemu_memory.cpp         # Memory bridge
├── test/                        # Testing harness
│   ├── dual_cpu_harness.cpp    # Dual execution
│   ├── trace_diff.cpp          # Trace comparison
│   └── instruction_tests/      # Validation suite
└── docs/
    ├── QEMU_INTEGRATION.md     # How it works
    └── TESTING_STRATEGY.md     # How to validate
```

### Documentation
- Integration guide
- Testing procedures
- Performance benchmarks
- Regression test suite

---

## Decision Points

### Week 2: Go/No-Go #1
**Question**: Is QEMU integration fundamentally sound?
- Can we execute basic instructions?
- Is memory access working?
- Can we call EmulOps?

**If NO**: Abort, cost = 2 weeks

### Week 8: Go/No-Go #2
**Question**: Are we on track for completion?
- Instruction tests passing?
- ROM boot working?
- Performance acceptable?

**If NO**: Abort, cost = 8 weeks

### Week 12: Go/No-Go #3
**Question**: Does it boot to Finder?
- Full boot working?
- No showstopper bugs?

**If NO**: Keep as experimental feature, cost = 12 weeks

---

## Recommendation

**Proceed with QEMU migration using DualCPU testing harness.**

### Why?
1. **Clean architecture** - Integration points are well-defined
2. **Empirical validation** - Testing catches all divergences
3. **Manageable scope** - 4 months is reasonable for this payoff
4. **Incremental risk** - Multiple decision points to abort
5. **Huge upside** - ARM64 support alone is worth it

### Start with BasiliskII m68k
- Simpler than SheepShaver (no 68k↔PPC switching)
- Well-understood instruction set
- Smaller ROM (easier to debug)
- Lessons learned apply to SheepShaver

### Then SheepShaver PPC
- Apply lessons from BasiliskII
- More complex but validated approach
- Dual-mode (68k/PPC) is just two CPUs

---

## Next Steps

1. **Week 1**: Build QEMU as library
   ```bash
   cd qemu
   ./configure --target-list=m68k-softmmu --enable-pie
   make -j8
   ```

2. **Week 1**: Implement minimal adapter
   ```cpp
   CPUM68KState *qemu_cpu = cpu_m68k_init("m68040");
   cpu_exec(qemu_cpu);
   ```

3. **Week 1**: First instruction test
   ```cpp
   // MOVE.W #$1234,D0
   uint8_t code[] = {0x30, 0x3c, 0x12, 0x34};
   run_dual_test(code, sizeof(code));
   ```

4. **Week 2**: Build out DualCPU harness
   - Implement snapshot/compare
   - Add trace generation
   - Create trace_diff tool

5. **Week 3+**: Execute testing strategy from [TESTING_STRATEGY.md](TESTING_STRATEGY.md)

---

## Questions?

- **"Will this break existing functionality?"**
  No - keep legacy CPU as fallback, QEMU is opt-in initially.

- **"How do we know it's correct?"**
  DualCPU harness validates every instruction matches legacy behavior.

- **"What if QEMU is too slow?"**
  Benchmark in Week 2, abort if >2x slower than legacy JIT.

- **"How do we debug divergences?"**
  Trace files show exact instruction where CPUs diverged, with full register/memory state.

- **"Can we do this incrementally?"**
  Yes - BasiliskII first, then SheepShaver. Or even keep QEMU experimental.

---

**Bottom line: This is doable, testable, and worth it.**
