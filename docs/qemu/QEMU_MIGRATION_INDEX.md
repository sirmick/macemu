# QEMU CPU Migration - Documentation Index

## Overview

This directory contains complete documentation for migrating BasiliskII and SheepShaver from their custom CPU emulators (UAE/KheperX) to QEMU's m68k and PPC emulation.

**TL;DR:** Replace custom CPUs with QEMU, validate with side-by-side testing harness, gain ARM64 JIT support and better maintainability in 4 months.

## Documents

### 1. [QEMU_MIGRATION_SUMMARY.md](QEMU_MIGRATION_SUMMARY.md) - **START HERE**
**Read this first for the big picture.**

Executive summary covering:
- Why QEMU?
- Why full CPU replacement (not just JIT)?
- Key integration points
- Benefits and risks
- 4-month timeline
- Decision points

**Audience:** Decision makers, project leads
**Length:** 15 min read

---

### 2. [QEMU_FEASIBILITY_ANALYSIS.md](QEMU_FEASIBILITY_ANALYSIS.md)
**Technical deep-dive on feasibility.**

Detailed analysis of:
- JIT-only replacement (❌ not recommended)
- Full CPU replacement (✅ recommended)
- Integration point analysis
  - EmulOp/NativeOp system ✅
  - Memory access ⚠️
  - ROM patching ✅
  - Device emulation ✅
  - 68k↔PPC switching ✅
- Effort estimation
- Risk assessment

**Audience:** Technical leads, architects
**Length:** 30 min read

---

### 3. [DUALCPU_TESTING_APPROACH.md](DUALCPU_TESTING_APPROACH.md) - **THE KEY INNOVATION**
**How to avoid "months of fucking around".**

Explains the DualCPU testing harness:
- Run legacy and QEMU CPUs side-by-side
- Compare execution after every instruction (or periodically)
- Catch divergences immediately with full context
- Binary search to pinpoint exact divergence
- Offline trace analysis

**Execution Modes:**
- Lockstep (exact, slow)
- Periodic (balanced)
- Checkpoint (fast)
- Trace-only (offline analysis)

**Audience:** Developers, testers
**Length:** 25 min read
**Importance:** ⭐⭐⭐ This is what makes the whole project tractable

---

### 4. [TESTING_STRATEGY.md](TESTING_STRATEGY.md)
**10-week testing plan with concrete examples.**

Phase-by-phase testing:
- Phase 0: Sanity check (Week 1)
- Phase 1: Instruction validation (Weeks 2-3)
- Phase 2: ROM execution (Weeks 4-5)
- Phase 3: Full boot (Weeks 6-8)
- Phase 4: Interactive testing (Weeks 9-10)

Each phase includes:
- Concrete test commands
- Success metrics
- Debugging workflows
- Example divergence scenarios

**Audience:** Developers, QA engineers
**Length:** 35 min read

---

### 5. [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)
**Week-by-week implementation plan.**

16-week roadmap:
- **Weeks 1-2:** QEMU integration + DualCPU harness
- **Weeks 3-8:** Instruction validation
- **Weeks 9-12:** ROM boot + full boot
- **Weeks 13-14:** Performance tuning + regression tests
- **Weeks 15-16:** SheepShaver PPC

Includes:
- Specific tasks per week
- Code examples
- Go/no-go decision points
- Success criteria

**Audience:** Developers, project managers
**Length:** 40 min read

---

### 6. [TRACE_FORMAT.md](TRACE_FORMAT.md)
**Binary and text trace file specifications.**

Documents:
- Binary trace format (128 bytes/instruction)
- Text trace format (human-readable)
- Compression (LZ4)
- Differential trace format (showing divergences)

**Audience:** Developers working on trace tools
**Length:** 10 min read

---

### 7. [ARCHITECTURE.md](ARCHITECTURE.md) - **EXISTING**
**Current emulator architecture.**

Documents the existing system:
- CPU emulation (UAE/KheperX)
- Memory architecture
- ROM patching system
- EmulOp mechanism
- Execution flow

**Useful for:** Understanding what we're replacing

---

## Quick Reference

### For Decision Makers
1. Read [QEMU_MIGRATION_SUMMARY.md](QEMU_MIGRATION_SUMMARY.md)
2. Review timeline and decision points
3. Decide: proceed, defer, or reject

**Decision:** ✅ Recommend proceeding

---

### For Technical Leads
1. Read [QEMU_FEASIBILITY_ANALYSIS.md](QEMU_FEASIBILITY_ANALYSIS.md)
2. Review integration points
3. Assess risks for your context
4. Read [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)

**Assessment:** ✅ Technically sound, well-scoped

---

### For Developers
1. Read [DUALCPU_TESTING_APPROACH.md](DUALCPU_TESTING_APPROACH.md)
2. Read [TESTING_STRATEGY.md](TESTING_STRATEGY.md)
3. Read [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md)
4. Start with Week 1 tasks

**Action:** Start with proof-of-concept in `test/` directory

---

### For QA/Testers
1. Read [DUALCPU_TESTING_APPROACH.md](DUALCPU_TESTING_APPROACH.md)
2. Read [TESTING_STRATEGY.md](TESTING_STRATEGY.md)
3. Familiarize with trace tools in `test/`

**Action:** Help design regression test suite

---

## Key Concepts

### DualCPU Testing Harness
The core innovation that makes this project tractable:

```
┌──────────────┐    ┌──────────────┐
│  Legacy CPU  │    │   QEMU CPU   │
│  (Proven)    │    │  (New)       │
└──────┬───────┘    └──────┬───────┘
       │   Same code    │
       │   Same memory  │
       │   Same input   │
       ↓                ↓
    Execute          Execute
       │                │
       └────┬───────────┘
            ↓
         Compare
            │
    ┌───────┴────────┐
    ↓                ↓
  Match?         Diverge?
  Continue       STOP & DEBUG!
```

**Result:** Any difference caught immediately with full context.

---

### EmulOps - The Integration Boundary
Special illegal opcodes that trap to emulator:

```cpp
// ROM code contains: 0x7100 (M68K_EMUL_OP_VIDEO_OPEN)
// CPU encounters illegal opcode
// Trap handler:
void EmulOp(uint16 opcode, M68kRegisters *r) {
    switch (opcode) {
        case M68K_EMUL_OP_VIDEO_OPEN:
            VideoOpen();  // Native host code
            break;
    }
}
```

**Key insight:** This boundary is orthogonal to CPU choice.
- UAE CPU: traps on 0x71xx → calls EmulOp()
- QEMU CPU: traps on 0x71xx → calls EmulOp()

Same interface, same device code, different CPU underneath.

---

### Trace Files - Offline Analysis
Instead of comparing in real-time, record execution:

```bash
# Generate traces (fast, no comparison overhead)
./dualcpu --mode trace-only \
    --trace-legacy boot.legacy.trace.lz4 \
    --trace-qemu boot.qemu.trace.lz4

# Compare later
./trace_diff boot.legacy.trace.lz4 boot.qemu.trace.lz4

# Output: exact divergence point with full context
```

**Benefit:** Run both CPUs at full speed, analyze at leisure.

---

## Timeline Summary

| Phase | Duration | Deliverable |
|-------|----------|-------------|
| **Foundation** | Weeks 1-2 | QEMU integrated, harness working |
| **Validation** | Weeks 3-8 | All instructions validated |
| **ROM Boot** | Weeks 9-12 | Boots to Finder |
| **Polish** | Weeks 13-16 | Production ready |

**Total:** 16 weeks (4 months)

**Go/No-Go Points:**
- Week 2: Basic integration working? Performance OK?
- Week 8: Instructions validated? On track?
- Week 12: Boots to Finder? No blockers?

---

## Benefits

### Immediate
- ✅ **ARM64 JIT** - Works out of the box
- ✅ **Less code** - Delete ~30K lines of CPU emulation
- ✅ **Better testing** - QEMU's extensive test suite

### Long-term
- ✅ **Maintenance** - QEMU team maintains CPU core
- ✅ **Bug fixes** - Upstream fixes CPU bugs
- ✅ **Features** - MTTCG, record/replay, etc.
- ✅ **Multi-arch** - RISC-V, ARM32, MIPS, etc.

### Strategic
- ✅ **Future-proof** - QEMU actively developed
- ✅ **Community** - Large QEMU community
- ✅ **Tooling** - GDB stub, tracing, profiling

---

## Risks & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Performance too slow | Medium | High | Benchmark Week 2, abort if >3x |
| Integration too complex | Low | Medium | Clean boundaries, prototype Week 1 |
| Subtle bugs hard to find | Low | High | DualCPU catches everything |
| Takes too long | Low | Medium | 3 go/no-go points to abort |

**Overall Risk:** Medium-Low with proper testing approach

---

## Success Criteria

### Must Have (Week 12)
- Boots to Finder on BasiliskII
- All instruction tests pass (0 divergences)
- Performance within 2x of legacy JIT
- EmulOps working correctly

### Should Have (Week 16)
- SheepShaver working
- CI regression tests
- Performance tuning complete

### Nice to Have (Post-launch)
- ARM64 builds
- Performance parity
- QEMU upstream contributions

---

## Getting Started

### Proof of Concept (Day 1)
```bash
cd macemu/test
make
./dual_cpu_example --test basic
```

### Week 1 (Developers)
1. Read [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) Week 1 section
2. Clone QEMU repo
3. Build QEMU for m68k
4. Create minimal adapter
5. Execute first instruction

### Week 2 (Developers)
1. Implement DualCPU harness
2. Benchmark performance
3. Run first comparison test
4. Make go/no-go decision

---

## Additional Resources

### Code
- `test/dual_cpu_harness.h` - Testing API
- `test/dual_cpu_example.cpp` - Usage examples
- `test/trace_diff.cpp` - Trace comparison tool
- `test/Makefile` - Build system

### External Links
- [QEMU Documentation](https://www.qemu.org/docs/master/)
- [QEMU TCG Internals](https://www.qemu.org/docs/master/devel/tcg.html)
- [QEMU m68k Target](https://wiki.qemu.org/Documentation/Platforms/m68k)

---

## FAQ

**Q: Why not just keep the current JIT?**
A: Current JIT only works on x86/x64. We want ARM64 support.

**Q: Why full CPU replacement instead of just porting the JIT?**
A: Clean integration boundaries (EmulOps, ROM patching), less total work, more benefits.

**Q: How do we know QEMU will work correctly?**
A: DualCPU testing harness validates every instruction matches legacy behavior.

**Q: What if it's too slow?**
A: Benchmark in Week 2. If >3x slower, abort. QEMU is generally quite fast.

**Q: What about SheepShaver?**
A: Same approach, apply lessons from BasiliskII. Weeks 15-16.

**Q: Can we keep the old CPU as fallback?**
A: Yes! Make QEMU opt-in initially (`--enable-qemu-cpu`), keep legacy as default until proven.

**Q: What if we find bugs in QEMU?**
A: Report upstream, contribute fixes. QEMU community is responsive.

**Q: Is 4 months realistic?**
A: Yes, with DualCPU testing. Without it, could be 12+ months of debugging.

---

## Conclusion

The QEMU CPU migration is:
- ✅ **Feasible** - Clean integration points
- ✅ **Testable** - DualCPU validates empirically
- ✅ **Valuable** - ARM64 support, better maintenance
- ✅ **Scoped** - 4 months with clear milestones

**The key innovation:** DualCPU testing eliminates guesswork and provides instant feedback on correctness.

**Recommendation:** Proceed with BasiliskII m68k first, using the roadmap provided.

---

## Document History

- 2024-XX-XX: Initial documentation created
- Based on discussion and analysis session

## Authors

- Analysis and design based on conversation with project contributor
- Documentation written to capture the feasibility study and implementation plan

## License

These documents are part of the BasiliskII/SheepShaver project and follow the same GPL v2 license.
