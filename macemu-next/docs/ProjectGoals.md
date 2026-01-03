# Project Goals and Vision

What we're building and why.

---

## Mission Statement

**Build a fast, maintainable Mac emulator using Unicorn M68K CPU with dual-CPU validation for correctness.**

---

## The End Goal

### Primary: Unicorn-Based Emulator

**What**: Mac emulator that uses Unicorn Engine as its CPU

**Why Unicorn**:
- ✅ **Fast**: JIT compilation (10-50x faster than interpreter)
- ✅ **Maintained**: Active upstream project (QEMU-based)
- ✅ **Clean API**: Simple C API, easy to integrate
- ✅ **Cross-platform**: Works on Linux, macOS, Windows
- ✅ **Well-tested**: Used in security research, reverse engineering

**Current State**: Unicorn backend executes 200k+ instructions with full trap/interrupt support

**Target State**:
- Boot Mac OS 7/8 to desktop
- Run Mac applications (HyperCard, games, productivity software)
- Competitive performance with UAE JIT
- Clean, maintainable codebase

### Secondary: Modern Architecture

**Goals**:
1. **Platform API Abstraction** - Backend-independent core code
2. **Meson Build System** - Fast, cross-platform builds
3. **Modular Design** - Clear separation of concerns
4. **Comprehensive Documentation** - Explain quirks, design decisions
5. **Continuous Validation** - Catch bugs early via dual-CPU mode

**Not Goals**:
- ❌ Rewrite everything from scratch (reference BasiliskII heavily)
- ❌ Support every Mac model (focus on Quadra 650 / 68020 first)
- ❌ Perfect historical accuracy (pragmatic emulation over cycle-accuracy)

---

## Role of Each Backend

### 1. Unicorn: The Future ⭐

**Purpose**: **Primary backend** for end users

**Status**: Active development focus

**Roadmap**:
- ✅ Basic execution (200k+ instructions)
- ✅ EmulOps (0x71xx traps)
- ✅ A-line/F-line traps
- ✅ Interrupt support
- ✅ Native trap execution
- ⏳ Boot to desktop
- ⏳ Full hardware emulation (VIA, SCSI, Video)
- ⏳ Performance optimization
- ⏳ JIT tuning

**Long-term Vision**:
- Eventually, most users will run Unicorn backend only
- Fast enough for daily use
- Stable enough for productivity

### 2. UAE: The Baseline 📊

**Purpose**: Legacy compatibility and validation reference

**Status**: Fully functional, maintained but not the focus

**Why Keep It**:
- ✅ Proven, stable implementation (decades of development)
- ✅ Validation baseline - if Unicorn differs, UAE is usually right
- ✅ Fallback option - if Unicorn has issues, UAE still works
- ✅ Historical reference - understand original BasiliskII design

**Role in Project**:
- **Validation reference**: "Does Unicorn match UAE behavior?"
- **Compatibility fallback**: Users can switch to UAE if needed
- **Code reference**: Understand how BasiliskII solved problems

**Not Going Away**: UAE will be retained indefinitely for legacy support

**Not the Focus**: New features will prioritize Unicorn

### 3. DualCPU: The Validator 🔍

**Purpose**: **Validation tool** for development

**Status**: Fully functional, critical for development

**How It Works**:
- Run UAE and Unicorn in lockstep
- Execute same instruction on both CPUs
- Compare all registers after each instruction
- Stop immediately on divergence

**Achievements**:
- ✅ Caught VBR register bug (uninitialized memory reads)
- ✅ Caught CPU type selection bug (68030 instead of 68020)
- ✅ Revealed interrupt timing differences
- ✅ Validated 514,000+ instructions with zero divergence

**Role in Project**:
- **Development tool**: Catch bugs immediately during Unicorn development
- **Regression testing**: Verify changes don't break existing functionality
- **Understanding divergence**: Analyze why/when UAE and Unicorn differ

**Not for End Users**: DualCPU is ~2x slower (runs both CPUs), only for development

---

## Development Philosophy

### 1. Reference BasiliskII Heavily

**Don't Reinvent**: BasiliskII solved these problems over decades

**Do Understand**: Read BasiliskII code, understand approach, then adapt

**Example**:
- ✅ Use direct addressing (proven fast)
- ✅ Copy EmulOp system (elegant trap mechanism)
- ✅ Reference ROM patches (know what Mac OS expects)
- ❌ Copy UAE CPU verbatim (we're building Unicorn backend)

### 2. Validate Continuously

**Dual-CPU Mode**: Run after every significant change

**Catch Bugs Early**: Better to fail at instruction 100 than 100,000

**Example**:
```bash
# After implementing interrupt support:
EMULATOR_TIMEOUT=30 CPU_BACKEND=dualcpu ./build/macemu-next ~/quadra.rom

# If it validates 500k+ instructions → probably correct
# If it diverges at 1k instructions → definitely a bug
```

### 3. Document Everything

**Quirks are Important**: UAE and Unicorn have surprising behavior

**Future You Will Thank You**: 6 months later, why did we do this?

**Example Documentation**:
- Why VBR reads returned garbage (missing Unicorn API)
- Why CPU type enum doesn't match array (Unicorn internals)
- Why interrupt timing differs (wall-clock vs instruction-count)

### 4. Performance Matters

**Hook Optimization**: UC_HOOK_CODE → UC_HOOK_BLOCK (10x improvement)

**JIT-Friendly**: Minimize cache invalidation, reduce hook overhead

**Profile and Measure**: Don't guess, measure actual performance

---

## Roadmap

### Phase 1: Core CPU Emulation ✅ **COMPLETE**

- ✅ Unicorn M68K backend running
- ✅ EmulOp system working
- ✅ A-line/F-line traps
- ✅ Interrupt support
- ✅ Native trap execution (no UAE dependency)
- ✅ Dual-CPU validation (514k+ instructions)
- ✅ Hook optimization (UC_HOOK_BLOCK)

**Outcome**: Unicorn executes 200k+ instructions successfully

### Phase 2: Boot to Desktop 🎯 **CURRENT FOCUS**

**Goal**: Unicorn backend boots Mac OS 7 to desktop

**Blockers**:
- ⏳ Understand interrupt timing divergence
- ⏳ Investigate why Unicorn stops at 200k (vs UAE 250k+)
- ⏳ Possibly need more hardware emulation

**Tasks**:
- Functional testing (not just instruction traces)
- Memory state comparison (UAE vs Unicorn at key points)
- Hardware emulation basics (VIA timer, SCSI stubs)

**Success Criteria**: See Mac OS desktop, mouse cursor moves

### Phase 3: Application Support ⏳ **FUTURE**

**Goal**: Run Mac applications successfully

**Examples**:
- HyperCard stacks
- Classic games (Marathon, SimCity 2000)
- Productivity software (PageMaker, MacWrite)

**Requirements**:
- Full hardware emulation (SCSI, video, sound, serial)
- ROM patching complete
- Stable execution (hours, not minutes)

### Phase 4: Performance & Polish ⏳ **FUTURE**

**Goal**: Competitive performance with UAE JIT

**Tasks**:
- Profile Unicorn backend
- Optimize hot paths
- JIT tuning
- Reduce hook overhead further

**Target**: 80-90% of native speed (currently unknown)

### Phase 5: SheepShaver Support ⏳ **FAR FUTURE**

**Goal**: Mac OS 9, PowerPC support

**Note**: Very far out, focus is 68K first

---

## Success Metrics

### Short-Term (Q1 2026)
- ✅ 500k+ instruction dual-CPU validation (ACHIEVED: 514k+)
- ⏳ Boot Mac OS 7 to desktop with Unicorn
- ⏳ Understand interrupt timing characteristics

### Medium-Term (2026)
- ⏳ Run HyperCard successfully
- ⏳ Play one classic game (e.g., Dark Castle)
- ⏳ Stable 30+ minute sessions

### Long-Term (Future)
- ⏳ Full hardware emulation
- ⏳ Mac OS 8 support
- ⏳ Performance competitive with UAE JIT

---

## Non-Goals

**What We're NOT Trying to Do**:

1. **Cycle-Accurate Emulation** - We're pragmatic, not perfect
2. **Support Every Mac Model** - Focus on Quadra 650 / 68020 first
3. **Rewrite Everything** - Reference BasiliskII, don't reinvent
4. **Replace BasiliskII for Users** - This is a research/learning project
5. **Support Pre-68020 Macs** - 68020+ only (too much work for 68000/68010)

---

## Why This Project Exists

### Technical Goals
- Learn emulator architecture
- Explore dual-CPU validation approach
- Modern build system (Meson) for classic emulator
- Clean abstraction layers (Platform API)

### Practical Goals
- Preserve access to classic Mac software
- Faster emulation via Unicorn JIT
- Maintainable codebase (vs. 30-year-old BasiliskII)

### Research Goals
- Differential testing (UAE vs Unicorn)
- Document quirks and design decisions
- Explore JIT optimization strategies

---

## Contributing

### What We Need Help With
1. **Hardware Emulation** - VIA, SCSI, video details
2. **Performance Optimization** - JIT tuning, profiling
3. **Testing** - Run Mac applications, report issues
4. **Documentation** - Explain Mac OS internals, ROM behavior

### What to Expect
- **Unicorn-first development** - New features target Unicorn
- **Dual-CPU validation** - Major changes need validation testing
- **Documentation required** - Quirks must be documented

---

## Summary

**Unicorn**: ⭐ The future - primary backend, active development
**UAE**: 📊 The baseline - legacy support, validation reference
**DualCPU**: 🔍 The validator - development tool, catch bugs early

**End Goal**: Fast, clean, validated Mac emulator using Unicorn M68K CPU

**Current Status**: Core CPU emulation complete, working toward boot-to-desktop

**Philosophy**: Reference BasiliskII, validate continuously, document everything
