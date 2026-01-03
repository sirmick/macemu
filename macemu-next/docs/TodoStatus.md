# TODO Status

Track what's done and what's next.

---

## Phase 1: Core CPU Emulation ✅ COMPLETE

### Build System
- ✅ Meson build configuration
- ✅ UAE CPU compilation
- ✅ Unicorn integration (git submodule)
- ✅ Backend selection via Meson options

### Memory System
- ✅ Direct addressing mode
- ✅ ROM loading (1MB Quadra 650 ROM)
- ✅ RAM allocation (configurable size)
- ✅ Endianness handling (UAE LE RAM, BE ROM)
- ✅ Byte-swapping when copying to Unicorn

### UAE Backend
- ✅ Full 68020 interpreter integrated
- ✅ Memory system (mem_banks, get_long/put_long)
- ✅ Exception handling (A-line, F-line traps)
- ✅ EmulOp support (0x71xx traps)
- ✅ Interrupt processing (SPCFLAG_INT)

### Unicorn Backend
- ✅ Unicorn engine initialization
- ✅ Memory mapping (RAM, ROM, dummy regions)
- ✅ Register access (D0-D7, A0-A7, PC, SR)
- ✅ **VBR register support** (added missing API, commit 006cc0f8)
- ✅ **CPU type selection fix** (68020 not 68030, commit 74fbd578)
- ✅ **Hook architecture optimization** (UC_HOOK_BLOCK + UC_HOOK_INSN_INVALID)
- ✅ EmulOp handling (0x71xx traps)
- ✅ A-line/F-line trap handling (0xAxxx, 0xFxxx)
- ✅ **Interrupt support** (UC_HOOK_BLOCK for efficiency, commit 1305d3b2)
- ✅ **Native 68k trap execution** (no UAE dependency, commit d90208dc)
- ✅ **Legacy API removal** (~236 lines, commit ebd3d1b2)

### DualCPU Backend
- ✅ Lockstep execution (UAE + Unicorn)
- ✅ Register comparison after each instruction
- ✅ Divergence detection and logging
- ✅ Trace history (circular buffer)
- ✅ **514,000+ instruction validation** (commit 155497f0)

### Platform API
- ✅ Platform struct with function pointers
- ✅ Backend-independent core code
- ✅ Runtime backend selection (CPU_BACKEND env var)
- ✅ Trap handlers (emulop_handler, trap_handler)
- ✅ **68k trap execution API** (cpu_execute_68k_trap)

---

## Phase 2: Boot to Desktop 🎯 CURRENT FOCUS

### Interrupt Timing
- ✅ Understand divergence root cause (wall-clock vs instruction-count)
- ✅ Document in InterruptTimingAnalysis.md
- ⏳ **Decision**: Accept non-determinism or add deterministic mode?
- ⏳ Functional testing approach (not just trace comparison)

### Execution Length
- ⏳ Investigate why Unicorn stops at ~200k (vs UAE 250k+)
- ⏳ Memory state comparison at key points
- ⏳ Analyze cumulative effects of interrupt timing

### Hardware Emulation (Basic)
- ⏳ VIA timer chip basics
- ⏳ SCSI stubs (enough for boot)
- ⏳ Video framebuffer basics

### Boot Testing
- ⏳ Boot Mac OS 7.0 to desktop
- ⏳ Mouse cursor visible
- ⏳ Basic responsiveness

---

## Phase 3: Application Support ⏳ FUTURE

### Full Hardware Emulation
- ⏳ VIA (Versatile Interface Adapter) complete
- ⏳ SCSI (disk access) functional
- ⏳ Video (framebuffer, display modes)
- ⏳ Audio (sound output)
- ⏳ Serial (modem, printer ports)
- ⏳ Ethernet (networking)

### ROM Patching
- ⏳ Identify all ROM patches needed
- ⏳ Implement trap optimization
- ⏳ Mac OS API emulation completeness

### Application Testing
- ⏳ HyperCard stacks run
- ⏳ Classic game playable (e.g., Dark Castle, Marathon)
- ⏳ Productivity software (MacWrite, PageMaker)

### Stability
- ⏳ 30+ minute sessions without crash
- ⏳ Save/restore state
- ⏳ Error recovery

---

## Phase 4: Performance & Polish ⏳ FUTURE

### Performance Optimization
- ⏳ Profile Unicorn backend
- ⏳ Optimize hot paths
- ⏳ JIT tuning
- ⏳ Reduce hook overhead further (if possible)

### User Interface
- ⏳ SDL-based window/input
- ⏳ Preferences UI
- ⏳ Debugger integration (step, breakpoints)

### Testing & CI
- ⏳ Automated testing suite
- ⏳ Regression tests
- ⏳ Continuous integration (GitHub Actions)

---

## Phase 5: PowerPC Support ⏳ FAR FUTURE

### SheepShaver Integration
- ⏳ PowerPC CPU backend
- ⏳ Mac OS 8.5-9.0.4 support
- ⏳ Mixed-mode (68K + PPC) execution

**Note**: Very far out, 68K focus first

---

## Bug Fixes & Investigations

### Completed ✅
- ✅ **VBR corruption** (missing Unicorn register API, commit 006cc0f8)
  - Symptom: VBR reads returned garbage (0xCEDF1400, etc.)
  - Fix: Added UC_M68K_REG_CR_VBR to reg_read/reg_write
  - Impact: +330% execution (23k → 100k instructions)

- ✅ **CPU type mismatch** (enum/array confusion, commit 74fbd578)
  - Symptom: Unicorn created 68030 instead of 68020
  - Fix: Use array indices not UC_CPU_M68K_* enum values
  - Impact: Both backends now correctly create 68020

- ✅ **Interrupt support** (Unicorn ignored interrupts, commit 1305d3b2)
  - Symptom: Divergence at ~29k instructions, crash at ~175k
  - Fix: UC_HOOK_BLOCK for interrupts, shared PendingInterrupt flag
  - Impact: Both backends process timer/ADB interrupts

- ✅ **Hybrid execution crash** (UAE dependency, commit d90208dc)
  - Symptom: Unicorn crashed at 175k when EmulOps called Execute68kTrap
  - Fix: Unicorn-native 68k trap execution
  - Impact: +24,696 instructions (175k → 200k), no UAE dependency

- ✅ **Performance overhead** (UC_HOOK_CODE, commit ebd3d1b2)
  - Symptom: 10x slowdown from per-instruction hook
  - Fix: UC_HOOK_INSN_INVALID for EmulOps, UC_HOOK_BLOCK for interrupts
  - Impact: Expected 5-10x performance improvement

### Active Investigations ⏳
- ⏳ **Timer interrupt timing** (wall-clock vs instruction-count)
  - Status: Understood (see deepdive/InterruptTimingAnalysis.md)
  - Not a bug, but a characteristic
  - Decision needed: accept or add deterministic mode

- ⏳ **Unicorn execution length** (200k vs UAE 250k)
  - Status: Under investigation
  - Possible cumulative effect of interrupt timing
  - Need functional testing approach

---

## Documentation

### Completed ✅
- ✅ README.md - Quick start guide
- ✅ Architecture.md - Platform API, backend abstraction
- ✅ ProjectGoals.md - Vision, Unicorn-first focus
- ✅ TodoStatus.md - This file
- ✅ Commands.md - Build, test, trace commands
- ✅ completed/ folder - Archived historical docs
- ✅ deepdive/ folder - Detailed technical docs

### Needed ⏳
- ⏳ Testing guide (functional testing approach)
- ⏳ Contributing guide (code style, PR process)
- ⏳ Troubleshooting guide (common issues, solutions)

---

## Recent Commits (Dec 2025 - Jan 2026)

```
d90208dc - Implement Unicorn-native 68k trap execution to eliminate UAE dependency
ebd3d1b2 - Remove legacy per-CPU hook API and UC_HOOK_CODE implementation
1305d3b2 - WIP: Interrupt support implementation (needs optimization)
50947779 - Add sequential trace comparison mode to find exact divergence points
74fbd578 - Fix Unicorn CPU type selection to match UAE cpu_level calculation
006cc0f8 - Fix VBR corruption in Unicorn M68K backend by adding missing register API support
543ef3c8 - Add 16MB dummy region to standalone Unicorn backend for UAE compatibility
155497f0 - Progress checkpoint: DualCPU validation now reaches 514k instructions
fecf542b - Add platform API for CPU type configuration and remove hardcoded defaults
ba7d6487 - Fix host pointer leak in ROM patching causing non-deterministic behavior
```

---

## Next Actions

### Immediate (This Week)
1. ⏳ Review interrupt timing analysis
2. ⏳ Decide on deterministic mode vs acceptance
3. ⏳ Set up functional testing infrastructure

### Short-Term (This Month)
1. ⏳ Investigate 200k execution limit
2. ⏳ Memory state comparison tool
3. ⏳ Basic VIA timer emulation

### Medium-Term (This Quarter)
1. ⏳ Boot to desktop attempt
2. ⏳ Full hardware emulation (VIA, SCSI basics)
3. ⏳ Application testing framework

---

**Last Updated**: January 3, 2026
**Current Phase**: Phase 2 (Boot to Desktop)
**Focus**: Understanding interrupt timing, investigating execution length
