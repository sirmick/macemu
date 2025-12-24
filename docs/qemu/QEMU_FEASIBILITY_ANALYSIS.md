# QEMU CPU Migration Feasibility Analysis

## Executive Summary

**Question:** Can we replace BasiliskII/SheepShaver's homegrown JIT compilers with QEMU's TCG (Tiny Code Generator)?

**Answer:** Yes, but replacing the **entire CPU emulator** (not just the JIT) is the better approach.

## Background

### Current Architecture

**BasiliskII (m68k emulation):**
- Uses UAE-derived CPU emulator
- JIT compiler in `uae_cpu/compiler/` (x86/x64 only)
- ~15,000 lines of CPU emulation code
- Direct x86 code generation with register allocation

**SheepShaver (PPC emulation):**
- Uses "KheperX" custom PPC emulator
- Uses **dyngen** (early QEMU technique from ~2003-2005)
- ~20,000 lines of CPU emulation code
- Template-based JIT (extracts machine code from compiled C functions)

### Why Consider QEMU?

1. **ARM64 Support** - Current JIT only works on x86/x64
2. **Modern TCG** - QEMU's current technology is far more advanced than dyngen
3. **Maintenance** - QEMU team maintains the CPU core
4. **Multi-architecture** - Get RISC-V, ARM32, etc. for free
5. **Better optimization** - TCG has sophisticated optimization passes

## Analysis: JIT-Only Replacement

### Approach
Replace just the code generation backend (dyngen/UAE JIT) with QEMU TCG while keeping the existing instruction decode and translation logic.

### Architecture
```
Current (SheepShaver):          QEMU TCG Only:
PPC decode                      PPC decode (keep existing)
     ↓                               ↓
Mid-level ops                   Mid-level ops (keep existing)
     ↓                               ↓
dyngen templates            →   TCG IR generation (NEW)
     ↓                               ↓
x86 code                        TCG backend → x86/ARM/etc
```

### ❌ Assessment: Not Recommended

**Cons:**
1. **Impedance mismatch** - Converting mid-level ops to TCG IR is awkward
2. **Lost optimizations** - Current SSE/SSSE3 hand-optimizations for AltiVec
3. **Added complexity** - TCG adds layers (IR generation, optimization, backend)
4. **Uncertain performance** - Overhead might negate benefits
5. **Large effort** - 6-12 months of work for uncertain gains

**Pros:**
- Keeps existing decode/translate logic
- Incremental migration possible

**Verdict:** The cost/benefit doesn't justify this approach.

## Analysis: Full CPU Replacement

### Approach
Replace the entire CPU emulator (UAE/KheperX) with QEMU's m68k/PPC system emulation, keeping only the emulator-specific integration layer.

### Architecture Comparison

```
Current Architecture:
┌─────────────────────────────────────────────┐
│  Main Loop (main_unix.cpp)                  │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐        │
│  │ UAE CPU      │  │ KheperX PPC  │        │
│  │ (m68k)       │  │ CPU          │        │
│  └──────┬───────┘  └──────┬───────┘        │
│         │                  │                 │
│         ↓                  ↓                 │
│  ┌──────────────────────────────┐          │
│  │   EmulOp Handler             │          │
│  │   (emul_op.cpp)              │          │
│  └──────┬───────────────────────┘          │
│         ↓                                    │
│  ┌──────────────────────────────┐          │
│  │  Device Emulation            │          │
│  │  (video, disk, ether, etc)   │          │
│  └──────────────────────────────┘          │
└─────────────────────────────────────────────┘

QEMU-Based Architecture:
┌─────────────────────────────────────────────┐
│  Main Loop (qemu_adapter.cpp) ← NEW         │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐        │
│  │ QEMU m68k    │  │ QEMU PPC     │        │
│  │              │  │              │        │
│  └──────┬───────┘  └──────┬───────┘        │
│         │                  │                 │
│         ↓                  ↓                 │
│  ┌──────────────────────────────┐          │
│  │   Helper Callbacks           │ ← NEW    │
│  │   (qemu_helpers.c)           │          │
│  └──────┬───────────────────────┘          │
│         ↓                                    │
│  ┌──────────────────────────────┐          │
│  │  EmulOp Handler              │ ← SAME!  │
│  │  (emul_op.cpp)               │          │
│  └──────┬───────────────────────┘          │
│         ↓                                    │
│  ┌──────────────────────────────┐          │
│  │  Device Emulation            │ ← SAME!  │
│  │  (video, disk, ether, etc)   │          │
│  └──────────────────────────────┘          │
└─────────────────────────────────────────────┘
```

### ✅ Assessment: Recommended

## Key Integration Points

### 1. EmulOp/NativeOp System ✅ **CLEAN INTEGRATION**

**Current:**
```cpp
// ROM patches inject special opcodes
// m68k: 0x71xx range (illegal MOVEQ)
// PPC:  0x18000000 range (reserved opcode)

// When CPU encounters these:
void EmulOp(uint16 opcode, M68kRegisters *r) {
    switch (opcode) {
        case M68K_EMUL_OP_VIDEO_OPEN:
            VideoOpen();
            break;
        // ... 50+ handlers
    }
}
```

**With QEMU:**
```cpp
// Register illegal instruction handler with QEMU
void qemu_illegal_instruction_handler(CPUState *cpu, uint32_t opcode) {
    if (is_emulop(opcode)) {
        // Convert QEMU registers to legacy format
        M68kRegisters regs;
        qemu_to_legacy_regs(cpu, &regs);

        // Call existing handler
        EmulOp(extract_selector(opcode), &regs);

        // Convert back
        legacy_to_qemu_regs(&regs, cpu);
    }
}
```

**Effort:** 1-2 weeks

**Risk:** Low - This is a well-established pattern in QEMU

### 2. Memory Access ⚠️ **ADAPTER NEEDED**

**Current:**
```cpp
// Direct host memory access
uint8_t *RAMBaseHost;  // Points to Mac RAM in host address space
uint8_t *ROMBaseHost;

// Reading/writing is direct pointer arithmetic
uint32_t ReadMacInt32(uint32_t addr) {
    return ntohl(*(uint32_t *)(RAMBaseHost + addr));
}
```

**With QEMU (Option A - Adapter):**
```cpp
// Bridge QEMU memory API to existing accessors
static uint64_t mac_mem_read(void *opaque, hwaddr addr, unsigned size) {
    switch (size) {
        case 1: return ReadMacInt8(addr);
        case 2: return ReadMacInt16(addr);
        case 4: return ReadMacInt32(addr);
    }
}

static const MemoryRegionOps mac_ram_ops = {
    .read = mac_mem_read,
    .write = mac_mem_write,
};

void setup_memory() {
    memory_region_init_io(&mac_ram, NULL, &mac_ram_ops,
                         NULL, "mac.ram", RAMSize);
}
```

**With QEMU (Option B - Direct mapping):**
```cpp
// Use QEMU's direct memory access mode
void setup_memory() {
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    memory_region_init_ram_ptr(ram, NULL, "mac.ram", RAMSize, RAMBaseHost);
    memory_region_add_subregion(system_memory, 0, ram);
}
```

**Effort:** 1-2 weeks

**Risk:** Medium - Memory access patterns need careful validation

### 3. ROM Patching ✅ **NO CHANGES NEEDED**

**Current:**
```cpp
// rom_patches.cpp - ~53KB of patching code
bool CheckROM() {
    // Detect ROM version by checksum
}

bool PatchROM() {
    // Patch ~50-100 locations in ROM
    // Redirect ROM routines to EmulOps
    WriteMacInt16(0x400a, M68K_EMUL_OP_VIDEO_OPEN);
    // ... etc
}
```

**With QEMU:**
```cpp
// Identical - ROM is patched BEFORE CPU sees it
bool PatchROM() {
    // Exact same code - patch memory buffer
    WriteMacInt16(0x400a, M68K_EMUL_OP_VIDEO_OPEN);
}

// Then pass patched ROM to QEMU
cpu_physical_memory_write(ROM_BASE, ROMBaseHost, ROMSize);
```

**Effort:** 0 days - No changes needed!

**Risk:** None - Orthogonal to CPU choice

### 4. Device Emulation ✅ **NO CHANGES NEEDED**

**Current:**
```cpp
// video.cpp, disk.cpp, ether.cpp, etc.
// Called from EmulOp handlers

void VideoOpen() {
    // Initialize video subsystem
    // Direct access to Mac memory
    uint32_t params = ReadMacInt32(A0);
    // ... device logic
}
```

**With QEMU:**
```cpp
// Identical - still called from EmulOp handlers
// Memory access still works (via adapter or direct mapping)

void VideoOpen() {
    uint32_t params = ReadMacInt32(A0);  // Same!
    // ... identical device logic
}
```

**Effort:** 0 days - No changes needed!

**Risk:** None - Abstracted by EmulOp layer

### 5. 68k ↔ PPC Mode Switching ✅ **QEMU SUPPORTS THIS**

**Current (SheepShaver only):**
```cpp
class sheepshaver_cpu : public powerpc_cpu {
    void execute_68k(uint32 entry, M68kRegisters *r);
    void execute_ppc(uint32 entry);
};
```

**With QEMU:**
```cpp
// Maintain two CPUState structures
CPUM68KState *m68k_cpu;
CPUPPCState *ppc_cpu;

void execute_68k(uint32 entry, M68kRegisters *r) {
    // Copy registers to m68k CPU
    // Run m68k until EXEC_RETURN
    cpu_exec(CPU(m68k_cpu));
}

void execute_ppc(uint32 entry) {
    cpu_exec(CPU(ppc_cpu));
}
```

**Effort:** 2-3 weeks

**Risk:** Medium - Need to handle state synchronization

## Benefits of Full CPU Replacement

### Immediate Benefits
1. **ARM64 JIT** - Works immediately (your README shows ARM64 is currently non-JIT)
2. **Better maintenance** - Delete ~30K lines of CPU code
3. **Modern tooling** - QEMU's GDB stub, tracing, profiling
4. **Bug fixes** - QEMU team fixes CPU bugs
5. **Features** - MTTCG (multi-threaded TCG), record/replay

### Long-term Benefits
1. **Multi-architecture** - RISC-V, ARM32, MIPS, etc.
2. **Better optimization** - TCG optimization passes
3. **Active development** - QEMU TCG actively improved
4. **Community** - Large QEMU community for support
5. **Testing** - QEMU's extensive test suite

## Risks and Mitigation

| Risk | Impact | Mitigation | Timeline |
|------|--------|------------|----------|
| **Performance regression** | High | Benchmark early (Week 2), abort if >2x slower | Week 2 |
| **Subtle compatibility bugs** | High | DualCPU testing harness catches all divergences | Ongoing |
| **QEMU integration complexity** | Medium | Start with m68k (simpler), prototype in 2 weeks | Week 1-2 |
| **Build system complexity** | Low | QEMU can be built as library | Week 1 |
| **EmulOp integration issues** | Medium | Well-defined interface, test incrementally | Week 2-3 |
| **Memory access overhead** | Medium | Use direct-mapping mode if adapter is slow | Week 3 |

## Effort Estimation

### Phase 1: QEMU Integration Core (Month 1)
- **Week 1:** Build QEMU as library, basic m68k integration
- **Week 2:** Memory system bridge, performance benchmark (go/no-go)
- **Week 3:** EmulOp handler registration and testing
- **Week 4:** First boot attempt, debug basic issues

**Deliverable:** Can execute simple m68k programs

### Phase 2: Instruction Validation (Month 2)
- **Week 5-6:** Run comprehensive instruction test suite
- **Week 7-8:** Debug divergences, fix edge cases (go/no-go)

**Deliverable:** All m68k instructions validated

### Phase 3: ROM Execution (Month 3)
- **Week 9-10:** ROM boot sequence working
- **Week 11-12:** Full boot to Finder (go/no-go)

**Deliverable:** BasiliskII boots with QEMU CPU

### Phase 4: Polish & SheepShaver (Month 4)
- **Week 13-14:** Performance tuning, regression tests
- **Week 15-16:** Apply lessons to SheepShaver PPC

**Deliverable:** Production-ready QEMU integration

**Total:** 4 months for BasiliskII, +1 month for SheepShaver

## Decision Points

### Week 2: Go/No-Go #1
**Question:** Is basic QEMU integration working?
- Can execute simple programs?
- Performance acceptable (within 2x of legacy)?
- EmulOps working?

**If NO:** Abort, cost = 2 weeks

### Week 8: Go/No-Go #2
**Question:** Are we on track?
- Instruction tests passing?
- No fundamental blockers?

**If NO:** Abort, cost = 8 weeks, or keep as experimental

### Week 12: Go/No-Go #3
**Question:** Does it work?
- Boots to Finder?
- No showstopper bugs?

**If NO:** Keep as experimental feature, cost = 12 weeks

## Comparison: JIT-Only vs Full Replacement

| Aspect | JIT-Only | Full Replacement |
|--------|----------|------------------|
| **Effort** | 6-12 months | 4-5 months |
| **Complexity** | High (IR conversion) | Medium (adapter layer) |
| **Risk** | High (uncertain performance) | Medium (well-defined) |
| **Maintenance** | Still maintain decode/translate | QEMU maintains everything |
| **ARM64 Support** | Yes | Yes |
| **Performance** | Uncertain | Proven (QEMU is fast) |
| **Testing** | Difficult to validate | Easy with DualCPU harness |
| **Code deletion** | ~5K lines | ~30K lines |

## Recommendation

**✅ Proceed with Full CPU Replacement**

### Rationale
1. **Clean boundaries** - EmulOps and ROM patching are orthogonal
2. **Less effort** - 4 months vs 6-12 months
3. **More benefits** - Delete more code, better maintenance
4. **Testable** - DualCPU harness validates correctness
5. **Proven** - QEMU is mature, well-tested

### Approach
1. **Start with BasiliskII** (m68k, simpler)
2. **Build DualCPU testing harness** (validate empirically)
3. **Keep legacy as fallback** (make QEMU opt-in initially)
4. **Apply lessons to SheepShaver** (PPC)

### Next Steps
1. Read [TESTING_STRATEGY.md](TESTING_STRATEGY.md) - How to validate
2. Read [QEMU_MIGRATION_SUMMARY.md](QEMU_MIGRATION_SUMMARY.md) - Overall plan
3. Build proof-of-concept (Week 1)
4. Implement DualCPU harness (Week 2)
5. Execute testing strategy (Weeks 3+)

## Appendix: QEMU TCG Background

### What is TCG?

**TCG (Tiny Code Generator)** is QEMU's JIT compiler infrastructure:

```
Guest Instruction → TCG Frontend → TCG IR → TCG Backend → Host Code
```

**TCG IR:** Platform-independent intermediate representation
**TCG Backend:** Host-specific code generation (x86, ARM, RISC-V, etc.)

### TCG vs Dyngen

| Feature | Dyngen (pre-2008) | TCG (current) |
|---------|-------------------|---------------|
| **Technique** | Extract code from compiled C | IR-based code generation |
| **Optimization** | Basic | Sophisticated (liveness, constant prop, etc.) |
| **Portability** | Hard (platform-specific templates) | Easy (just write backend) |
| **Maintenance** | Difficult | Easier |
| **Performance** | Good | Better |

SheepShaver uses dyngen (the old approach). QEMU moved to TCG in 2008 and has improved it significantly since then.

### Performance Characteristics

Typical TCG performance on modern QEMU:
- **m68k emulation:** 50-200 MIPS on modern x86 host
- **PPC emulation:** 100-400 MIPS on modern x86 host
- **Overhead:** 10-50x slower than native (still very usable)

For comparison, BasiliskII/SheepShaver JIT:
- Likely in similar range (not precisely benchmarked)
- Hand-optimizations for specific cases (AltiVec)

**Key point:** QEMU performance is proven adequate for full-system emulation of similar architectures.

## Conclusion

Replacing the entire CPU emulator with QEMU is:
- ✅ **Feasible** - Clean integration points
- ✅ **Beneficial** - ARM64 support, less maintenance
- ✅ **Testable** - DualCPU harness validates correctness
- ✅ **Practical** - 4-5 months of focused work

The key insight is that **EmulOps and ROM patching provide clean boundaries** that make this a well-scoped project rather than a risky rewrite.
