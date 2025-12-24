# QEMU CPU Adapter Layer

This directory contains the adapter code that bridges BasiliskII/SheepShaver to QEMU's CPU emulation.

## Overview

The adapter layer implements BasiliskII's CPU API (`Init680x0()`, `Start680x0()`, etc.) using QEMU's m68k/PPC CPU emulation instead of the legacy UAE/KheperX emulators.

## Architecture

```
BasiliskII/SheepShaver Code
         ↓
    CPU API (cpu_emulation.h)
         ↓
    QEMU Adapter (this directory)
         ↓
    QEMU CPU Emulation
```

## Files

### qemu_m68k_adapter.h
Header file defining the adapter API. This matches BasiliskII's CPU API but with `_QEMU` suffix to distinguish from UAE implementation.

**Key functions:**
- `Init680x0_QEMU()` - Initialize QEMU CPU
- `Start680x0_QEMU()` - Start execution loop
- `Execute68k_QEMU()` - Execute code at specific address
- `Execute68kTrap_QEMU()` - Execute Mac OS trap
- `TriggerInterrupt_QEMU()` - Trigger interrupt

### qemu_m68k_adapter.cpp
Implementation of the adapter layer.

**What it does:**
1. Creates and initializes QEMU m68040 CPU
2. Registers the illegal instruction hook for EmulOps
3. Converts between BasiliskII's `M68kRegisters` and QEMU's `CPUM68KState`
4. Handles EmulOp opcodes (0x71xx) by calling BasiliskII's `EmulOp()` function
5. Manages memory regions (maps BasiliskII's RAM/ROM to QEMU)

## Current Status

✅ **Complete:**
- Basic structure and API definition
- EmulOp hook handler
- Register conversion functions
- CPU initialization/shutdown

⏳ **TODO:**
- Memory region setup (map BasiliskII's RAM/ROM into QEMU)
- Main execution loop implementation
- Trap execution (`Execute68kTrap`)
- Interrupt handling
- Integration with BasiliskII's build system

## How It Works

### EmulOp Handling

When QEMU encounters an illegal instruction (0x71xx):

1. QEMU's exception handler calls our hook: `emulop_hook_handler()`
2. Hook checks if opcode is 0x71xx (EmulOp)
3. If yes:
   - Extract selector (low byte of opcode)
   - Convert QEMU registers to `M68kRegisters`
   - Call BasiliskII's `EmulOp(selector, &regs)`
   - Convert registers back to QEMU format
   - Advance PC past illegal instruction
   - Return `true` (skip normal exception)
4. If no: Return `false` (let QEMU handle as normal illegal instruction)

### Register Conversion

BasiliskII uses this format:
```c
struct M68kRegisters {
    uint32_t d[8];   // Data registers
    uint32_t a[8];   // Address registers
    uint16_t sr;     // Status register
};
```

QEMU uses:
```c
struct CPUM68KState {
    uint32_t dregs[8];
    uint32_t aregs[8];
    uint32_t sr;
    uint32_t pc;
    // ... many more fields
};
```

The adapter simply copies the common fields between the two formats.

## Memory Architecture

BasiliskII allocates Mac RAM and ROM in host memory:
- `RAMBaseHost` - Pointer to Mac RAM (e.g., 128 MB)
- `ROMBaseHost` - Pointer to Mac ROM (e.g., 4 MB)

QEMU needs these mapped as `MemoryRegion` objects. The adapter will create:
- RAM region pointing directly to `RAMBaseHost` (zero-copy)
- ROM region pointing directly to `ROMBaseHost` (zero-copy)

This allows QEMU to access BasiliskII's memory without copying.

## Building

### Prerequisites

1. QEMU must be built with hooks (see `../qemu/`)
2. BasiliskII headers must be available
3. QEMU headers and libraries must be accessible

### Compilation

```bash
# (Will be added to BasiliskII's Makefile)

g++ -c qemu_m68k_adapter.cpp \
    -I../BasiliskII/src/include \
    -I../BasiliskII/src/uae_cpu \
    -I../qemu/include \
    -I../qemu/build \
    -I../qemu/target/m68k \
    $(pkg-config --cflags glib-2.0 pixman-1)
```

### Linking

```bash
# Link into BasiliskII binary
g++ ... qemu_m68k_adapter.o \
    ../qemu/build/libqemu-m68k-softmmu.a \
    $(pkg-config --libs glib-2.0 pixman-1) \
    -lz -lm -lpthread
```

(Exact linking strategy TBD - see `../docs/qemu/QEMU_LINKING_STRATEGY.md`)

## Integration with BasiliskII

### Option 1: Compile-time Selection

```c
// In BasiliskII code:
#ifdef USE_QEMU_CPU
    #include "qemu_m68k_adapter.h"
    #define Init680x0 Init680x0_QEMU
    #define Start680x0 Start680x0_QEMU
    // ... etc
#else
    // Use UAE CPU
#endif
```

### Option 2: Runtime Selection

```c
// Function pointers set at startup
bool (*Init680x0_impl)(void);
void (*Start680x0_impl)(void);

// In main():
if (use_qemu) {
    Init680x0_impl = Init680x0_QEMU;
    Start680x0_impl = Start680x0_QEMU;
} else {
    Init680x0_impl = Init680x0_UAE;
    Start680x0_impl = Start680x0_UAE;
}
```

## Testing Strategy

1. **Unit tests:** Test register conversion, hook mechanism
2. **DualCPU mode:** Run UAE and QEMU in parallel, compare execution
3. **ROM boot:** Boot actual Mac ROM with QEMU
4. **Full system:** Run Mac OS applications

See `../docs/qemu/TESTING_STRATEGY.md` for detailed testing approach.

## Performance Considerations

- **Register conversion:** Minimal overhead (simple memcpy)
- **EmulOp calls:** Same overhead as UAE (function call + conversion)
- **Main execution:** QEMU's TCG JIT should be comparable to UAE JIT
- **Memory access:** Zero-copy (direct pointer mapping)

Expected performance: Within 2x of UAE CPU (goal: match or exceed).

## Next Steps

1. Complete memory region setup
2. Implement main execution loop
3. Add to BasiliskII build system
4. Create DualCPU testing harness
5. Test with actual ROM boot

## See Also

- `../docs/qemu/IMPLEMENTATION_ROADMAP.md` - Overall plan
- `../docs/qemu/QEMU_LINKING_STRATEGY.md` - Build integration
- `../docs/qemu/DUALCPU_TESTING_APPROACH.md` - Testing strategy
- `../qemu-patches/README.md` - QEMU modifications
