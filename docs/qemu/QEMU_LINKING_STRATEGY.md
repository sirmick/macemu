# QEMU Linking Strategy for macemu

## Overview

Now that QEMU is built, we need to integrate it into BasiliskII and SheepShaver. This document outlines the linking approaches.

## What We Have

After building QEMU, we have:

```
qemu/build/
├── qemu-system-m68k          # Full m68k emulator binary (22 MB)
├── qemu-system-ppc           # Full PPC emulator binary (25 MB)
├── libqemuutil.a             # QEMU utility library (659 KB)
├── libqemu-m68k-softmmu.a.p/ # m68k object files
├── libqemu-ppc-softmmu.a.p/  # PPC object files
└── libcommon.a.p/            # Common QEMU code objects
```

The binaries are statically linked with all CPU emulation code embedded.

## What We Need

We need to link against:
1. **CPU core** - m68k/PPC instruction decode and execute
2. **TCG (JIT)** - Code generation for host architecture
3. **Memory system** - For our adapter layer
4. **Helper functions** - CPU state management

## Linking Approaches

### Option A: Link Against Complete Binaries (Not Recommended)

```makefile
# Don't do this - too heavy
QEMU_M68K = $(QEMU_DIR)/build/qemu-system-m68k
LDFLAGS += -Wl,--whole-archive $(QEMU_M68K) -Wl,--no-whole-archive
```

**Problems:**
- ❌ Pulls in entire QEMU (device emulation, UI, network, etc.)
- ❌ Huge binary size
- ❌ Initialization conflicts
- ❌ Multiple main() functions

### Option B: Extract and Link Object Files (Complex)

```makefile
# Extract specific .o files we need
QEMU_OBJS = \
    target/m68k/cpu.c.o \
    target/m68k/translate.c.o \
    target/m68k/op_helper.c.o \
    target/m68k/helper.c.o \
    accel/tcg/*.o \
    # ... many more
```

**Problems:**
- ⚠️ Complex dependency tracking
- ⚠️ Easy to miss required objects
- ⚠️ Brittle (breaks when QEMU updates)
- ✅ Precise control over what's linked

### Option C: Use QEMU as Embedded Library (Recommended)

This is the approach used by projects like:
- **Unicorn Engine** (QEMU-based CPU emulator library)
- **libvirt** (QEMU integration)
- **Android Emulator** (uses QEMU internally)

**Strategy:**
1. Build QEMU with custom entry points
2. Create a thin C wrapper API
3. Link against QEMU's static components
4. Initialize only the CPU/TCG subsystems we need

## Recommended Approach: Custom QEMU Library Build

### Step 1: Create Custom QEMU Configuration

We'll need to build QEMU in a way that exposes the CPU core as a library.

**Add to QEMU build:**
```c
// File: qemu/macemu/qemu_cpu_lib.c
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"

// External API for BasiliskII/SheepShaver
CPUM68KState *macemu_m68k_cpu_init(void);
void macemu_m68k_cpu_reset(CPUM68KState *cpu);
void macemu_m68k_cpu_exec(CPUM68KState *cpu);
void macemu_m68k_cpu_destroy(CPUM68KState *cpu);

// Similar for PPC...
```

### Step 2: Build Custom Library

```bash
cd qemu
# Patch QEMU with our hooks (coming next)
# Build with our library wrapper
ninja libmacemu-m68k.a libmacemu-ppc.a
```

### Step 3: Link from BasiliskII

```makefile
# BasiliskII/src/Unix/Makefile.in
QEMU_DIR = ../../../qemu/build
QEMU_M68K_LIB = $(QEMU_DIR)/libmacemu-m68k.a

LIBS += $(QEMU_M68K_LIB) -lpixman-1 -lglib-2.0 -lz -lm

CXXFLAGS += -I$(QEMU_DIR)/include
```

## Immediate Next Steps (Simpler Approach)

Before building a custom library, let's start simpler:

### Phase 1: Proof of Concept (Week 1)

**Create a standalone test that uses QEMU:**

```c
// File: test/qemu_poc.c
#include "qemu/osdep.h"
#include "target/m68k/cpu.h"

int main() {
    // Initialize QEMU's type system
    module_call_init(MODULE_INIT_QOM);

    // Create m68k CPU
    M68kCPU *cpu = M68K_CPU(cpu_create("m68040"));

    // Set PC
    cpu->env.pc = 0x1000;

    // Execute one instruction
    cpu_exec(CPU(cpu));

    return 0;
}
```

**Build it:**
```bash
cd macemu
gcc -o test/qemu_poc test/qemu_poc.c \
    -I qemu/include \
    -I qemu/build \
    -I qemu/target/m68k \
    qemu/build/qemu-system-m68k \
    $(pkg-config --libs glib-2.0 pixman-1) -lz -lm
```

If this works, we've proven we can call QEMU from external code!

### Phase 2: Create Adapter Layer (Week 2)

```c
// File: qemu-cpu/qemu_m68k_adapter.c
#include "cpu_emulation.h"  // BasiliskII header
#include "qemu/osdep.h"
#include "target/m68k/cpu.h"

static M68kCPU *qemu_m68k_cpu = NULL;

bool Init680x0_QEMU(void) {
    module_call_init(MODULE_INIT_QOM);
    qemu_m68k_cpu = M68K_CPU(cpu_create("m68040"));

    // Register illegal instruction hook (our patch)
    m68k_illegal_insn_hook = handle_basilisk_emulop;

    return true;
}

void Execute68k_QEMU(uint32 addr, M68kRegisters *r) {
    // Copy registers from BasiliskII format to QEMU
    for (int i = 0; i < 8; i++) {
        qemu_m68k_cpu->env.dregs[i] = r->d[i];
        qemu_m68k_cpu->env.aregs[i] = r->a[i];
    }
    qemu_m68k_cpu->env.pc = addr;

    // Execute
    cpu_exec(CPU(qemu_m68k_cpu));

    // Copy back
    for (int i = 0; i < 8; i++) {
        r->d[i] = qemu_m68k_cpu->env.dregs[i];
        r->a[i] = qemu_m68k_cpu->env.aregs[i];
    }
}
```

## Dependencies We'll Need to Link

Based on `ldd` output, QEMU needs:

```makefile
QEMU_LIBS = \
    -lpixman-1 \
    -lglib-2.0 \
    -lgio-2.0 \
    -lgobject-2.0 \
    -lgmodule-2.0 \
    -lz \
    -lm
```

These are already on the system (we installed them for QEMU build).

## Build Integration

We'll need to modify BasiliskII's build system:

```makefile
# BasiliskII/src/Unix/configure.ac
AC_ARG_ENABLE(qemu-cpu,
  [  --enable-qemu-cpu       use QEMU CPU emulation instead of UAE],
  [WANT_QEMU_CPU=$enableval], [WANT_QEMU_CPU=no])

if [[ "x$WANT_QEMU_CPU" = "xyes" ]]; then
  AC_DEFINE(USE_QEMU_CPU, 1, [Use QEMU CPU emulation])
  QEMU_DIR="../../../qemu"
  CPPFLAGS="$CPPFLAGS -I$QEMU_DIR/include -I$QEMU_DIR/build"
  LIBS="$LIBS $QEMU_DIR/build/libmacemu-m68k.a"
  PKG_CHECK_MODULES(QEMU_DEPS, [glib-2.0 pixman-1])
  LIBS="$LIBS $QEMU_DEPS_LIBS"
fi
```

## Summary

**Short term (Proof of Concept):**
1. ✅ QEMU built successfully
2. **Next**: Create minimal test program that calls QEMU
3. **Then**: Create adapter layer

**Long term (Production):**
1. Build custom QEMU library (`libmacemu-m68k.a`, `libmacemu-ppc.a`)
2. Integrate into BasiliskII/SheepShaver build system
3. Make it configurable (`--enable-qemu-cpu` vs legacy CPU)

**The key insight:** We're **not** using QEMU as a standalone emulator. We're using QEMU's CPU emulation core as a **library** that BasiliskII/SheepShaver will call directly.

## Next Document to Read

See `QEMU_MODIFICATION_REQUIREMENTS.md` for the ~30 line patches we need to add illegal instruction hooks.
