# macemu-next Documentation

Modern Mac emulator built on BasiliskII's UAE M68K CPU core with dual-CPU validation.

## Overview

macemu-next is a clean-room rewrite of the BasiliskII Mac emulator with a modern build system (Meson) and modular architecture. The project focuses on:

- **Dual-CPU validation**: Run UAE and Unicorn M68K cores in parallel to validate instruction execution
- **Clean modular structure**: Separate core logic from platform-specific code
- **Modern build system**: Meson-based build with clear dependencies
- **Minimal dependencies**: Start with just CPU emulation, add components incrementally

## Project Status

**Current milestone**: ✅ ROM execution working!

The emulator successfully:
- Loads Quadra 650 ROM (1MB)
- Initializes UAE M68K CPU core
- Executes ROM code starting at ROMBaseMac + 0x2a
- Hits EMUL_OP traps (illegal instructions for Mac OS API calls)

**Next steps**:
- Implement EMUL_OP handlers for Mac OS traps
- Add ROM patching infrastructure
- Implement basic hardware emulation (VIA, etc.)

## Architecture

```
macemu-next/
├── src/
│   ├── common/include/    # Shared headers (sysdeps.h, etc.)
│   ├── core/              # Core Mac managers (copied from BasiliskII)
│   ├── drivers/dummy/     # Dummy driver implementations
│   ├── cpu/               # CPU emulation
│   │   ├── uae_cpu/       # UAE M68K CPU core
│   │   ├── unicorn_wrapper.c
│   │   ├── uae_wrapper.cpp
│   │   └── dualcpu.c      # Dual-CPU validation
│   └── tests/
│       └── boot/          # Boot test program
└── docs/                  # Documentation (you are here!)
```

## Documentation Index

1. [CPU Emulation](CPU.md) - UAE and Unicorn cores, dual-CPU validation
2. [Memory Layout](Memory.md) - ROM/RAM addressing, direct addressing mode
3. [UAE CPU Quirks](UAE-Quirks.md) - Byte-swapping, HAVE_GET_WORD_UNSWAPPED, etc.
4. [Unicorn Quirks](Unicorn-Quirks.md) - API differences, validation approach
5. [ROM Patching](ROM-Patching.md) - How BasiliskII patches ROMs (TODO)
6. [Build System](Build.md) - Meson build structure

## Quick Start

### Build

```bash
cd macemu-next
meson setup build-dualcpu -Dcpu_backend=dualcpu
meson compile -C build-dualcpu
```

### Run Boot Test

```bash
./build-dualcpu/tests/boot/test_boot /path/to/Quadra-650.ROM
```

You should see output showing ROM code execution and EMUL_OP traps.

## Key Concepts

### Direct Addressing Mode

BasiliskII uses "direct addressing" where Mac memory addresses map directly to host memory via a simple offset (`MEMBaseDiff`). This is much faster than banking/translation but requires contiguous memory allocation.

See [Memory Layout](Memory.md) for details.

### EMUL_OP Instructions

BasiliskII replaces certain ROM code sequences with illegal M68K instructions (0x71xx) to trap Mac OS API calls. When the CPU encounters these, it calls back into the emulator to handle the operation.

See [ROM Patching](ROM-Patching.md) for details.

### Dual-CPU Validation

Every M68K instruction is executed by BOTH UAE and Unicorn, and register state is compared after each instruction. This catches emulation bugs early.

See [CPU Emulation](CPU.md) for details.

## Contributing

This is a learning/research project. Key principles:

1. **Reference BasiliskII heavily** - Copy approach, not just code
2. **Keep it modular** - Clean separation of concerns
3. **Document quirks** - UAE and Unicorn both have surprising behavior
4. **Test incrementally** - Add one feature at a time

## License

Based on BasiliskII which is GPL v2. See LICENSE file.
