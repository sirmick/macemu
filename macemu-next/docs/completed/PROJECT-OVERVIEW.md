# macemu-next Project Overview

## Mission

Give BasiliskII and SheepShaver a serious glow-up through clean-room rewrite with modern architecture, validation, and build system.

## The Big Picture

### What is BasiliskII/SheepShaver?

Classic Mac emulators that run:
- **BasiliskII**: Mac OS 7.x through 8.1 (68K Macs like Quadra 650)
- **SheepShaver**: Mac OS 7.5.2 through 9.0.4 (PowerPC Macs like Power Mac G3)

Original codebase (kanjitalk755/macemu):
- Started in the 1990s
- Autotools build system
- Platform-specific code mixed with core logic
- Single CPU backend (UAE interpreter + optional JIT)
- No systematic validation

### What is macemu-next?

A modern rewrite focusing on:

1. **Clean Architecture**
   - Modular design with clear separation of concerns
   - Platform API abstraction layer
   - Core emulation decoupled from host OS

2. **Modern Build System**
   - Meson-based build (replaces Autotools/Xcode)
   - Fast, cross-platform, easy to understand
   - Clear dependency management

3. **Multiple CPU Backends**
   - UAE interpreter (original, proven)
   - Unicorn engine (validation, future JIT)
   - DualCPU (UAE + Unicorn in lockstep for validation)
   - Runtime selection via CPU_BACKEND environment variable

4. **Differential Testing**
   - Execute every instruction on both UAE and Unicorn
   - Compare register state after each instruction
   - Catch emulation bugs immediately
   - Build confidence in new backends

## Current Status (January 2026)

### ✅ What Works

1. **Build System**: Meson build compiles cleanly
2. **UAE CPU**: Full 68K interpreter integrated
3. **Unicorn CPU**: Full 68020 emulation with JIT
4. **DualCPU**: Validates **514,000+ instructions** successfully (massive improvement!)
5. **ROM Loading**: Quadra 650 ROM loads and executes
6. **EmulOp System**: 0x71xx traps call emulator functions
7. **A-line/F-line Traps**: ✅ **COMPLETE** - Mac OS traps (0xAxxx, 0xFxxx) working
8. **Interrupt Support**: ✅ **COMPLETE** - Timer interrupts processed by all backends
9. **Native Trap Execution**: ✅ **COMPLETE** - Unicorn executes 68k traps natively
10. **XPRAM**: Configuration storage working
11. **Memory**: Direct addressing mode implemented
12. **Boot Sequence**: ROM boots, executes successfully

### 🚧 Currently Working On

**Timer Interrupt Timing Analysis**
- First divergence at instruction #29,518 due to timer interrupt
- UAE (interpreted) vs Unicorn (JIT) execute at different speeds
- Wall-clock timers fire at different instruction counts
- Not a bug, but a characteristic of wall-clock-based timing
- Investigation doc: [INTERRUPT_TIMING_ANALYSIS.md](INTERRUPT_TIMING_ANALYSIS.md)

**Performance Gap Investigation**
- Unicorn stops at ~200k instructions vs UAE 250k
- Likely due to cumulative effects of interrupt timing divergence
- Need functional testing approach (not just trace comparison)

### 📋 Roadmap (Not Yet Started)

1. **Full Hardware Emulation**
   - VIA (Versatile Interface Adapter)
   - SCSI (disk access)
   - Video (framebuffer, display)
   - Audio, Serial, Ethernet

2. **ROM Patching**
   - Replace ROM code with EmulOps
   - Optimize trap dispatch
   - Enable Mac OS API emulation

3. **User Interface**
   - SDL-based window/input
   - Preferences UI
   - Debugger integration

4. **Performance**
   - JIT compilation (UAE JIT or LLVM)
   - Optimize hot paths
   - Profile and tune

5. **SheepShaver Support**
   - PowerPC CPU backend
   - Mac OS 9 compatibility
   - Modern Mac emulation

## Architecture

### Directory Structure

```
macemu-next/
├── src/
│   ├── common/              # Cross-platform utilities
│   │   ├── include/         # Shared headers (sysdeps.h, etc.)
│   │   ├── platform.cpp     # Platform API implementation
│   │   ├── prefs.cpp        # Preferences system
│   │   └── macos_util.cpp   # Mac OS utilities
│   │
│   ├── core/                # Core emulation (from BasiliskII)
│   │   ├── emul_op.cpp      # EmulOp trap handlers
│   │   ├── xpram.cpp        # XPRAM storage
│   │   ├── main.cpp         # Main emulation loop
│   │   ├── video.cpp        # Video manager
│   │   ├── disk.cpp         # Disk manager
│   │   ├── scsi.cpp         # SCSI manager
│   │   ├── serial.cpp       # Serial manager
│   │   ├── audio.cpp        # Audio manager
│   │   └── ...              # Other managers
│   │
│   ├── cpu/                 # CPU emulation backends
│   │   ├── cpu_backend.h    # Unified CPU API
│   │   ├── cpu_backend.cpp  # Backend selection
│   │   ├── cpu_uae.c        # UAE backend
│   │   ├── cpu_unicorn.c    # Unicorn backend
│   │   ├── cpu_dualcpu.c    # DualCPU validation
│   │   │
│   │   ├── uae_cpu/         # UAE CPU core (from BasiliskII)
│   │   │   ├── newcpu.cpp   # Main CPU loop
│   │   │   ├── cpuemu_*.cpp # Generated instruction handlers
│   │   │   └── ...
│   │   │
│   │   ├── unicorn_wrapper.c     # Unicorn API wrapper
│   │   ├── unicorn_exception.c   # Exception simulation (TODO)
│   │   ├── unicorn_validation.cpp # DualCPU logic
│   │   └── uae_wrapper.cpp       # UAE API wrapper
│   │
│   ├── drivers/             # Platform drivers
│   │   └── dummy/           # Dummy implementations (for testing)
│   │       ├── video_dummy.cpp
│   │       ├── disk_dummy.cpp
│   │       ├── xpram_dummy.cpp
│   │       └── ...
│   │
│   └── main.cpp             # Entry point
│
├── external/
│   └── unicorn/             # Unicorn engine (git submodule)
│
├── tests/
│   ├── boot/                # Boot tests
│   │   └── test_boot.cpp    # ROM boot test
│   └── ...
│
├── docs/                    # Documentation
│   ├── README.md
│   ├── CPU.md
│   ├── Memory.md
│   ├── A-line-F-line-Exception-Design.md
│   └── PROJECT-OVERVIEW.md  # This file
│
└── meson.build              # Build configuration
```

### Key Design Patterns

#### 1. Platform API Abstraction

All platform-specific code goes through function pointers in [platform.h](../src/common/include/platform.h):

```c
typedef struct Platform {
    // Video
    bool (*video_init)(void);
    void (*video_exit)(void);
    void (*video_refresh)(void);

    // Disk
    void* (*sys_open)(const char *path, bool read_only);
    void (*sys_close)(void *fh);
    size_t (*sys_read)(void *fh, void *buf, size_t len);
    // ... etc

    // CPU Backend
    bool (*cpu_init)(void);
    CPUExecResult (*cpu_execute_one)(void);
    uint32_t (*cpu_get_pc)(void);
    // ... etc
} Platform;

extern Platform g_platform;
```

Benefits:
- Core emulation has ZERO platform dependencies
- Easy to add new platforms (Linux, macOS, Windows, Web)
- Runtime backend selection (CPU, video, disk, etc.)

#### 2. CPU Backend Abstraction

All CPU backends implement [CPUBackend](../src/cpu/cpu_backend.h) interface:

```c
typedef struct CPUBackend {
    const char *name;

    // Lifecycle
    bool (*init)(void);
    void (*reset)(void);
    void (*destroy)(void);

    // Execution
    CPUExecResult (*execute_one)(void);

    // State query/modification
    uint32_t (*get_pc)(void);
    void (*set_pc)(uint32_t pc);
    uint32_t (*get_dreg)(int n);
    uint32_t (*get_areg)(int n);
    // ... etc
} CPUBackend;
```

Implementations:
- **cpu_uae.c**: Wraps UAE interpreter
- **cpu_unicorn.c**: Wraps Unicorn engine
- **cpu_dualcpu.c**: Runs both, validates each instruction

Selection:
```bash
CPU_BACKEND=uae ./macemu-next ~/quadra.rom        # Use UAE
CPU_BACKEND=unicorn ./macemu-next ~/quadra.rom    # Use Unicorn
CPU_BACKEND=dualcpu ./macemu-next ~/quadra.rom    # Validate
```

#### 3. Wrapper Pattern

Low-level APIs (UAE, Unicorn) are wrapped with clean C APIs:

**UAE Wrapper** ([uae_wrapper.cpp](../src/cpu/uae_wrapper.cpp)):
- Converts between UAE's `regstruct` and our simple API
- Handles C++ ↔ C interface
- Abstracts UAE quirks (pc_p, spcflags, etc.)

**Unicorn Wrapper** ([unicorn_wrapper.c](../src/cpu/unicorn_wrapper.c)):
- Creates/destroys Unicorn engine
- Maps memory regions
- Sets up hooks (invalid instruction, memory access)
- Provides clean register access

Benefits:
- Core code doesn't include UAE/Unicorn headers directly
- Easy to swap implementations
- Clean separation between "what" and "how"

## How It All Fits Together

### Boot Sequence

1. **main.cpp**
   - Parse command line
   - Select CPU backend (from CPU_BACKEND env var)
   - Load ROM file
   - Initialize platform API

2. **Platform Initialization**
   - Set up function pointers
   - Initialize drivers (video, disk, xpram, etc.)
   - Call CPU backend's init()

3. **CPU Backend Initialization**
   - **UAE**: Build CPU instruction table
   - **Unicorn**: Create Unicorn engine, map memory
   - **DualCPU**: Initialize both UAE and Unicorn

4. **Memory Setup**
   - Map ROM at 0x40800000 (4GB - 8MB)
   - Map RAM at 0x00000000
   - Set up direct addressing (Mac addr → host memory)

5. **CPU Reset**
   - Load initial SSP from ROM[0]
   - Load initial PC from ROM[4]
   - For Quadra: PC = ROMBaseMac + 0x2a

6. **Execution Loop**
   ```cpp
   CPUBackend *cpu = cpu_backend_get();
   while (true) {
       CPUExecResult result = cpu->execute_one();

       if (result == CPU_EXEC_EMULOP) {
           // Handle EmulOp trap
       } else if (result == CPU_EXEC_STOPPED) {
           break;
       } else if (result == CPU_EXEC_DIVERGENCE) {
           fprintf(stderr, "DualCPU divergence!\n");
           break;
       }
   }
   ```

### EmulOp Dispatch

When ROM executes 0x71xx instruction:

1. **CPU Backend Detects Illegal Instruction**
   - UAE: `op_illg()` → `m68k_emulop()` → `EmulOp()`
   - Unicorn: `hook_invalid_insn()` → EmulOp handler

2. **EmulOp Handler** ([emul_op.cpp](../src/core/emul_op.cpp))
   ```cpp
   void EmulOp(uint16 opcode, M68kRegisters *r) {
       switch (opcode) {
           case M68K_EMUL_OP_CLKNOMEM:  // XPRAM access
               // Read/write XPRAM
               break;

           case M68K_EMUL_OP_DISK_READ:  // Disk read
               // Call platform API: g_platform.sys_read()
               break;

           // ... 50+ EmulOps
       }
   }
   ```

3. **Return to CPU**
   - Update Mac registers from M68kRegisters structure
   - Advance PC past EmulOp instruction
   - Continue execution

### DualCPU Validation

For every instruction:

1. **Save Initial State**
   ```cpp
   uint32_t uae_pc = uae_get_pc();
   uint32_t uni_pc = unicorn_get_pc();
   assert(uae_pc == uni_pc);  // Should start in sync
   ```

2. **Execute on Both CPUs**
   ```cpp
   uae_cpu_execute_one();
   unicorn_execute_one();
   ```

3. **Compare Final State**
   ```cpp
   for (int i = 0; i < 8; i++) {
       assert(uae_get_dreg(i) == unicorn_get_dreg(i));
       assert(uae_get_areg(i) == unicorn_get_areg(i));
   }
   assert(uae_get_pc() == unicorn_get_pc());
   assert(uae_get_sr() == unicorn_get_sr());
   ```

4. **Log Divergence**
   If any register differs:
   ```
   [23250] UNICORN EXECUTION FAILED
   PC: 0x02003E08, Opcode: 0xA247
   Error: Unhandled CPU exception (UC_ERR_EXCEPTION)

   UAE:     D0=00000000 PC=02003E0A SR=2700
   Unicorn: D0=00000000 PC=02003E08 SR=2700
   ```

This is how we discovered the A-line exception issue!

## Development Workflow

### Building

```bash
# First time setup
cd macemu-next
meson setup build

# Build
meson compile -C build

# Or for DualCPU validation
meson setup build-dualcpu
meson compile -C build-dualcpu
```

### Testing

```bash
# Boot test with UAE
CPU_BACKEND=uae ./build/macemu-next ~/quadra.rom

# Boot test with Unicorn (will fail at A-line until implemented)
CPU_BACKEND=unicorn ./build/macemu-next ~/quadra.rom

# Boot test with validation
CPU_BACKEND=dualcpu ./build/macemu-next ~/quadra.rom

# With debug output
CPU_TRACE=5 EMULOP_VERBOSE=1 ./build/macemu-next ~/quadra.rom

# With timeout (auto-exit after N seconds)
EMULATOR_TIMEOUT=3 ./build/macemu-next ~/quadra.rom
```

### Debug Environment Variables

- **CPU_BACKEND**: Select backend (uae|unicorn|dualcpu)
- **CPU_TRACE**: Trace instructions (number = how many to show)
- **EMULOP_VERBOSE**: Log EmulOp calls
- **EMULATOR_TIMEOUT**: Auto-exit after N seconds

## Key Technical Concepts

### Direct Addressing Mode

BasiliskII uses "direct addressing" for speed:

```
Mac Address              Host Memory
0x00000000 (RAM) ----→   RAMBaseHost + 0x00000000
0x40800000 (ROM) ----→   ROMBaseHost

# No banking, no translation, just offset arithmetic
host_ptr = mac_addr + MEMBaseDiff
```

Benefits:
- Fast memory access (no table lookup)
- Simple implementation
- Native performance

Drawbacks:
- Requires contiguous memory allocation
- Less flexible than banking

See [Memory.md](Memory.md) for details.

### EmulOp Instructions

Mac ROMs call OS functions like this:
```assembly
_SetToolTrap:  .word 0xA247  ; Illegal instruction
```

BasiliskII patches ROMs to replace these with:
```assembly
_SetToolTrap:  .word 0x7104  ; EmulOp #4 (custom illegal opcode)
```

When CPU executes 0x71xx:
1. CPU raises illegal instruction exception
2. Emulator catches it
3. Executes C++ function instead of Mac OS code
4. Returns to caller

This is how we emulate Mac OS APIs!

See [ROM-Patching.md](ROM-Patching.md) (TODO) for details.

### Exception Vectors

68K CPUs use exception vector table for:
- Reset (vector 0)
- Bus error (vector 2)
- Address error (vector 3)
- Illegal instruction (vector 4)
- Divide by zero (vector 5)
- Privilege violation (vector 8)
- **A-line trap (vector 10)** ← Mac OS traps
- **F-line trap (vector 11)** ← FPU emulation
- Interrupts (vectors 24-31)

Each vector is 4 bytes, pointing to handler code.

VBR (Vector Base Register) sets base address (0x00000000 by default).

## Why This Matters

### For Retro Computing

Classic Mac software is cultural heritage:
- HyperCard stacks
- Early desktop publishing (PageMaker, QuarkXPress)
- Classic games (Marathon, SimCity 2000)
- Music software (SoundEdit, MIDI apps)

Modern hardware can't run these. Emulation preserves access.

### For Emulation Research

macemu-next explores:
- **Differential testing**: Run multiple backends, validate behavior
- **Clean architecture**: Separate concerns, modular design
- **Modern tooling**: Meson, sanitizers, continuous validation
- **Documentation**: Explain quirks, design decisions, tradeoffs

The patterns here apply beyond Mac emulation.

### For Performance

Current BasiliskII:
- Single backend (UAE interpreter or JIT)
- No validation
- Mixed architecture

macemu-next goals:
- Multiple backends (interpret, JIT, LLVM?)
- Continuous validation
- Clean separation → easier optimization
- Profile-guided optimization

## Contributing

This is a learning/research project. Key principles:

1. **Reference BasiliskII heavily** - Don't reinvent, understand then improve
2. **Document everything** - Quirks, decisions, tradeoffs
3. **Test incrementally** - Small changes, validate continuously
4. **Keep it modular** - Clean APIs, clear boundaries
5. **Embrace validation** - DualCPU catches bugs immediately

Areas needing work:
- [ ] A-line/F-line exception handling (in progress)
- [ ] Full hardware emulation (VIA, SCSI, Video)
- [ ] ROM patching infrastructure
- [ ] SDL-based UI
- [ ] JIT compilation
- [ ] PowerPC backend (SheepShaver)
- [ ] Performance profiling/optimization

## License

Based on BasiliskII, which is GPL v2. All code is GPL v2 compatible.

## References

- Original BasiliskII: https://github.com/kanjitalk755/macemu
- Unicorn Engine: https://www.unicorn-engine.org/
- M68K Reference: Motorola M68000 Family Programmer's Reference Manual
- Inside Macintosh (Apple's technical documentation)
- Meson Build: https://mesonbuild.com/

---

**Last Updated**: January 3, 2026
**Status**: Active development - Timer interrupt timing analysis and functional testing
