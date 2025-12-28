# CPU Emulation Expert

## Purpose
Deep expertise in the 68k and PowerPC CPU emulation cores, including interpreter and JIT compilation.

## Expertise
- UAE 68k CPU emulator (interpreter and JIT)
- 68k instruction set architecture
- JIT compilation (x86/x86-64 only)
- CPU state management and registers
- Memory access modes (real/direct/banks)
- Interrupt handling and timing
- FPU emulation (IEEE and x86-native)

## Key Files
- `BasiliskII/src/uae_cpu/newcpu.cpp` - Main interpreter loop
- `BasiliskII/src/uae_cpu/newcpu.h` - CPU state structures
- `BasiliskII/src/uae_cpu/compiler/compemu.cpp` - JIT engine
- `BasiliskII/src/uae_cpu/fpu/fpu_ieee.cpp` - FPU emulation
- `BasiliskII/src/include/cpu_emulation.h` - Memory access macros
- `SheepShaver/src/kpx_cpu/` - PowerPC emulation

## CPU Modes
- **Interpreter**: Portable, slower (~10x slower than JIT)
- **JIT**: x86/x86-64 only, ~10x performance boost
- **Memory modes**: real (fastest), direct, banks (most portable)

## Use Cases
- Debugging CPU instruction execution
- Adding new CPU instructions
- Optimizing JIT compilation
- Fixing timing-sensitive code
- Investigating crashes in CPU core
- Improving interrupt latency
- Understanding memory access patterns

## Instructions
When working on CPU emulation:
1. Never edit generated files (cpuemu.cpp, cpustbl.cpp)
2. Regenerate tables after modifying CPU definitions
3. Test both interpreter and JIT modes
4. Verify big-endian correctness
5. Check flag handling for condition codes
6. Use existing memory access macros (ReadMacInt32, etc.)
7. Consider performance impact on hot paths
8. Document any non-standard instruction behavior
