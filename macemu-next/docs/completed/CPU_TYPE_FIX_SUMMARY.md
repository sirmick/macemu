# CPU Type Selection Fix for Unicorn Backend

## Problem

The Unicorn backend was incorrectly creating a 68030 CPU instead of a 68020 when configured for 68020 mode.

## Root Cause

Unicorn's `UC_CPU_M68K_*` enum values don't match the CPU table array indices in `m68k_cpus_type_infos[]`:

**Enum values** (from `unicorn/m68k.h`):
```c
UC_CPU_M68K_M5206  = 0
UC_CPU_M68K_M68000 = 1
UC_CPU_M68K_M68020 = 2
UC_CPU_M68K_M68030 = 3
UC_CPU_M68K_M68040 = 4
```

**Array indices** (from `unicorn/qemu/target/m68k/cpu.c`):
```c
[0] = m68000
[1] = m68020
[2] = m68030
[3] = m68040
[4] = m68060
```

When passing `UC_CPU_M68K_M68020` (value 2) to `unicorn_create_with_model()`, it indexed to array position [2] which is **m68030**, not m68020!

## Solution

Use direct array indices instead of enum values in [cpu_unicorn.cpp:122-132](macemu-next/src/cpu/cpu_unicorn.cpp#L122-L132):

```cpp
// NOTE: Unicorn's CPU table uses array indices, not UC_CPU_M68K enum values!
// Array order: 0=m68000, 1=m68020, 2=m68030, 3=m68040, 4=m68060...
int uc_model;
if (unicorn_cpu_type == 4) {
    uc_model = 3;  // 68040 (array index)
} else {
    if (unicorn_fpu_type)
        uc_model = 2;  // 68030 (array index)
    else if (unicorn_cpu_type >= 2)
        uc_model = 1;  // 68020 (array index)
    else
        uc_model = 0;  // 68000 (array index)
}
```

## Changes Made

### 1. Fixed CPU Type Selection
**File**: [macemu-next/src/cpu/cpu_unicorn.cpp](macemu-next/src/cpu/cpu_unicorn.cpp)

Changed from using `UC_CPU_M68K_*` enum values to direct array indices.

### 2. Fixed VBR Register Support (Separate Bug)
**Files**:
- [macemu-next/external/unicorn/qemu/target/m68k/unicorn.c:90-93](macemu-next/external/unicorn/qemu/target/m68k/unicorn.c#L90-L93) (read)
- [macemu-next/external/unicorn/qemu/target/m68k/unicorn.c:179-182](macemu-next/external/unicorn/qemu/target/m68k/unicorn.c#L179-L182) (write)

Added missing VBR register cases to Unicorn's register API. VBR existed in CPU state but had no API access, causing reads to return uninitialized memory.

## Verification

Both backends now correctly create 68020 CPUs:
- **UAE**: `cpu_level=2` (68020)
- **Unicorn**: `model=1` → array[1] → m68020

Both complete 100,000 instruction execution successfully.

## CACR Divergence

There is a minor difference in CACR (Cache Control Register) masking between UAE and Unicorn:
- **UAE mask**: `0x00000003` (2 bits)
- **Unicorn mask**: `0x0000000f` (4 bits)

This difference is **harmless** because:
1. Neither backend implements a real instruction cache
2. CACR is only used for cache enable/disable tracking
3. The difference doesn't affect functionality
4. Both backends execute identically despite different CACR values

**Decision**: Accept the CACR difference rather than modify Unicorn's internal behavior.

## Future Work

If needed, CACR masking could be handled in our wrapper code (cpu_unicorn.cpp) rather than modifying Unicorn internals.
