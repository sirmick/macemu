# Unmapped Memory Issue - Root Cause Analysis

## Problem
Unicorn backend crashes at ~175,170 instructions with:
```
UC_ERR_WRITE_UNMAPPED: Invalid memory write
Addresses: 0xFFFFFFFE, 0xFFFFFFFC
```

UAE completes the same trace successfully with 250,000 instructions.

## Root Cause

### UAE Memory Model
In `macemu-next/src/cpu/uae_cpu/memory.cpp:584-587`:

```c
void memory_init(void)
{
    for(long i=0; i<65536; i++)
        put_mem_bank(i<<16, &dummy_bank);

    // ... then map RAM, ROM, framebuffer over top
}
```

**UAE fills the ENTIRE 4GB address space with `dummy_bank` before mapping real regions.**

The `dummy_bank` handlers (lines 89-127):
- **Reads**: Return 0 (optionally log if `illegal_mem` flag set)
- **Writes**: Silent no-op (optionally log if `illegal_mem` flag set)

This means **any unmapped address access succeeds** - it just returns 0 or ignores writes.

### Unicorn Memory Model
In `macemu-next/src/cpu/cpu_unicorn.cpp:142-191`:

```c
unicorn_backend_init() {
    // Map only 3 regions:
    unicorn_map_ram(RAMBaseMac, RAMBaseHost, RAMSize);           // ~128MB
    unicorn_map_rom_writable(ROMBaseMac, ROMBaseHost, ROMSize); // 1MB
    unicorn_map_ram(dummy_region_base, buffer, 16MB);           // 16MB after ROM
}
```

**Unicorn only maps specific regions (~145MB total).** The rest of the 4GB address space is unmapped.

Accessing unmapped addresses triggers `UC_ERR_WRITE_UNMAPPED` or `UC_ERR_READ_UNMAPPED`.

## Why This Matters

At instruction #175,170, Unicorn executes code that writes to 0xFFFFFFFE/0xFFFFFFFC:
- These are **high memory addresses** (top of 32-bit address space)
- Could be hardware register placeholders, debug markers, or hardware initialization
- **UAE silently ignores** these writes via `dummy_bank`
- **Unicorn crashes** because these addresses aren't mapped

## Evidence

From `unicorn_250k.log`:
```
unicorn_mem_write_word: failed to write to 0xFFFFFFFE: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
unicorn_mem_write_word: failed to write to 0xFFFFFFFC: Invalid memory write (UC_ERR_WRITE_UNMAPPED)
```

These writes come from `unicorn_mem_write_word()` in [cpu_unicorn.cpp:449-461](macemu-next/src/cpu/cpu_unicorn.cpp#L449-L461), which is called by EmulOp handlers or Mac OS code.

## Solution

Map the entire 4GB address space in Unicorn with a dummy region that mimics UAE's behavior:

### Option 1: Map Full 4GB Dummy Region (Simple)
Map unmapped regions with UC_HOOK_MEM_READ_UNMAPPED/UC_HOOK_MEM_WRITE_UNMAPPED hooks that return 0/ignore writes.

**Pros**:
- Simple, matches UAE exactly
- No memory overhead (hooks don't allocate memory)

**Cons**:
- Hook overhead for every unmapped access (but these should be rare)

### Option 2: Map Large Dummy Buffer (Thorough)
Allocate and map large dummy regions to cover common hardware register areas:
- 0xF0000000-0xFFFFFFFF (256MB at top of address space - hardware registers)
- Fill gaps between RAM/ROM

**Pros**:
- No hook overhead
- Can detect patterns in unmapped accesses

**Cons**:
- Memory overhead (though virtual memory makes this cheap)
- More complex setup

### Option 3: Hybrid Approach (Recommended)
1. Map common hardware register regions (0xF0000000-0xFFFFFFFF) with dummy buffer
2. Add UC_HOOK_MEM_*_UNMAPPED hooks as fallback for other unmapped regions

**Pros**:
- Handles 99% of cases without hooks
- Still has safety net for unexpected accesses
- Can log unexpected unmapped accesses for debugging

## Next Steps

1. Implement Option 3 (hybrid approach)
2. Test with 250k+ instruction traces
3. Monitor for any new unmapped access patterns
4. Document any hardware register patterns we discover

## Related Files

- [macemu-next/src/cpu/uae_cpu/memory.cpp:584-587](macemu-next/src/cpu/uae_cpu/memory.cpp#L584-L587) - UAE dummy_bank setup
- [macemu-next/src/cpu/uae_cpu/memory.cpp:89-127](macemu-next/src/cpu/uae_cpu/memory.cpp#L89-L127) - UAE dummy_bank handlers
- [macemu-next/src/cpu/cpu_unicorn.cpp:142-191](macemu-next/src/cpu/cpu_unicorn.cpp#L142-L191) - Unicorn memory setup
- [macemu-next/src/cpu/unicorn_wrapper.c](macemu-next/src/cpu/unicorn_wrapper.c) - Unicorn wrapper implementation
