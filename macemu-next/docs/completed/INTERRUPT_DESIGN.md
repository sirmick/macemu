# Interrupt Support Implementation Design

## Problem Statement

**Unicorn backend does not process interrupts**, causing it to diverge from UAE and crash after ~175k instructions. Interrupts are critical for:
- Timer events
- ADB (keyboard/mouse) events
- Device I/O

## Current Architecture

### UAE Backend
1. Timer/ADB calls `TriggerInterrupt()` (in `uae_cpu/basilisk_glue.cpp`)
2. Sets `SPCFLAG_INT` flag
3. UAE CPU loop checks flags after each instruction
4. Calls `intlev()` → checks global `InterruptFlags`
5. Calls `Interrupt(level)` to process

### Unicorn Backend
1. Timer/ADB calls `TriggerInterrupt()` → **links to UAE version!**
2. Sets `SPCFLAG_INT` → **Unicorn never checks this**
3. Interrupts completely ignored
4. System gets into invalid state → crashes

## Proposed Solution

### Design Principles
1. **Move `TriggerInterrupt()` to platform code** - shared by all backends
2. **Use shared interrupt state** - not UAE-specific SPCFLAGS
3. **Backend-agnostic API** - each backend checks interrupts its own way
4. **Minimal changes to UAE** - keep existing interrupt handling working

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Platform Code (main.cpp / emul_op.cpp)                      │
│                                                              │
│  uint32 InterruptFlags = 0;  // Already exists             │
│  volatile bool PendingInterrupt = false;  // NEW            │
│                                                              │
│  void TriggerInterrupt() {   // MOVED from basilisk_glue   │
│      idle_resume();                                         │
│      PendingInterrupt = true;                               │
│  }                                                           │
└─────────────────────────────────────────────────────────────┘
                             ↓
         ┌───────────────────┴───────────────────┐
         │                                       │
┌────────▼──────────┐                  ┌────────▼──────────┐
│ UAE Backend       │                  │ Unicorn Backend   │
│                   │                  │                   │
│ SPCFLAGS_SET()    │                  │ Check after each  │
│ (keep existing)   │                  │ instruction       │
│                   │                  │                   │
│ Check every inst  │                  │ if (PendingIntr)  │
│ via SPCFLAG_INT   │                  │   Process it      │
└───────────────────┘                  └───────────────────┘
```

### Implementation Steps

#### 1. Platform Code Changes

**File**: `macemu-next/src/core/main.cpp` (or similar platform file)

```c
// Global interrupt state (shared by all backends)
volatile bool PendingInterrupt = false;

// Move TriggerInterrupt here from basilisk_glue.cpp
void TriggerInterrupt(void) {
    idle_resume();
    PendingInterrupt = true;
}

void TriggerNMI(void) {
    // TODO: Implement NMI
}
```

#### 2. UAE Backend Changes

**File**: `macemu-next/src/cpu/uae_cpu/basilisk_glue.cpp`

```cpp
// Remove TriggerInterrupt() - now in platform code
// Keep intlev() as-is

// In CPU loop (newcpu.cpp), add check for PendingInterrupt:
if (PendingInterrupt) {
    PendingInterrupt = false;
    SPCFLAGS_SET(SPCFLAG_INT);
}
```

#### 3. Unicorn Backend Changes

**File**: `macemu-next/src/cpu/unicorn_wrapper.c`

In `ucpu_execute_instruction()`, after each instruction:

```c
// Check for pending interrupts
extern volatile bool PendingInterrupt;
extern uint32 InterruptFlags;

bool ucpu_execute_instruction(struct ucpu *cpu) {
    // ... existing code ...

    uc_err err = uc_emu_start(cpu->uc, pc, 0xFFFFFFFFFFFFFFFFULL, 0, 1);

    // Check for interrupts after instruction
    if (PendingInterrupt) {
        PendingInterrupt = false;

        // Get interrupt level (same logic as UAE's intlev())
        int intr_level = InterruptFlags ? 1 : 0;

        if (intr_level > 0) {
            // Get current SR to check interrupt mask
            uint32_t sr;
            uc_reg_read(cpu->uc, UC_M68K_REG_SR, &sr);
            int current_mask = (sr >> 8) & 7;

            if (intr_level > current_mask) {
                // Trigger M68K interrupt in Unicorn
                // This will cause Unicorn to vector through the interrupt table
                unicorn_trigger_m68k_interrupt(cpu, intr_level);
            }
        }
    }

    return true;
}

static void unicorn_trigger_m68k_interrupt(struct ucpu *cpu, int level) {
    // M68K interrupt handling:
    // 1. Push SR onto stack
    // 2. Push PC onto stack
    // 3. Update SR (set supervisor mode, set interrupt mask)
    // 4. Jump to interrupt vector

    uint32_t sr, pc, sp;
    uc_reg_read(cpu->uc, UC_M68K_REG_SR, &sr);
    uc_reg_read(cpu->uc, UC_M68K_REG_PC, &pc);
    uc_reg_read(cpu->uc, UC_M68K_REG_A7, &sp);

    // Push PC (long)
    sp -= 4;
    uint32_t pc_be = __builtin_bswap32(pc);
    uc_mem_write(cpu->uc, sp, &pc_be, 4);

    // Push SR (word)
    sp -= 2;
    uint16_t sr_be = __builtin_bswap16((uint16_t)sr);
    uc_mem_write(cpu->uc, sp, &sr_be, 2);

    // Update SR: set supervisor mode (bit 13), set interrupt mask
    sr |= (1 << 13);  // Supervisor mode
    sr = (sr & ~0x0700) | ((level & 7) << 8);  // Set interrupt mask
    uc_reg_write(cpu->uc, UC_M68K_REG_SR, &sr);
    uc_reg_write(cpu->uc, UC_M68K_REG_A7, &sp);

    // Read interrupt vector and jump to it
    // For level 1 interrupt: vector is at VBR + (24 + level) * 4
    uint32_t vbr = 0;  // Assume VBR = 0 for now (68000/68010)
    // TODO: Read VBR register for 68020+

    uint32_t vector_addr = vbr + (24 + level) * 4;
    uint32_t handler_addr_be;
    uc_mem_read(cpu->uc, vector_addr, &handler_addr_be, 4);
    uint32_t handler_addr = __builtin_bswap32(handler_addr_be);

    uc_reg_write(cpu->uc, UC_M68K_REG_PC, &handler_addr);
}
```

## Testing Plan

1. **Unit test**: Verify `TriggerInterrupt()` sets `PendingInterrupt`
2. **UAE test**: Verify UAE still processes interrupts correctly
3. **Unicorn test**: Verify Unicorn now processes interrupts
4. **Convergence test**: Run 250k instruction traces and compare:
   - Both should now process timer interrupts at similar points
   - D0 values should converge (no more 0xD1D00000 vs 0x14300000)
   - Unicorn should run longer without crashing

## Expected Results

- **Before**: Unicorn diverges at instruction 29518, crashes at 175k
- **After**: Both backends process interrupts, traces stay synchronized longer
- **Note**: Exact convergence unlikely due to timing differences, but divergence should be much later

## Alternative: Use uc_emu_stop()

If needed, we could use `uc_emu_stop()` to interrupt Unicorn mid-execution:

```c
void TriggerInterrupt(void) {
    idle_resume();
    PendingInterrupt = true;

    // If Unicorn is running, stop it
    if (current_backend == UNICORN && unicorn_is_running) {
        uc_emu_stop(global_uc_handle);
    }
}
```

This would require storing the Unicorn handle globally, which is less clean.

## Files to Modify

1. `macemu-next/src/core/main.cpp` - Add `PendingInterrupt`, move `TriggerInterrupt()`
2. `macemu-next/src/cpu/uae_cpu/basilisk_glue.cpp` - Remove `TriggerInterrupt()`, add `PendingInterrupt` check
3. `macemu-next/src/cpu/uae_cpu/newcpu.cpp` - Add `PendingInterrupt` check in CPU loop
4. `macemu-next/src/cpu/unicorn_wrapper.c` - Add interrupt checking and handling
5. `macemu-next/src/common/include/main.h` - Declare `PendingInterrupt` extern

## References

- M68K interrupt handling: Motorola M68000 Programmer's Reference Manual, Section 6
- Unicorn API: https://github.com/unicorn-engine/unicorn/blob/master/docs/DOCUMENTATION.md
- UAE CPU emulation: `macemu-next/src/cpu/uae_cpu/newcpu.cpp`
