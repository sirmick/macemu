/**
 * UAE CPU Wrapper Implementation
 */

#include "uae_wrapper.h"

// UAE CPU headers
extern "C" {
#include "sysdeps.h"
#include "uae_cpu/main.h"
}

#include "uae_cpu/cpu_emulation.h"  // C++ linkage for Init680x0/Exit680x0
#include "uae_cpu/m68k.h"
#include "uae_cpu/newcpu.h"
#include "uae_cpu/memory.h"

#include <stdlib.h>
#include <string.h>

/* Global UAE registers */
extern struct regstruct regs;

/* CPU/FPU types */
int CPUType = CPU_68020;
int FPUType = FPU_68881;

/* Interrupt flags */
volatile uint32 InterruptFlags = 0;

/* Quit flag */
volatile bool QuitEmulator = false;

/* Memory pointers are defined in basilisk_glue.cpp */
extern uint32 RAMBaseMac;
extern uint8 *RAMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMBaseMac;
extern uint8 *ROMBaseHost;
extern uint32 ROMSize;
extern int MacFrameLayout;
#if !REAL_ADDRESSING && !DIRECT_ADDRESSING
extern uint8 *MacFrameBaseHost;
extern uint32 MacFrameSize;
#endif

/* CPU configuration */
void uae_set_cpu_type(int cpu_type, int fpu_type) {
    CPUType = cpu_type;
    FPUType = fpu_type;
}

/* CPU initialization */
bool uae_cpu_init(void) {
    return Init680x0();
}

void uae_cpu_reset(void) {
    m68k_reset();
}

void uae_cpu_exit(void) {
    Exit680x0();
}

/* Memory initialization */
bool uae_mem_init(uint32_t ram_size, uint32_t rom_size) {
    RAMSize = ram_size;
    ROMSize = rom_size;

    RAMBaseHost = (uint8 *)calloc(1, ram_size);
    if (!RAMBaseHost) return false;

    ROMBaseHost = (uint8 *)malloc(rom_size);
    if (!ROMBaseHost) {
        free(RAMBaseHost);
        RAMBaseHost = NULL;
        return false;
    }

    RAMBaseMac = 0x00000000;
    ROMBaseMac = 0x00400000;  /* Typical Mac ROM location */

    return true;
}

void uae_mem_cleanup(void) {
    if (RAMBaseHost) {
        free(RAMBaseHost);
        RAMBaseHost = NULL;
    }
    if (ROMBaseHost) {
        free(ROMBaseHost);
        ROMBaseHost = NULL;
    }
}

/* Memory mapping - UAE uses global pointers, so these are no-ops */
void uae_mem_map_ram(uint32_t addr, uint32_t size) {
    (void)addr;
    (void)size;
    /* UAE memory model uses RAMBaseHost global */
}

void uae_mem_map_rom(uint32_t addr, uint32_t size) {
    (void)addr;
    (void)size;
    /* UAE memory model uses ROMBaseHost global */
}

/* Memory access */
void uae_mem_write(uint32_t addr, const void *data, uint32_t size) {
    if (!data) return;

    uint8_t *dest = NULL;
    /* Determine if writing to RAM or ROM */
    if (addr >= RAMBaseMac && addr < RAMBaseMac + RAMSize) {
        uint32_t offset = addr - RAMBaseMac;
        dest = RAMBaseHost + offset;
    } else if (addr >= ROMBaseMac && addr < ROMBaseMac + ROMSize) {
        uint32_t offset = addr - ROMBaseMac;
        dest = ROMBaseHost + offset;
    }

    if (!dest) return;

    /* UAE stores memory in NATIVE (little-endian) format on x86.
     * Input data is big-endian M68K format, so byte-swap when writing. */
    const uint8_t *src = (const uint8_t *)data;
    if (size >= 2 && (addr & 1) == 0) {
        /* Word-aligned, swap 16-bit words */
        for (uint32_t i = 0; i < size - 1; i += 2) {
            dest[i] = src[i + 1];
            dest[i + 1] = src[i];
        }
        if (size & 1) dest[size - 1] = src[size - 1];  /* Odd trailing byte */
    } else {
        /* Unaligned or single byte */
        memcpy(dest, src, size);
    }
}

void uae_mem_read(uint32_t addr, void *data, uint32_t size) {
    if (!data) return;

    /* Determine if reading from RAM or ROM */
    if (addr >= RAMBaseMac && addr < RAMBaseMac + RAMSize) {
        uint32_t offset = addr - RAMBaseMac;
        memcpy(data, RAMBaseHost + offset, size);
    } else if (addr >= ROMBaseMac && addr < ROMBaseMac + ROMSize) {
        uint32_t offset = addr - ROMBaseMac;
        memcpy(data, ROMBaseHost + offset, size);
    }
}

/* Register access */
uint32_t uae_get_dreg(int reg) {
    if (reg < 0 || reg > 7) return 0;
    return m68k_dreg(regs, reg);
}

uint32_t uae_get_areg(int reg) {
    if (reg < 0 || reg > 7) return 0;
    return m68k_areg(regs, reg);
}

uint32_t uae_get_pc(void) {
    return m68k_getpc();
}

uint16_t uae_get_sr(void) {
    extern void MakeSR(void);
    MakeSR();  /* Build SR from separate flag variables (OPTIMIZED_FLAGS) */
    return regs.sr;
}

void uae_set_dreg(int reg, uint32_t value) {
    if (reg < 0 || reg > 7) return;
    m68k_dreg(regs, reg) = value;
}

void uae_set_areg(int reg, uint32_t value) {
    if (reg < 0 || reg > 7) return;
    m68k_areg(regs, reg) = value;
}

void uae_set_pc(uint32_t value) {
    m68k_setpc(value);
    regs.pc = value;
    fill_prefetch_0();
}

void uae_set_sr(uint16_t value) {
    extern void MakeFromSR(void);
    regs.sr = value;
    MakeFromSR();  /* Extract flags from SR into separate variables (OPTIMIZED_FLAGS) */
}

/* Execution */

// Debug trace control (set CPU_TRACE=1 environment variable to enable)
static int cpu_trace_enabled = -1;  // -1 = uninitialized
static uint64_t cpu_trace_count = 0;
static uint64_t cpu_trace_max = 10;  // Default: trace first 10 instructions

static void cpu_trace_init(void) {
    const char *env = getenv("CPU_TRACE");
    if (env && atoi(env) > 0) {
        cpu_trace_enabled = 1;
        // Optional: CPU_TRACE=N to trace first N instructions
        int n = atoi(env);
        if (n > 1) {
            cpu_trace_max = n;
        }
        fprintf(stderr, "[CPU trace enabled: will trace first %lu instructions]\n",
                (unsigned long)cpu_trace_max);
    } else {
        cpu_trace_enabled = 0;
    }
}

void uae_cpu_execute_one(void) {
    /* Initialize trace on first call */
    if (cpu_trace_enabled == -1) {
        cpu_trace_init();
    }

    /* Capture PC before execution (for trace) */
    uae_u32 pc_before = m68k_getpc();

    /* Execute one instruction */
    uae_u32 opcode = GET_OPCODE;

    // Optional trace output (enabled via CPU_TRACE env var)
    if (cpu_trace_enabled && cpu_trace_count < cpu_trace_max) {
        fprintf(stderr, "[%04lu] PC=%08X OP=%04X | D0=%08X D1=%08X A0=%08X A7=%08X SR=%04X\n",
            (unsigned long)cpu_trace_count,
            (unsigned int)pc_before,
            (unsigned int)opcode,
            (unsigned int)regs.regs[0],   // D0
            (unsigned int)regs.regs[1],   // D1
            (unsigned int)regs.regs[8],   // A0
            (unsigned int)regs.regs[15],  // A7
            (unsigned int)regs.sr);
        cpu_trace_count++;
        if (cpu_trace_count == cpu_trace_max) {
            fprintf(stderr, "[Trace limit reached, disabling trace]\n");
        }
    }

    (*cpufunctbl[opcode])(opcode);
}

/* Set memory base pointers directly (for dual-CPU mode) */
extern uintptr MEMBaseDiff;  // From basilisk_glue.cpp

void uae_mem_set_ram_ptr(void *ptr, uint32_t size) {
    RAMBaseHost = (uint8 *)ptr;
    RAMSize = size;
    RAMBaseMac = 0x00000000;

    // Set MEMBaseDiff for direct addressing: host_ptr = mac_addr + MEMBaseDiff
    MEMBaseDiff = (uintptr)RAMBaseHost - RAMBaseMac;
}

void uae_mem_set_rom_ptr(void *ptr, uint32_t size) {
    ROMBaseHost = (uint8 *)ptr;
    ROMSize = size;
    ROMBaseMac = 0x00400000;  /* Typical Mac ROM location */
}

void uae_mem_set_rom_ptr_with_addr(void *ptr, uint32_t addr, uint32_t size) {
    ROMBaseHost = (uint8 *)ptr;
    ROMSize = size;
    ROMBaseMac = addr;  /* Use provided ROM address */
}

/* Disassembly */
void uae_disasm(uint32_t addr, uint32_t *next_pc, int count) {
    uaecptr npc;
    m68k_disasm(addr, &npc, count);
    if (next_pc) {
        *next_pc = npc;
    }
}
