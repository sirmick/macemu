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
void uae_cpu_execute_one(void) {
    /* Execute one instruction */
    static int first = 1;
    if (first) {
        fprintf(stderr, "DEBUG uae_cpu_execute_one BEFORE opcode fetch:\n");
        fprintf(stderr, "  regs.pc = 0x%08X\n", (unsigned int)regs.pc);
        fprintf(stderr, "  regs.pc_p = %p\n", (void*)regs.pc_p);
        fprintf(stderr, "  RAMBaseHost = %p\n", (void*)RAMBaseHost);
        fprintf(stderr, "  ROMBaseHost = %p\n", (void*)ROMBaseHost);
        fprintf(stderr, "  RAMBaseMac = 0x%08X\n", RAMBaseMac);
        fprintf(stderr, "  ROMBaseMac = 0x%08X\n", ROMBaseMac);
        fprintf(stderr, "  MEMBaseDiff = 0x%lX\n", (unsigned long)MEMBaseDiff);
        if (regs.pc_p) {
            uint8_t *p = (uint8_t*)regs.pc_p;
            fprintf(stderr, "  Bytes at regs.pc_p: %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3]);
        }
    }
    uae_u32 opcode = GET_OPCODE;
    if (first) {
        fprintf(stderr, "  Fetched opcode: 0x%04X\n", opcode);
        fprintf(stderr, "  Handler: %p\n", (void*)cpufunctbl[opcode]);
        first = 0;
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
