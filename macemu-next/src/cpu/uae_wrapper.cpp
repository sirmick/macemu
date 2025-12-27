/**
 * UAE CPU Wrapper Implementation
 */

#include "uae_wrapper.h"

// UAE CPU headers
extern "C" {
#include "uae_cpu/sysdeps.h"
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

    /* Determine if writing to RAM or ROM */
    if (addr >= RAMBaseMac && addr < RAMBaseMac + RAMSize) {
        uint32_t offset = addr - RAMBaseMac;
        memcpy(RAMBaseHost + offset, data, size);
    } else if (addr >= ROMBaseMac && addr < ROMBaseMac + ROMSize) {
        uint32_t offset = addr - ROMBaseMac;
        memcpy(ROMBaseHost + offset, data, size);
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
    regs.sr = value;
}

/* Execution */
void uae_cpu_execute_one(void) {
    /* Execute one instruction using UAE's dispatch table */
    extern cpuop_func *cpufunctbl[];
    uae_u32 opcode = GET_OPCODE;
    (*cpufunctbl[opcode])(opcode);
}
