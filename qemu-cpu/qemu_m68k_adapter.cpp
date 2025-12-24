/*
 * QEMU M68K CPU Adapter for BasiliskII - Implementation
 *
 * This file implements BasiliskII's CPU API using QEMU's m68k emulation.
 */

#include "qemu_m68k_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* QEMU includes - paths relative to qemu directory */
extern "C" {
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "system/address-spaces.h"
#include "system/memory.h"
}

/* BasiliskII includes */
#include "sysdeps.h"
#include "cpu_emulation.h"
#include "main.h"
#include "emul_op.h"

/* Global QEMU CPU state */
static M68kCPU *qemu_cpu = NULL;
static CPUM68KState *qemu_env = NULL;

/* Memory regions */
static MemoryRegion ram_region;
static MemoryRegion rom_region;
static bool memory_initialized = false;

/* Memory pointers (from BasiliskII) */
static uint8_t *mac_ram_base = NULL;
static uint32_t mac_ram_size = 0;
static uint8_t *mac_rom_base = NULL;
static uint32_t mac_rom_size = 0;

/* Forward declarations */
static bool emulop_hook_handler(CPUM68KState *env, uint16_t opcode);
static void copy_regs_to_qemu(CPUM68KState *env, const M68kRegisters *r);
static void copy_regs_from_qemu(M68kRegisters *r, const CPUM68KState *env);

/*
 * EmulOp Hook Handler
 *
 * This is called by QEMU when it encounters an illegal instruction.
 * We check if it's a 0x71xx EmulOp and handle it if so.
 */
static bool emulop_hook_handler(CPUM68KState *env, uint16_t opcode)
{
    /* Check if it's an EmulOp (0x71xx range) */
    if ((opcode & 0xFF00) != 0x7100) {
        /* Not an EmulOp, let QEMU handle it as normal illegal instruction */
        return false;
    }

    /* Extract EmulOp selector */
    uint16_t selector = opcode & 0xFF;

    D(bug("EmulOp hook: opcode=0x%04x, selector=0x%02x, PC=0x%08x\n",
          opcode, selector, env->pc));

    /* Convert QEMU CPU state to BasiliskII's M68kRegisters format */
    M68kRegisters regs;
    copy_regs_from_qemu(&regs, env);

    /* Call BasiliskII's existing EmulOp handler */
    EmulOp(selector, &regs);

    /* Copy registers back to QEMU */
    copy_regs_to_qemu(env, &regs);

    /* Advance PC past the illegal instruction (2 bytes) */
    env->pc += 2;

    /* Return true to indicate we handled it (skip normal exception) */
    return true;
}

/*
 * Helper: Copy BasiliskII registers to QEMU
 */
static void copy_regs_to_qemu(CPUM68KState *env, const M68kRegisters *r)
{
    for (int i = 0; i < 8; i++) {
        env->dregs[i] = r->d[i];
        env->aregs[i] = r->a[i];
    }
    env->sr = r->sr;
}

/*
 * Helper: Copy QEMU registers to BasiliskII
 */
static void copy_regs_from_qemu(M68kRegisters *r, const CPUM68KState *env)
{
    for (int i = 0; i < 8; i++) {
        r->d[i] = env->dregs[i];
        r->a[i] = env->aregs[i];
    }
    r->sr = env->sr;
}

/*
 * Setup Memory Regions
 *
 * Called by BasiliskII to tell us where RAM and ROM are located.
 * This creates QEMU MemoryRegion objects that point to BasiliskII's
 * pre-allocated RAM and ROM buffers (zero-copy approach).
 */
void QEMU_SetupMemory(uint8_t *ram_base, uint32_t ram_size,
                      uint8_t *rom_base, uint32_t rom_size)
{
    mac_ram_base = ram_base;
    mac_ram_size = ram_size;
    mac_rom_base = rom_base;
    mac_rom_size = rom_size;

    D(bug("QEMU memory setup: RAM=%p size=0x%x, ROM=%p size=0x%x\n",
          ram_base, ram_size, rom_base, rom_size));

    if (memory_initialized) {
        D(bug("QEMU memory already initialized, skipping\n"));
        return;
    }

    if (!qemu_cpu) {
        fprintf(stderr, "QEMU: CPU not initialized, cannot setup memory\n");
        return;
    }

    /* Get the system memory region (root of the address space) */
    MemoryRegion *sysmem = get_system_memory();

    /*
     * Initialize RAM region using zero-copy approach
     * memory_region_init_ram_ptr() creates a MemoryRegion that points
     * directly to BasiliskII's pre-allocated RAM buffer
     */
    memory_region_init_ram_ptr(&ram_region,
                               OBJECT(qemu_cpu),
                               "mac.ram",
                               ram_size,
                               ram_base);

    /*
     * Mac RAM starts at address 0 in the 68k address space
     * BasiliskII uses REAL_ADDRESSING mode where Mac addresses = host addresses
     */
    memory_region_add_subregion(sysmem, 0x00000000, &ram_region);

    D(bug("QEMU: Mapped RAM at 0x%08x size 0x%x\n", 0x00000000, ram_size));

    /*
     * Initialize ROM region (also zero-copy)
     * ROM is typically at 0x00400000 (4MB) in Classic Mac II/Quadra
     */
    memory_region_init_ram_ptr(&rom_region,
                               OBJECT(qemu_cpu),
                               "mac.rom",
                               rom_size,
                               rom_base);

    /* ROM is read-only */
    memory_region_set_readonly(&rom_region, true);

    /*
     * ROM base address - BasiliskII typically places ROM at RAMSize
     * For now, use a fixed address of 0x00400000 (4MB) which is standard
     * for Mac II/Quadra. TODO: Make this configurable based on ROMBaseMac
     */
    uint32_t rom_addr = 0x00400000;
    memory_region_add_subregion(sysmem, rom_addr, &rom_region);

    D(bug("QEMU: Mapped ROM at 0x%08x size 0x%x (read-only)\n", rom_addr, rom_size));

    memory_initialized = true;
    D(bug("QEMU memory setup complete\n"));
}

/*
 * Initialize QEMU CPU
 *
 * Initialization order:
 * 1. Init680x0_QEMU() - creates CPU and registers hooks
 * 2. QEMU_SetupMemory() - called by BasiliskII after RAM/ROM allocation
 * 3. Start680x0_QEMU() - starts main execution loop
 */
bool Init680x0_QEMU(void)
{
    D(bug("Init680x0_QEMU: Initializing QEMU m68k CPU\n"));

    /* Initialize QEMU's type system */
    module_call_init(MODULE_INIT_QOM);

    /* Create m68040 CPU */
    qemu_cpu = M68K_CPU(cpu_create("m68040"));
    if (!qemu_cpu) {
        fprintf(stderr, "QEMU: Failed to create m68040 CPU\n");
        return false;
    }

    qemu_env = &qemu_cpu->env;
    D(bug("QEMU CPU created: %p\n", qemu_cpu));

    /* Register our EmulOp hook */
    extern bool (*m68k_illegal_insn_hook)(CPUM68KState *env, uint16_t opcode);
    m68k_illegal_insn_hook = emulop_hook_handler;
    D(bug("EmulOp hook registered at %p\n", (void*)m68k_illegal_insn_hook));

    /*
     * Memory setup happens later via QEMU_SetupMemory()
     * BasiliskII will call it after allocating RAM/ROM buffers
     */

    /* Initialize CPU state */
    qemu_env->pc = 0;  /* Will be set by ROM */
    qemu_env->sr = 0x2700;  /* Supervisor mode, interrupts masked */

    D(bug("Init680x0_QEMU: Success\n"));
    return true;
}

/*
 * Shutdown QEMU CPU
 */
void Exit680x0_QEMU(void)
{
    D(bug("Exit680x0_QEMU: Shutting down QEMU CPU\n"));

    /* Clean up memory regions if initialized */
    if (memory_initialized) {
        MemoryRegion *sysmem = get_system_memory();

        /* Remove regions from address space before destroying */
        memory_region_del_subregion(sysmem, &rom_region);
        memory_region_del_subregion(sysmem, &ram_region);

        D(bug("QEMU: Memory regions removed\n"));
        memory_initialized = false;
    }

    /* CPU will be cleaned up by QEMU */
    qemu_cpu = NULL;
    qemu_env = NULL;
}

/*
 * Start CPU execution (main loop)
 */
void Start680x0_QEMU(void)
{
    D(bug("Start680x0_QEMU: Starting CPU execution loop\n"));

    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    /* TODO: Implement main execution loop
     * This would be similar to UAE's m68k_execute() but using QEMU's cpu_exec()
     * For now, this is a placeholder
     */

    fprintf(stderr, "Start680x0_QEMU: Not yet implemented\n");
}

/*
 * Execute 68k code at specific address
 * Called from EmulOp handlers to run Mac ROM code
 */
void Execute68k_QEMU(uint32_t addr, M68kRegisters *r)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    D(bug("Execute68k_QEMU: addr=0x%08x\n", addr));

    /* Copy registers to QEMU */
    copy_regs_to_qemu(qemu_env, r);

    /* Set PC */
    qemu_env->pc = addr;

    /* TODO: Execute until M68K_EXEC_RETURN (0x7100) is encountered
     * This requires integration with QEMU's cpu_exec() loop
     */

    /* Copy registers back */
    copy_regs_from_qemu(r, qemu_env);
}

/*
 * Execute 68k trap
 * Called from EmulOp handlers to invoke Mac OS traps
 */
void Execute68kTrap_QEMU(uint16_t trap, M68kRegisters *r)
{
    if (!qemu_env) {
        fprintf(stderr, "QEMU: CPU not initialized!\n");
        return;
    }

    D(bug("Execute68kTrap_QEMU: trap=0x%04x\n", trap));

    /* TODO: Implement trap execution
     * This needs to:
     * 1. Push trap number and return address on stack
     * 2. Vector to trap handler
     * 3. Execute until RTS
     */

    fprintf(stderr, "Execute68kTrap_QEMU: Not yet implemented\n");
}

/*
 * Trigger interrupt
 */
void TriggerInterrupt_QEMU(void)
{
    if (!qemu_env) {
        return;
    }

    D(bug("TriggerInterrupt_QEMU: Triggering level 1 interrupt\n"));

    /* TODO: Use QEMU's interrupt API
     * cpu_interrupt(CPU(qemu_cpu), CPU_INTERRUPT_HARD);
     */
}

/*
 * Trigger NMI (level 7 interrupt)
 */
void TriggerNMI_QEMU(void)
{
    if (!qemu_env) {
        return;
    }

    D(bug("TriggerNMI_QEMU: Triggering NMI\n"));

    /* TODO: Implement NMI via QEMU interrupt API */
}
