/**
 * Unicorn CPU Backend for Platform API
 *
 * Wraps Unicorn engine to conform to platform CPU interface.
 * Always available, no compile-time dependencies.
 */

#include "platform.h"
#include "unicorn_wrapper.h"
#include "unicorn_exception.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

// M68kRegisters structure (from main.h, duplicated to avoid type conflicts)
struct M68kRegisters {
	uint32_t d[8];
	uint32_t a[8];
	uint16_t sr;
};

// Forward declarations (from macemu globals)
extern uint32_t RAMBaseMac;  // RAM base in Mac address space
extern uint8_t *RAMBaseHost; // RAM base in host address space
extern uint32_t RAMSize;     // RAM size
extern uint32_t ROMBaseMac;  // ROM base in Mac address space
extern uint8_t *ROMBaseHost; // ROM base in host address space
extern uint32_t ROMSize;     // ROM size
extern void EmulOp(uint16_t opcode, struct M68kRegisters *r);

static UnicornCPU *unicorn_cpu = NULL;

// EmulOp handler for Unicorn-only mode
static void unicorn_emulop_handler(uint16_t opcode, void *user_data) {
	(void)user_data;

	// Build M68kRegisters structure from Unicorn state
	struct M68kRegisters regs;
	for (int i = 0; i < 8; i++) {
		regs.d[i] = unicorn_get_dreg(unicorn_cpu, i);
		regs.a[i] = unicorn_get_areg(unicorn_cpu, i);
	}
	regs.sr = unicorn_get_sr(unicorn_cpu);

	// Call EmulOp handler
	EmulOp(opcode, &regs);

	// Write registers back to Unicorn
	for (int i = 0; i < 8; i++) {
		unicorn_set_dreg(unicorn_cpu, i, regs.d[i]);
		unicorn_set_areg(unicorn_cpu, i, regs.a[i]);
	}
	unicorn_set_sr(unicorn_cpu, regs.sr);
}

// CPU Lifecycle
static bool unicorn_backend_init(void) {
	if (unicorn_cpu) {
		return true;  // Already initialized
	}

	// Create Unicorn CPU with 68030 model (matches UAE CPUType=3)
	#define UC_CPU_M68K_M68030 3
	unicorn_cpu = unicorn_create_with_model(UCPU_ARCH_M68K, UC_CPU_M68K_M68030);
	if (!unicorn_cpu) {
		fprintf(stderr, "Failed to create Unicorn CPU\n");
		return false;
	}

	// Map RAM to Unicorn
	if (!unicorn_map_ram(unicorn_cpu, RAMBaseMac, RAMBaseHost, RAMSize)) {
		fprintf(stderr, "Failed to map RAM to Unicorn\n");
		unicorn_destroy(unicorn_cpu);
		unicorn_cpu = NULL;
		return false;
	}

	// Map ROM as writable (BasiliskII patches ROM during boot)
	if (!unicorn_map_rom_writable(unicorn_cpu, ROMBaseMac, ROMBaseHost, ROMSize)) {
		fprintf(stderr, "Failed to map ROM to Unicorn\n");
		unicorn_destroy(unicorn_cpu);
		unicorn_cpu = NULL;
		return false;
	}

	// Register EmulOp handler for 0x71xx illegal instructions
	unicorn_set_emulop_handler(unicorn_cpu, unicorn_emulop_handler, NULL);

	// Register exception handler for A-line/F-line traps
	unicorn_set_exception_handler(unicorn_cpu, unicorn_simulate_exception);

	return true;
}

static void unicorn_backend_reset(void) {
	if (!unicorn_cpu) return;

	// M68K reset: Initialize registers to power-on state
	for (int i = 0; i < 8; i++) {
		unicorn_set_dreg(unicorn_cpu, i, 0);
		unicorn_set_areg(unicorn_cpu, i, 0);
	}

	// Set A7 (SSP) to initial stack pointer value
	unicorn_set_areg(unicorn_cpu, 7, 0x2000);

	// Set PC to ROM entry point (matching UAE's m68k_reset)
	unicorn_set_pc(unicorn_cpu, ROMBaseMac + 0x2a);

	// Set SR: Supervisor mode, interrupt mask 7
	unicorn_set_sr(unicorn_cpu, 0x2700);  // S=1, I=111
}

static void unicorn_backend_destroy(void) {
	if (unicorn_cpu) {
		unicorn_destroy(unicorn_cpu);
		unicorn_cpu = NULL;
	}
}

// Execution
static int unicorn_backend_execute_one(void) {
	if (!unicorn_cpu) {
		return 3;  // CPU_EXEC_EXCEPTION
	}

	if (!unicorn_execute_one(unicorn_cpu)) {
		return 3;  // CPU_EXEC_EXCEPTION
	}

	// Unicorn doesn't track STOP state separately
	return 0;  // CPU_EXEC_OK
}

static void unicorn_backend_execute_fast(void) {
	// Unicorn doesn't have fast path
}

// State Query
static bool unicorn_backend_is_stopped(void) {
	// Unicorn doesn't track STOP state
	return false;
}

static uint32_t unicorn_backend_get_pc(void) {
	if (!unicorn_cpu) return 0;
	return unicorn_get_pc(unicorn_cpu);
}

static uint16_t unicorn_backend_get_sr(void) {
	if (!unicorn_cpu) return 0;
	return unicorn_get_sr(unicorn_cpu);
}

static uint32_t unicorn_backend_get_dreg(int n) {
	if (!unicorn_cpu) return 0;
	return unicorn_get_dreg(unicorn_cpu, n);
}

static uint32_t unicorn_backend_get_areg(int n) {
	if (!unicorn_cpu) return 0;
	return unicorn_get_areg(unicorn_cpu, n);
}

// State Modification
static void unicorn_backend_set_pc(uint32_t pc) {
	if (!unicorn_cpu) return;
	unicorn_set_pc(unicorn_cpu, pc);
}

static void unicorn_backend_set_sr(uint16_t sr) {
	if (!unicorn_cpu) return;
	unicorn_set_sr(unicorn_cpu, sr);
}

static void unicorn_backend_set_dreg(int n, uint32_t val) {
	if (!unicorn_cpu) return;
	unicorn_set_dreg(unicorn_cpu, n, val);
}

static void unicorn_backend_set_areg(int n, uint32_t val) {
	if (!unicorn_cpu) return;
	unicorn_set_areg(unicorn_cpu, n, val);
}

// Memory Access
static void unicorn_backend_mem_read(uint32_t addr, void *data, uint32_t size) {
	if (!unicorn_cpu) return;
	unicorn_mem_read(unicorn_cpu, addr, data, size);
}

static void unicorn_backend_mem_write(uint32_t addr, const void *data, uint32_t size) {
	if (!unicorn_cpu) return;
	unicorn_mem_write(unicorn_cpu, addr, data, size);
}

// Interrupts
static void unicorn_backend_trigger_interrupt(int level) {
	// TODO: Implement interrupt triggering for Unicorn
	(void)level;
}

/**
 * Install Unicorn CPU backend into platform
 */
void cpu_unicorn_install(Platform *p) {
	p->cpu_name = "Unicorn Engine";

	// Lifecycle
	p->cpu_init = unicorn_backend_init;
	p->cpu_reset = unicorn_backend_reset;
	p->cpu_destroy = unicorn_backend_destroy;

	// Execution
	p->cpu_execute_one = unicorn_backend_execute_one;
	p->cpu_execute_fast = NULL;  // No fast path

	// State query
	p->cpu_is_stopped = unicorn_backend_is_stopped;
	p->cpu_get_pc = unicorn_backend_get_pc;
	p->cpu_get_sr = unicorn_backend_get_sr;
	p->cpu_get_dreg = unicorn_backend_get_dreg;
	p->cpu_get_areg = unicorn_backend_get_areg;

	// State modification
	p->cpu_set_pc = unicorn_backend_set_pc;
	p->cpu_set_sr = unicorn_backend_set_sr;
	p->cpu_set_dreg = unicorn_backend_set_dreg;
	p->cpu_set_areg = unicorn_backend_set_areg;

	// Memory access
	p->cpu_mem_read = unicorn_backend_mem_read;
	p->cpu_mem_write = unicorn_backend_mem_write;

	// Interrupts
	p->cpu_trigger_interrupt = unicorn_backend_trigger_interrupt;
}
