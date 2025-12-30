/**
 * Unicorn CPU Backend for Platform API
 *
 * Wraps Unicorn engine to conform to platform CPU interface.
 * Always available, no compile-time dependencies.
 */

#include "platform.h"
#include "unicorn_wrapper.h"
#include "unicorn_exception.h"
#include "cpu_trace.h"
#include <unicorn/unicorn.h>
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

// Platform EmulOp handler for Unicorn-only mode
// This needs to use platform API because it's called from within Unicorn's hook context
// and needs to properly sync registers back to Unicorn
static bool unicorn_platform_emulop_handler(uint16_t opcode, bool is_primary) {
	(void)is_primary;  // Unicorn is always primary in standalone mode

	// Build M68kRegisters structure from Unicorn state
	struct M68kRegisters regs;
	for (int i = 0; i < 8; i++) {
		regs.d[i] = unicorn_get_dreg(unicorn_cpu, i);
		regs.a[i] = unicorn_get_areg(unicorn_cpu, i);
	}
	regs.sr = unicorn_get_sr(unicorn_cpu);

	// Call EmulOp handler
	EmulOp(opcode, &regs);

	// IMPORTANT: Write registers back to Unicorn directly
	// We're outside uc_emu_start() so register writes will persist
	for (int i = 0; i < 8; i++) {
		g_platform.cpu_set_dreg(i, regs.d[i]);
		g_platform.cpu_set_areg(i, regs.a[i]);
	}
	g_platform.cpu_set_sr(regs.sr);

	// Debug: Verify A7 write for RESET EmulOp
	if (opcode == 0x7103) {
		uint32_t a7_readback = g_platform.cpu_get_areg(7);
		fprintf(stderr, "[EmulOp 0x7103] Set A7=0x%08X, readback=0x%08X\n",
		        regs.a[7], a7_readback);
	}

	// Return false to indicate PC was not advanced (caller will advance it)
	return false;
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
	fprintf(stderr, "[DEBUG] Mapping RAM to unicorn_cpu=%p: Mac=0x%08X Host=%p Size=0x%08X (%u MB)\n",
		(void*)unicorn_cpu, RAMBaseMac, RAMBaseHost, RAMSize, RAMSize / (1024*1024));
	if (!unicorn_map_ram(unicorn_cpu, RAMBaseMac, RAMBaseHost, RAMSize)) {
		fprintf(stderr, "Failed to map RAM to Unicorn\n");
		unicorn_destroy(unicorn_cpu);
		unicorn_cpu = NULL;
		return false;
	}

	// Map ROM as writable (BasiliskII patches ROM during boot)
	fprintf(stderr, "[DEBUG] Mapping ROM to unicorn_cpu=%p: Mac=0x%08X Host=%p Size=0x%08X (%u KB)\n",
		(void*)unicorn_cpu, ROMBaseMac, ROMBaseHost, ROMSize, ROMSize / 1024);
	if (!unicorn_map_rom_writable(unicorn_cpu, ROMBaseMac, ROMBaseHost, ROMSize)) {
		fprintf(stderr, "Failed to map ROM to Unicorn\n");
		unicorn_destroy(unicorn_cpu);
		unicorn_cpu = NULL;
		return false;
	}

	fprintf(stderr, "[DEBUG] unicorn_cpu instance at init: %p\n", (void*)unicorn_cpu);

	// Initialize CPU tracing from environment variable
	cpu_trace_init();

	// Register EmulOp handler via platform API
	// EmulOps are now handled in unicorn_execute_one() when UC_ERR_INSN_INVALID occurs
	// No hooks needed - this is faster and compatible with JIT
	g_platform.emulop_handler = unicorn_platform_emulop_handler;

	// Register exception handler for A-line/F-line traps (also handled via UC_ERR_INSN_INVALID)
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

	/* CPU tracing (controlled by CPU_TRACE env var) */
	if (cpu_trace_should_log()) {
		uint32_t pc = unicorn_get_pc(unicorn_cpu);
		uint16_t opcode = 0;
		uc_mem_read((uc_engine*)unicorn_get_uc(unicorn_cpu), pc, &opcode, sizeof(opcode));
		#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		opcode = __builtin_bswap16(opcode);
		#endif

		cpu_trace_log_simple(
			pc, opcode,
			unicorn_get_dreg(unicorn_cpu, 0),
			unicorn_get_dreg(unicorn_cpu, 1),
			unicorn_get_areg(unicorn_cpu, 0),
			unicorn_get_areg(unicorn_cpu, 7),
			unicorn_get_sr(unicorn_cpu)
		);
	}

	if (!unicorn_execute_one(unicorn_cpu)) {
		uint32_t pc = unicorn_get_pc(unicorn_cpu);
		uint32_t a7 = unicorn_get_areg(unicorn_cpu, 7);
		fprintf(stderr, "Unicorn execution failed: %s (unicorn_cpu=%p)\n",
			unicorn_get_error(unicorn_cpu), (void*)unicorn_cpu);
		fprintf(stderr, "PC=0x%08X A7=0x%08X A7-4=0x%08X\n", pc, a7, a7-4);
		return 3;  // CPU_EXEC_EXCEPTION
	}

	cpu_trace_increment();

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
