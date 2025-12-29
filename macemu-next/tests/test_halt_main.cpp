/*
 *  test_halt_main.cpp - Minimal test with single HALT instruction
 *
 *  Tests: Can UAE CPU execute one instruction and halt?
 *
 *  This is the simplest possible test:
 *  - Load minimal ROM with just STOP instruction
 *  - Configure UAE CPU in verbose/debug mode
 *  - Execute one instruction
 *  - Verify CPU halted
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "sysdeps.h"
#include "cpu_emulation.h"
#include "uae_wrapper.h"
#include "newcpu.h"
#include "platform.h"

// Global variables (declared extern in cpu_emulation.h, defined in basilisk_glue.cpp)
extern uint8 *RAMBaseHost;
extern uint8 *ROMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMSize;

#if DIRECT_ADDRESSING
extern uintptr MEMBaseDiff;
extern uint32 RAMBaseMac;
extern uint32 ROMBaseMac;
#endif

// Scratch memory (not used)
extern uint8 *ScratchMem;

/*
 *  Load ROM file
 */
static bool load_rom(const char *rom_path)
{
	// Open ROM file
	int fd = open(rom_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: Failed to open ROM file: %s\n", rom_path);
		return false;
	}

	// Get file size
	ROMSize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	printf("Loading ROM from %s...\n", rom_path);
	printf("ROM size: %u bytes\n", ROMSize);

	// Read ROM
	ssize_t bytes_read = read(fd, ROMBaseHost, ROMSize);
	close(fd);

	if (bytes_read != ROMSize) {
		fprintf(stderr, "ERROR: Failed to read ROM file\n");
		return false;
	}

	printf("ROM loaded successfully\n");
	return true;
}

int main(int argc, char **argv)
{
	printf("=== test_halt - Minimal UAE CPU Test ===\n\n");

	// Initialize platform with null drivers
	platform_init();

	// Check for ROM file argument
	const char *rom_path = "roms/test_halt.bin";
	if (argc >= 2) {
		rom_path = argv[1];
	}

	// Initialize global pointers (they're extern, defined in basilisk_glue.cpp as NULL)
	// We need to allocate and set them
	RAMSize = 1 * 1024 * 1024;  // 1MB (minimal)
	ROMSize = 1 * 1024 * 1024;  // 1MB max

	printf("Allocating RAM (%u KB)...\n", RAMSize / 1024);

	// Allocate RAM + ROM in one chunk (like test_boot does)
	RAMBaseHost = (uint8 *)mmap(NULL, RAMSize + 0x100000,
	                             PROT_READ | PROT_WRITE,
	                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (RAMBaseHost == MAP_FAILED) {
		fprintf(stderr, "ERROR: Failed to allocate RAM\n");
		return 1;
	}

	// ROM right after RAM
	ROMBaseHost = RAMBaseHost + RAMSize;
	memset(RAMBaseHost, 0, RAMSize);

#if DIRECT_ADDRESSING
	// Set up direct addressing (exactly like test_boot does)
	MEMBaseDiff = (uintptr)RAMBaseHost;
	RAMBaseMac = 0;
	ROMBaseMac = Host2MacAddr(ROMBaseHost);  // ROMBaseHost - MEMBaseDiff

	printf("RAM at %p (Mac: 0x%08x)\n", RAMBaseHost, RAMBaseMac);
	printf("ROM at %p (Mac: 0x%08x)\n", ROMBaseHost, ROMBaseMac);
	printf("MEMBaseDiff = 0x%016lx\n\n", MEMBaseDiff);
#endif

	// Load ROM
	if (!load_rom(rom_path)) {
		munmap(RAMBaseHost, RAMSize);
		munmap(ROMBaseHost, ROMSize);
		return 1;
	}

	printf("\n=== Initializing UAE CPU ===\n");

	// Initialize UAE CPU
	init_m68k();

	printf("UAE CPU initialized\n");

	// Reset CPU to ROM entry point
	printf("\n=== Resetting CPU ===\n");
	m68k_reset();

	// Print CPU state
	printf("\nCPU reset complete. Registers:\n");
	printf("  PC = 0x%08x\n", m68k_getpc());
	printf("  A7 = 0x%08x\n", m68k_areg(regs, 7));
	printf("  SR = 0x%04x\n", regs.sr);

	// Verify ROM header was read
	uint32 initial_sp = (ROMBaseHost[0] << 24) | (ROMBaseHost[1] << 16) |
	                    (ROMBaseHost[2] << 8) | ROMBaseHost[3];
	uint32 initial_pc = (ROMBaseHost[4] << 24) | (ROMBaseHost[5] << 16) |
	                    (ROMBaseHost[6] << 8) | ROMBaseHost[7];

	printf("\nROM Header:\n");
	printf("  Initial SP: 0x%08x\n", initial_sp);
	printf("  Initial PC: 0x%08x\n", initial_pc);

	// Verify opcode at entry point
	uint32 entry_offset = initial_pc - ROMBaseMac;
	uint16 opcode = (ROMBaseHost[entry_offset] << 8) | ROMBaseHost[entry_offset + 1];
	printf("  Opcode at PC: 0x%04x", opcode);
	if (opcode == 0x4E72) {
		printf(" (STOP)\n");
	} else {
		printf(" (unknown)\n");
	}

	printf("\n=== Executing Single Instruction ===\n");
	printf("Instruction trace:\n");

	// Execute exactly 1 instruction
	int instructions_executed = 0;

	// Single-step mode
	if (!regs.stopped) {
		printf("[%4d] PC=0x%08x SR=0x%04x ", instructions_executed, m68k_getpc(), regs.sr);

		// Execute one instruction
		m68k_do_execute();

		printf("-> PC=0x%08x (stopped=%d)\n", m68k_getpc(), regs.stopped);
		instructions_executed++;
	}

	printf("\n=== Test Complete ===\n");
	printf("Instructions executed: %d\n", instructions_executed);
	printf("CPU stopped: %s\n", regs.stopped ? "YES" : "NO");

	// Verify results
	bool passed = true;
	if (instructions_executed != 1) {
		printf("FAIL: Expected 1 instruction, got %d\n", instructions_executed);
		passed = false;
	}
	if (!regs.stopped) {
		printf("FAIL: CPU should be stopped after STOP instruction\n");
		passed = false;
	}

	if (passed) {
		printf("\n*** PASS: test_halt ***\n");
	} else {
		printf("\n*** FAIL: test_halt ***\n");
	}

	// Cleanup
	munmap(RAMBaseHost, RAMSize);
	munmap(ROMBaseHost, ROMSize);

	return passed ? 0 : 1;
}
