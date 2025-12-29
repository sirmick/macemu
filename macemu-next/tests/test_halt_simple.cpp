/*
 *  test_halt_simple.cpp - Absolute minimal test with single HALT instruction
 *
 *  Does NOT call InitAll() - directly uses UAE CPU for maximum simplicity.
 *
 *  Goal: Load tiny ROM, execute one STOP instruction, verify CPU halted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "sysdeps.h"
#include "cpu_emulation.h"
#include "newcpu.h"
#include "readcpu.h"

// Global variables (defined in basilisk_glue.cpp)
extern uint8 *RAMBaseHost;
extern uint8 *ROMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMSize;

#if DIRECT_ADDRESSING
extern uintptr MEMBaseDiff;
extern uint32 RAMBaseMac;
extern uint32 ROMBaseMac;
#endif

/*
 *  Load ROM file
 */
static bool load_rom(const char *rom_path)
{
	int fd = open(rom_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: Failed to open ROM file: %s\n", rom_path);
		return false;
	}

	ROMSize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	printf("Loading ROM from %s (size: %u bytes)...\n", rom_path, ROMSize);

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
	printf("=== test_halt_simple - UAE CPU Minimal Test ===\n\n");

	const char *rom_path = (argc >= 2) ? argv[1] : "roms/test_halt.bin";

	// Allocate memory
	RAMSize = 1 * 1024 * 1024;  // 1MB
	printf("Allocating RAM (%u KB)...\n", RAMSize / 1024);

	RAMBaseHost = (uint8 *)mmap(NULL, RAMSize + 0x100000,
	                             PROT_READ | PROT_WRITE,
	                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (RAMBaseHost == MAP_FAILED) {
		fprintf(stderr, "ERROR: Failed to allocate RAM\n");
		return 1;
	}

	ROMBaseHost = RAMBaseHost + RAMSize;
	memset(RAMBaseHost, 0, RAMSize);

#if DIRECT_ADDRESSING
	MEMBaseDiff = (uintptr)RAMBaseHost;
	RAMBaseMac = 0;
	ROMBaseMac = Host2MacAddr(ROMBaseHost);

	printf("RAM at %p (Mac: 0x%08x)\n", RAMBaseHost, RAMBaseMac);
	printf("ROM at %p (Mac: 0x%08x)\n", ROMBaseHost, ROMBaseMac);
	printf("MEMBaseDiff = 0x%016lx\n\n", MEMBaseDiff);
#endif

	if (!load_rom(rom_path)) {
		munmap(RAMBaseHost, RAMSize + 0x100000);
		return 1;
	}

	// Verify ROM header
	uint32 initial_sp = (ROMBaseHost[0] << 24) | (ROMBaseHost[1] << 16) |
	                    (ROMBaseHost[2] << 8) | ROMBaseHost[3];
	uint32 initial_pc = (ROMBaseHost[4] << 24) | (ROMBaseHost[5] << 16) |
	                    (ROMBaseHost[6] << 8) | ROMBaseHost[7];

	printf("\nROM Header:\n");
	printf("  Initial SP: 0x%08x\n", initial_sp);
	printf("  Initial PC: 0x%08x\n", initial_pc);

	uint32 entry_offset = initial_pc - ROMBaseMac;
	uint16 opcode = (ROMBaseHost[entry_offset] << 8) | ROMBaseHost[entry_offset + 1];
	printf("  Opcode at entry: 0x%04x", opcode);
	if (opcode == 0x4E72) printf(" (STOP)\n");
	else printf(" (unknown)\n");

	printf("\n=== Initializing UAE CPU ===\n");

	// Initialize CPU tables
	init_m68k();
	printf("CPU tables built\n");

	// Reset CPU - this reads ROM vectors
	printf("\n=== Resetting CPU ===\n");
	m68k_reset();

	// Check CPU state
	printf("\nCPU state after reset:\n");
	printf("  PC = 0x%08x\n", m68k_getpc());
	printf("  A7 = 0x%08x\n", m68k_areg(regs, 7));
	printf("  SR = 0x%04x\n", regs.sr);
	printf("  Stopped = %d\n", regs.stopped);

	printf("\n=== Executing One Instruction ===\n");

	if (!regs.stopped) {
		printf("Before: PC=0x%08x stopped=%d\n", m68k_getpc(), regs.stopped);

		// Execute single instruction
		m68k_do_execute();

		printf("After:  PC=0x%08x stopped=%d\n", m68k_getpc(), regs.stopped);
	}

	printf("\n=== Test Complete ===\n");
	printf("CPU stopped: %s\n", regs.stopped ? "YES" : "NO");

	bool passed = regs.stopped;
	if (passed) {
		printf("\n*** PASS: CPU executed STOP and halted ***\n");
	} else {
		printf("\n*** FAIL: CPU did not halt ***\n");
	}

	munmap(RAMBaseHost, RAMSize + 0x100000);
	return passed ? 0 : 1;
}
