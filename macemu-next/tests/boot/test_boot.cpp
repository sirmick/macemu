/*
 *  test_boot.cpp - Minimal boot test for macemu-next
 *
 *  Tests the initialization sequence with dummy drivers
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
#include "newcpu.h"  // For regstruct and regs
#include "main.h"
#include "prefs.h"
#include "video.h"
#include "xpram.h"
#include "timer.h"
#include "sony.h"
#include "disk.h"
#include "cdrom.h"
#include "scsi.h"
#include "serial.h"
#include "ether.h"
#include "clip.h"
#include "adb.h"
#include "audio.h"
#include "rom_patches.h"
#include "user_strings.h"
#include "platform.h"

#define DEBUG 1
#include "debug.h"

// Global variables (defined in basilisk_glue.cpp when using dualcpu backend)
extern uint8 *RAMBaseHost;
extern uint8 *ROMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMSize;

#if DIRECT_ADDRESSING
// MEMBaseDiff, RAMBaseMac, ROMBaseMac are defined in uae_wrapper.cpp/basilisk_glue.cpp
extern uintptr MEMBaseDiff;
extern uint32 RAMBaseMac;
extern uint32 ROMBaseMac;
#endif

// CPU and FPU type (CPUType/FPUType defined in uae_wrapper.cpp)
extern int CPUType;
bool CPUIs68060;
extern int FPUType;
bool TwentyFourBitAddressing;

// Error handling (these are defined in main.cpp, but we need const char* versions)
void ErrorAlert(const char *text)
{
	fprintf(stderr, "ERROR: %s\n", text);
}

void WarningAlert(const char *text)
{
	fprintf(stderr, "WARNING: %s\n", text);
}

// Quit emulator
void QuitEmulator(void)
{
	printf("QuitEmulator() called\n");
	ExitAll();
	exit(1);
}

// Interrupt flags (declared in main.h and defined in uae_wrapper.cpp)
extern uint32 InterruptFlags;

// Disable interrupts (stub)
void DisableInterrupt(void)
{
}

// Enable interrupts (stub - specific to test)
void EnableInterrupt(void)
{
}

// NOTE: Most stubs have been moved to platform_null.cpp and are linked from libdrivers.a
// Only test-specific overrides remain here.

int main(int argc, char **argv)
{
	printf("=== macemu-next Boot Test ===\n\n");

	// Initialize platform with null drivers
	platform_init();

	// Check for ROM file argument
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <rom-file>\n", argv[0]);
		return 1;
	}
	const char *rom_path = argv[1];

	// Initialize random number generator
	srand(time(NULL));

	// Set RAM size before PrefsInit
	RAMSize = 32 * 1024 * 1024;  // 32MB

	// Read preferences (minimal)
	PrefsInit(NULL, argc, argv);
	PrefsAddInt32("ramsize", RAMSize);
	PrefsAddInt32("cpu", 4);  // 68040
	PrefsAddBool("fpu", true);

	printf("Allocating RAM (%d MB)...\n", RAMSize / (1024 * 1024));

	// Allocate RAM (simple mmap for now)
	RAMBaseHost = (uint8 *)mmap(NULL, RAMSize + 0x100000,
	                             PROT_READ | PROT_WRITE,
	                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (RAMBaseHost == MAP_FAILED) {
		fprintf(stderr, "Failed to allocate RAM\n");
		return 1;
	}

	ROMBaseHost = RAMBaseHost + RAMSize;
	memset(RAMBaseHost, 0, RAMSize);

#if DIRECT_ADDRESSING
	// RAMBaseMac shall always be zero
	MEMBaseDiff = (uintptr)RAMBaseHost;
	RAMBaseMac = 0;
	ROMBaseMac = Host2MacAddr(ROMBaseHost);
#endif

	printf("RAM at %p (Mac: 0x%08x)\n", RAMBaseHost, RAMBaseMac);
	printf("ROM at %p (Mac: 0x%08x)\n", ROMBaseHost, ROMBaseMac);

	// Load ROM
	printf("\nLoading ROM from %s...\n", rom_path);
	int rom_fd = open(rom_path, O_RDONLY);
	if (rom_fd < 0) {
		fprintf(stderr, "Failed to open ROM file: %s\n", rom_path);
		return 1;
	}

	ROMSize = lseek(rom_fd, 0, SEEK_END);
	printf("ROM size: %d bytes (%d KB)\n", ROMSize, ROMSize / 1024);

	if (ROMSize != 64*1024 && ROMSize != 128*1024 && ROMSize != 256*1024 &&
	    ROMSize != 512*1024 && ROMSize != 1024*1024) {
		fprintf(stderr, "Invalid ROM size (must be 64/128/256/512/1024 KB)\n");
		close(rom_fd);
		return 1;
	}

	lseek(rom_fd, 0, SEEK_SET);
	if (read(rom_fd, ROMBaseHost, ROMSize) != (ssize_t)ROMSize) {
		fprintf(stderr, "Failed to read ROM file\n");
		close(rom_fd);
		return 1;
	}
	close(rom_fd);

	// ROM is stored in big-endian format (as in the file)
	// UAE's do_get_mem_word() will handle byte-swapping when the CPU reads it
	printf("ROM loaded successfully (kept in big-endian format)\n");

	// Initialize everything
	printf("\n=== Initializing Emulator ===\n");
	if (!InitAll(NULL)) {
		fprintf(stderr, "Initialization failed\n");
		return 1;
	}

	printf("\n=== Initialization Complete ===\n");
	printf("ROM Version: 0x%08x\n", ROMVersion);
	printf("CPU Type: 680%02d\n", (CPUType == 0) ? 0 : (CPUType * 10 + 20));
	printf("FPU: %s\n", FPUType ? "Yes" : "No");
	printf("24-bit addressing: %s\n", TwentyFourBitAddressing ? "Yes" : "No");

#ifdef CPU_EMULATION_DUALCPU
	// Initialize Unicorn validation (runs Unicorn in lockstep with UAE)
	extern "C" {
		bool unicorn_validation_init(void);
		void unicorn_validation_shutdown(void);
	}

	printf("\n");
	if (!unicorn_validation_init()) {
		fprintf(stderr, "Failed to initialize Unicorn validation\n");
		return 1;
	}
#endif

	// Reset CPU (like BasiliskII's Start680x0() does)
	// This sets PC to ROMBaseMac + 0x2a and A7 to 0x2000
	printf("\nResetting CPU (calling m68k_reset)...\n");
	extern void m68k_reset(void);  // From UAE CPU
	m68k_reset();

	printf("\nCPU reset complete. Registers:\n");
	printf("  PC = 0x%08x\n", uae_get_pc());
	printf("  A7 = 0x%08x\n", uae_get_areg(7));
	printf("  SR = 0x%04x\n", uae_get_sr());

	// Check regs.pc_p to see where it's actually pointing
	extern regstruct regs;  // From UAE CPU (defined in newcpu.h)
	printf("\nInternal CPU state:\n");
	printf("  regs.pc_p = %p\n", (void *)regs.pc_p);
	printf("  Should be: %p (ROMBaseHost + 0x2a)\n", (void *)(ROMBaseHost + 0x2a));
	if (regs.pc_p) {
		uint8_t *ptr = (uint8_t *)regs.pc_p;
		printf("  Bytes at regs.pc_p: %02x %02x %02x %02x\n",
		       ptr[0], ptr[1], ptr[2], ptr[3]);
	}
	fflush(stdout);

	// Execute instructions (like BasiliskII's m68k_execute() but with a limit)
	printf("\n=== Starting Execution ===\n");
	printf("Executing limited instruction loop (like m68k_execute)...\n\n");

	// Verify ROM is readable at the expected location
	printf("Memory layout verification:\n");
	printf("  MEMBaseDiff = 0x%lx\n", (unsigned long)MEMBaseDiff);
	printf("  RAMBaseHost = 0x%lx\n", (unsigned long)RAMBaseHost);
	printf("  ROMBaseHost = 0x%lx\n", (unsigned long)ROMBaseHost);
	printf("  RAMBaseMac = 0x%08x\n", RAMBaseMac);
	printf("  ROMBaseMac = 0x%08x\n", ROMBaseMac);
	printf("\n");

	// Check ROM bytes at offset 0x2a
	printf("ROM verification at offset 0x2a:\n");
	uint8_t *rom_at_2a = ROMBaseHost + 0x2a;
	printf("  Bytes at ROMBaseHost+0x2a: %02x %02x %02x %02x\n",
	       rom_at_2a[0], rom_at_2a[1], rom_at_2a[2], rom_at_2a[3]);
	printf("  Expected: 4e fa 00 60 (JMP instruction)\n");
	printf("\n");
	fflush(stdout);

	extern void m68k_do_execute(void);  // From UAE CPU
	extern bool quit_program;           // From UAE CPU

	int instruction_count = 0;
	int max_instructions = 1000;  // Limit for testing

	// Before starting, let's manually check what opcode would be fetched
	printf("Manual opcode fetch check:\n");
	uint16_t *pc_as_u16 = (uint16_t *)regs.pc_p;
	uint16_t raw_bytes = *pc_as_u16;
	printf("  Raw bytes at regs.pc_p (little-endian read): 0x%04x\n", raw_bytes);

	// Try using UAE's do_get_mem_word
	extern uae_u32 do_get_mem_word(uae_u16 *a);
	uint32_t opcode_via_uae = do_get_mem_word((uae_u16 *)regs.pc_p);
	printf("  Opcode via do_get_mem_word: 0x%04x\n", opcode_via_uae);

	// Check cpufunctbl
	extern cpuop_func *cpufunctbl[];
	printf("  cpufunctbl[0x%04x] = %p\n", opcode_via_uae, (void *)cpufunctbl[opcode_via_uae]);
	printf("  cpufunctbl[0x2100] = %p\n", (void *)cpufunctbl[0x2100]);

	printf("\n");
	fflush(stdout);

	quit_program = false;
	for (int i = 0; i < max_instructions; i++) {
		// Show progress
		if (i % 100 == 0) {
			printf("[%5d] PC=%08x A7=%08x SR=%04x\n",
			       i, uae_get_pc(), uae_get_areg(7), uae_get_sr());
			fflush(stdout);
		}

		// Execute one iteration (like m68k_execute does)
		m68k_do_execute();

		instruction_count++;

		if (quit_program) {
			printf("\nquit_program was set, stopping execution\n");
			break;
		}
	}

	printf("\n\nTotal iterations executed: %d\n", instruction_count);

	// Clean up
	printf("\n=== Shutting Down ===\n");
	ExitAll();
	PrefsExit();

	munmap(RAMBaseHost, RAMSize + 0x100000);

	printf("\nBoot test completed successfully!\n");
	return 0;
}
