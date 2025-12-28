/*
 *  test_boot_dualcpu.cpp - Dual-CPU validation boot test
 *
 *  Executes ROM code with both UAE and Unicorn CPUs in lockstep,
 *  validating that both produce identical register states.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

extern "C" {
#include "dualcpu.h"
}

#define RAM_SIZE (32 * 1024 * 1024)  // 32MB
#define RAM_BASE 0x00000000
#define ROM_BASE 0x02000000  // Mac ROM location (right after RAM)

int main(int argc, char **argv)
{
	printf("=== macemu-next Dual-CPU Boot Test ===\n\n");

	// Check for ROM file argument
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <rom-file>\n", argv[0]);
		return 1;
	}
	const char *rom_path = argv[1];

	// Load ROM file first (to get size)
	printf("Loading ROM from %s...\n", rom_path);
	int rom_fd = open(rom_path, O_RDONLY);
	if (rom_fd < 0) {
		fprintf(stderr, "Failed to open ROM file: %s\n", rom_path);
		return 1;
	}

	off_t rom_size = lseek(rom_fd, 0, SEEK_END);
	printf("ROM size: %ld bytes (%ld KB)\n", rom_size, rom_size / 1024);

	if (rom_size != 64*1024 && rom_size != 128*1024 && rom_size != 256*1024 &&
	    rom_size != 512*1024 && rom_size != 1024*1024) {
		fprintf(stderr, "Invalid ROM size (must be 64/128/256/512/1024 KB)\n");
		close(rom_fd);
		return 1;
	}

	// Read ROM into buffer
	uint8_t *rom_data = (uint8_t *)malloc(rom_size);
	if (!rom_data) {
		fprintf(stderr, "Failed to allocate ROM buffer\n");
		close(rom_fd);
		return 1;
	}

	lseek(rom_fd, 0, SEEK_SET);
	if (read(rom_fd, rom_data, rom_size) != rom_size) {
		fprintf(stderr, "Failed to read ROM file\n");
		free(rom_data);
		close(rom_fd);
		return 1;
	}
	close(rom_fd);

	printf("ROM loaded successfully\n");

	// Create dual-CPU harness
	printf("\n=== Creating Dual-CPU Harness ===\n");
	DualCPU *dcpu = dualcpu_create();
	if (!dcpu) {
		fprintf(stderr, "Failed to create dual-CPU harness\n");
		free(rom_data);
		return 1;
	}
	printf("✓ Harness created\n");

	// Map RAM
	printf("Mapping RAM (%d MB at 0x%08X)...\n", RAM_SIZE / (1024 * 1024), RAM_BASE);
	if (!dualcpu_map_ram(dcpu, RAM_BASE, RAM_SIZE)) {
		fprintf(stderr, "Failed to map RAM\n");
		dualcpu_destroy(dcpu);
		free(rom_data);
		return 1;
	}
	printf("✓ RAM mapped for both CPUs\n");

	// Map ROM
	printf("Mapping ROM (%ld KB at 0x%08X)...\n", rom_size / 1024, ROM_BASE);
	if (!dualcpu_map_rom(dcpu, ROM_BASE, rom_data, (uint32_t)rom_size)) {
		fprintf(stderr, "Failed to map ROM\n");
		dualcpu_destroy(dcpu);
		free(rom_data);
		return 1;
	}
	printf("✓ ROM mapped for both CPUs\n");

	// Map dummy hardware region (0x50000000-0x60000000) to catch hardware accesses
	// Mac ROM accesses VIA, SCSI, and other hardware in this range
	#define HW_BASE 0x50000000
	#define HW_SIZE (16 * 1024 * 1024)  // 16MB should cover all hardware
	printf("Mapping dummy hardware region (16 MB at 0x%08X)...\n", HW_BASE);
	if (!dualcpu_map_memory(dcpu, HW_BASE, HW_SIZE)) {
		fprintf(stderr, "Failed to map hardware region: %s\n", dualcpu_get_error(dcpu));
		dualcpu_destroy(dcpu);
		free(rom_data);
		return 1;
	}
	printf("✓ Dummy hardware region mapped\n");

	// Set initial CPU state (like Mac ROM boot)
	// According to 68k spec, reset vector is at ROM+0 (SP) and ROM+4 (PC)
	// But BasiliskII uses ROM+0x2a as entry point after some setup
	printf("\n=== Setting Initial CPU State ===\n");

	// Read reset vector from ROM (big-endian)
	uint32_t initial_sp = (rom_data[0] << 24) | (rom_data[1] << 16) |
	                      (rom_data[2] << 8) | rom_data[3];
	uint32_t initial_pc = (rom_data[4] << 24) | (rom_data[5] << 16) |
	                      (rom_data[6] << 8) | rom_data[7];

	printf("Reset vector from ROM:\n");
	printf("  Initial SP: 0x%08X\n", initial_sp);
	printf("  Initial PC: 0x%08X\n", initial_pc);

	// But we'll use BasiliskII's approach: PC at ROM+0x2a, SP at 0x2000
	uint32_t boot_pc = ROM_BASE + 0x2a;
	uint32_t boot_sp = 0x00002000;

	printf("\nBasiliskII boot state:\n");
	printf("  PC: 0x%08X (ROM+0x2a)\n", boot_pc);
	printf("  SP: 0x%08X\n", boot_sp);

	// Check what instruction is at ROM+0x2a
	uint8_t *rom_at_2a = rom_data + 0x2a;
	printf("  Instruction at ROM+0x2a: %02X %02X %02X %02X\n",
	       rom_at_2a[0], rom_at_2a[1], rom_at_2a[2], rom_at_2a[3]);

	// Set both CPUs to this state
	dualcpu_set_pc(dcpu, boot_pc);
	dualcpu_set_areg(dcpu, 7, boot_sp);  // A7 = Stack pointer
	dualcpu_set_sr(dcpu, 0x2700);  // Supervisor mode, interrupts disabled

	printf("✓ Both CPUs initialized\n");

	// Execute instructions with dual-CPU validation
	printf("\n=== Starting Dual-CPU Execution ===\n");
	printf("Executing ROM code with lockstep validation...\n\n");

	int max_instructions = 1000;
	int instruction_count = 0;
	bool diverged = false;

	for (int i = 0; i < max_instructions; i++) {
		// Show PC and SR before each instruction (for first 10 instructions)
		if (i < 10) {
			CPUStateSnapshot uae_before, unicorn_before;
			dualcpu_get_divergence(dcpu, &uae_before, &unicorn_before);

			// Read opcode from ROM
			uint32_t pc_offset = uae_before.pc - ROM_BASE;
			uint16_t opcode = 0;
			if (pc_offset < rom_size - 1) {
				opcode = (rom_data[pc_offset] << 8) | rom_data[pc_offset + 1];
			}

			printf("[%d] BEFORE: PC=0x%08X opcode=0x%04X  UAE_SR=0x%04X  UC_SR=0x%04X\n",
			       i, uae_before.pc, opcode, uae_before.sr, unicorn_before.sr);
			fflush(stdout);
		}

		// Show progress every 100 instructions
		if (i % 100 == 0 && i >= 10) {
			DualCPUStats stats;
			dualcpu_get_stats(dcpu, &stats);
			printf("[%5d] Instructions: %lu, Divergences: %lu\n",
			       i, stats.instructions_executed, stats.divergences);
			fflush(stdout);
		}

		// Execute one instruction on both CPUs and compare
		if (!dualcpu_execute_one(dcpu)) {
			printf("\n❌ CPU DIVERGENCE DETECTED!\n");
			printf("Error: %s\n", dualcpu_get_error(dcpu));

			// Get detailed divergence info
			CPUStateSnapshot uae_state, unicorn_state;
			if (dualcpu_get_divergence(dcpu, &uae_state, &unicorn_state)) {
				printf("\nUAE State:\n");
				printf("  PC: 0x%08X\n", uae_state.pc);
				printf("  SR: 0x%04X\n", uae_state.sr);
				printf("  D0-D7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
				       uae_state.dregs[0], uae_state.dregs[1], uae_state.dregs[2], uae_state.dregs[3],
				       uae_state.dregs[4], uae_state.dregs[5], uae_state.dregs[6], uae_state.dregs[7]);
				printf("  A0-A7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
				       uae_state.aregs[0], uae_state.aregs[1], uae_state.aregs[2], uae_state.aregs[3],
				       uae_state.aregs[4], uae_state.aregs[5], uae_state.aregs[6], uae_state.aregs[7]);

				printf("\nUnicorn State:\n");
				printf("  PC: 0x%08X\n", unicorn_state.pc);
				printf("  SR: 0x%04X\n", unicorn_state.sr);
				printf("  D0-D7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
				       unicorn_state.dregs[0], unicorn_state.dregs[1], unicorn_state.dregs[2], unicorn_state.dregs[3],
				       unicorn_state.dregs[4], unicorn_state.dregs[5], unicorn_state.dregs[6], unicorn_state.dregs[7]);
				printf("  A0-A7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
				       unicorn_state.aregs[0], unicorn_state.aregs[1], unicorn_state.aregs[2], unicorn_state.aregs[3],
				       unicorn_state.aregs[4], unicorn_state.aregs[5], unicorn_state.aregs[6], unicorn_state.aregs[7]);
			}

			diverged = true;
			break;
		}

		instruction_count++;
	}

	// Final statistics
	printf("\n=== Execution Complete ===\n");
	DualCPUStats stats;
	dualcpu_get_stats(dcpu, &stats);
	printf("Total instructions executed: %lu\n", stats.instructions_executed);
	printf("Total divergences: %lu\n", stats.divergences);
	printf("Memory operations: %lu\n", stats.memory_ops);
	printf("Exceptions: %lu\n", stats.exceptions);

	if (diverged) {
		printf("\n⚠️  Test FAILED - CPUs diverged\n");
	} else if (instruction_count >= max_instructions) {
		printf("\n✅ Test PASSED - %d instructions executed without divergence!\n", instruction_count);
	} else {
		printf("\n✅ Test completed\n");
	}

	// Clean up
	dualcpu_destroy(dcpu);
	free(rom_data);

	return diverged ? 1 : 0;
}
