/**
 * Unicorn CPU Validation Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unicorn_validation.h"
#include "unicorn_wrapper.h"
#include "uae_wrapper.h"
#include "sysdeps.h"
#include "cpu_emulation.h"

// External memory pointers from BasiliskII
extern uint32 RAMBaseMac;
extern uint8 *RAMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMBaseMac;
extern uint8 *ROMBaseHost;
extern uint32 ROMSize;

// Validation state
static struct {
    UnicornCPU *unicorn;
    bool enabled;
    bool initialized;
    FILE *log_file;

    uint64_t instruction_count;
    uint64_t divergence_count;
    uint64_t emulop_count;

    // Last known good state
    uint32_t last_good_pc;
} validation_state = {0};

/* Initialize validation */
bool unicorn_validation_init(void) {
    if (validation_state.initialized) {
        fprintf(stderr, "Unicorn validation already initialized\n");
        return false;
    }

    printf("\n=== Initializing Unicorn Validation ===\n");

    // Create Unicorn CPU with 68040 model
    #define UC_CPU_M68K_M68040 3
    validation_state.unicorn = unicorn_create_with_model(UCPU_ARCH_M68K, UC_CPU_M68K_M68040);
    if (!validation_state.unicorn) {
        fprintf(stderr, "Failed to create Unicorn CPU\n");
        return false;
    }
    printf("✓ Unicorn CPU created (68040)\n");

    // Map RAM
    if (!unicorn_map_ram(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize)) {
        fprintf(stderr, "Failed to map RAM to Unicorn\n");
        unicorn_destroy(validation_state.unicorn);
        return false;
    }
    printf("✓ RAM mapped (0x%08X, %u MB)\n", RAMBaseMac, RAMSize / (1024*1024));

    // Map ROM (use the patched ROM from UAE)
    if (!unicorn_map_rom(validation_state.unicorn, ROMBaseMac, ROMBaseHost, ROMSize)) {
        fprintf(stderr, "Failed to map ROM to Unicorn\n");
        unicorn_destroy(validation_state.unicorn);
        return false;
    }
    printf("✓ ROM mapped (0x%08X, %u KB)\n", ROMBaseMac, ROMSize / 1024);

    // NOTE: Don't sync CPU state here - UAE CPU isn't initialized yet (PC is NULL)
    // State will be synced on first instruction execution in unicorn_validation_step()
    printf("✓ Unicorn initialized (state sync deferred until first instruction)\n");

    // Open log file
    validation_state.log_file = fopen("cpu_validation.log", "w");
    if (!validation_state.log_file) {
        fprintf(stderr, "Warning: Could not open validation log file\n");
    } else {
        fprintf(validation_state.log_file, "=== BasiliskII Dual-CPU Validation Log ===\n");
        fprintf(validation_state.log_file, "UAE vs Unicorn instruction-by-instruction comparison\n\n");
        fflush(validation_state.log_file);
        printf("✓ Log file opened: cpu_validation.log\n");
    }

    validation_state.initialized = true;
    validation_state.enabled = true;
    validation_state.instruction_count = 0;
    validation_state.divergence_count = 0;
    validation_state.emulop_count = 0;
    validation_state.last_good_pc = uae_get_pc();

    printf("=== Unicorn Validation Initialized ===\n\n");
    return true;
}

/* Shutdown validation */
void unicorn_validation_shutdown(void) {
    if (!validation_state.initialized) {
        return;
    }

    printf("\n=== Unicorn Validation Statistics ===\n");
    printf("Instructions executed: %lu\n", validation_state.instruction_count);
    printf("EMUL_OP instructions:  %lu\n", validation_state.emulop_count);
    printf("Divergences detected:  %lu\n", validation_state.divergence_count);

    if (validation_state.divergence_count == 0) {
        printf("✅ PERFECT! Zero divergences detected!\n");
    } else {
        double divergence_rate = (double)validation_state.divergence_count / validation_state.instruction_count * 100.0;
        printf("Divergence rate: %.4f%%\n", divergence_rate);
    }

    if (validation_state.log_file) {
        fprintf(validation_state.log_file, "\n=== Final Statistics ===\n");
        fprintf(validation_state.log_file, "Instructions: %lu\n", validation_state.instruction_count);
        fprintf(validation_state.log_file, "EMUL_OPs: %lu\n", validation_state.emulop_count);
        fprintf(validation_state.log_file, "Divergences: %lu\n", validation_state.divergence_count);
        fclose(validation_state.log_file);
        validation_state.log_file = NULL;
    }

    if (validation_state.unicorn) {
        unicorn_destroy(validation_state.unicorn);
        validation_state.unicorn = NULL;
    }

    validation_state.initialized = false;
    printf("=== Unicorn Validation Shutdown ===\n");
}

/* Helper: Read a word from memory (big-endian) */
static uint16_t read_word_be(uint32_t addr) {
    if (addr >= RAMBaseMac && addr < RAMBaseMac + RAMSize) {
        uint8_t *ptr = RAMBaseHost + (addr - RAMBaseMac);
        return (ptr[0] << 8) | ptr[1];
    } else if (addr >= ROMBaseMac && addr < ROMBaseMac + ROMSize) {
        uint8_t *ptr = ROMBaseHost + (addr - ROMBaseMac);
        return (ptr[0] << 8) | ptr[1];
    }
    return 0;
}

/* Validate one instruction */
bool unicorn_validation_step(void) {
    if (!validation_state.initialized || !validation_state.enabled) {
        return true;  // Validation disabled, no divergence
    }

    // Sync state on first instruction (UAE CPU is initialized after reset)
    if (validation_state.instruction_count == 0) {
        // IMPORTANT: Set PC and SR first, THEN registers
        // Setting PC clears A7 in Unicorn (bug or feature?), so A7 must be set after PC
        unicorn_set_pc(validation_state.unicorn, uae_get_pc());
        unicorn_set_sr(validation_state.unicorn, uae_get_sr());

        for (int i = 0; i < 8; i++) {
            unicorn_set_dreg(validation_state.unicorn, i, uae_get_dreg(i));
            unicorn_set_areg(validation_state.unicorn, i, uae_get_areg(i));
        }
    }

    validation_state.instruction_count++;

    // Get current PC
    uint32_t pc = uae_get_pc();

    // Check if this is an EMUL_OP instruction (0x71xx)
    uint16_t opcode = read_word_be(pc);
    if ((opcode & 0xFF00) == 0x7100) {
        validation_state.emulop_count++;

        // Execute EMUL_OP on UAE only
        uae_cpu_execute_one();

        // Sync entire state from UAE to Unicorn (EMUL_OP can modify anything)
        for (int i = 0; i < 8; i++) {
            unicorn_set_dreg(validation_state.unicorn, i, uae_get_dreg(i));
            unicorn_set_areg(validation_state.unicorn, i, uae_get_areg(i));
        }
        unicorn_set_pc(validation_state.unicorn, uae_get_pc());
        unicorn_set_sr(validation_state.unicorn, uae_get_sr());

        // Sync all RAM (EMUL_OP can write anywhere)
        unicorn_mem_write(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize);

        validation_state.last_good_pc = uae_get_pc();
        return true;  // EMUL_OP handled, no divergence to report
    }

    // Normal instruction - capture state before
    uint32_t uae_pc_before = pc;
    uint32_t uae_dregs_before[8], uae_aregs_before[8];
    uint16_t uae_sr_before = uae_get_sr();

    for (int i = 0; i < 8; i++) {
        uae_dregs_before[i] = uae_get_dreg(i);
        uae_aregs_before[i] = uae_get_areg(i);
    }

    // Execute on UAE
    uae_cpu_execute_one();

    // Capture state after
    uint32_t uae_pc_after = uae_get_pc();
    uint32_t uae_dregs_after[8], uae_aregs_after[8];
    uint16_t uae_sr_after = uae_get_sr();

    for (int i = 0; i < 8; i++) {
        uae_dregs_after[i] = uae_get_dreg(i);
        uae_aregs_after[i] = uae_get_areg(i);
    }

    // Execute on Unicorn
    if (!unicorn_execute_one(validation_state.unicorn)) {
        // Unicorn execution failed
        fprintf(stderr, "\n❌ Unicorn execution failed at PC=0x%08X\n", uae_pc_before);
        fprintf(stderr, "Error: %s\n", unicorn_get_error(validation_state.unicorn));

        if (validation_state.log_file) {
            fprintf(validation_state.log_file, "\n[%lu] UNICORN EXECUTION FAILED\n", validation_state.instruction_count);
            fprintf(validation_state.log_file, "PC: 0x%08X, Opcode: 0x%04X\n", uae_pc_before, opcode);
            fprintf(validation_state.log_file, "Error: %s\n", unicorn_get_error(validation_state.unicorn));
            fflush(validation_state.log_file);
        }

        validation_state.divergence_count++;
        return false;
    }

    // Compare states
    uint32_t uc_pc = unicorn_get_pc(validation_state.unicorn);
    uint16_t uc_sr = unicorn_get_sr(validation_state.unicorn);
    bool divergence = false;

    // Check PC
    if (uc_pc != uae_pc_after) {
        divergence = true;
        if (validation_state.log_file) {
            fprintf(validation_state.log_file, "\n[%lu] PC DIVERGENCE at 0x%08X (opcode 0x%04X)\n",
                    validation_state.instruction_count, uae_pc_before, opcode);
            fprintf(validation_state.log_file, "UAE PC: 0x%08X → 0x%08X\n", uae_pc_before, uae_pc_after);
            fprintf(validation_state.log_file, "UC  PC: 0x%08X → 0x%08X\n", uae_pc_before, uc_pc);
        }
    }

    // Check SR
    if (uc_sr != uae_sr_after) {
        divergence = true;
        if (validation_state.log_file) {
            fprintf(validation_state.log_file, "\n[%lu] SR DIVERGENCE at 0x%08X (opcode 0x%04X)\n",
                    validation_state.instruction_count, uae_pc_before, opcode);
            fprintf(validation_state.log_file, "UAE SR: 0x%04X → 0x%04X\n", uae_sr_before, uae_sr_after);
            fprintf(validation_state.log_file, "UC  SR: 0x%04X → 0x%04X\n", uae_sr_before, uc_sr);
        }
    }

    // Check data registers
    for (int i = 0; i < 8; i++) {
        uint32_t uc_dreg = unicorn_get_dreg(validation_state.unicorn, i);
        if (uc_dreg != uae_dregs_after[i]) {
            divergence = true;
            if (validation_state.log_file) {
                fprintf(validation_state.log_file, "\n[%lu] D%d DIVERGENCE at 0x%08X (opcode 0x%04X)\n",
                        validation_state.instruction_count, i, uae_pc_before, opcode);
                fprintf(validation_state.log_file, "UAE D%d: 0x%08X → 0x%08X\n", i, uae_dregs_before[i], uae_dregs_after[i]);
                fprintf(validation_state.log_file, "UC  D%d: 0x%08X → 0x%08X\n", i, uae_dregs_before[i], uc_dreg);
            }
        }
    }

    // Check address registers
    for (int i = 0; i < 8; i++) {
        uint32_t uc_areg = unicorn_get_areg(validation_state.unicorn, i);
        if (uc_areg != uae_aregs_after[i]) {
            divergence = true;
            if (validation_state.log_file) {
                fprintf(validation_state.log_file, "\n[%lu] A%d DIVERGENCE at 0x%08X (opcode 0x%04X)\n",
                        validation_state.instruction_count, i, uae_pc_before, opcode);
                fprintf(validation_state.log_file, "UAE A%d: 0x%08X → 0x%08X\n", i, uae_aregs_before[i], uae_aregs_after[i]);
                fprintf(validation_state.log_file, "UC  A%d: 0x%08X → 0x%08X\n", i, uae_aregs_before[i], uc_areg);
            }
        }
    }

    if (divergence) {
        validation_state.divergence_count++;
        if (validation_state.log_file) {
            fflush(validation_state.log_file);
        }

        // Print to console every 10th divergence
        if (validation_state.divergence_count % 10 == 0) {
            printf("⚠️  Divergence #%lu at PC=0x%08X (total: %lu instructions)\n",
                   validation_state.divergence_count, uae_pc_before, validation_state.instruction_count);
        }

        return false;
    }

    validation_state.last_good_pc = uae_pc_after;

    // Sync RAM from UAE to Unicorn periodically (every 100 instructions)
    // This is slow but ensures Unicorn sees memory writes
    if (validation_state.instruction_count % 100 == 0) {
        unicorn_mem_write(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize);
    }

    return true;
}

/* Check if enabled */
bool unicorn_validation_enabled(void) {
    return validation_state.initialized && validation_state.enabled;
}

/* Enable/disable */
void unicorn_validation_set_enabled(bool enabled) {
    validation_state.enabled = enabled;
}

/* Get statistics */
void unicorn_validation_get_stats(uint64_t *instructions, uint64_t *divergences) {
    if (instructions) *instructions = validation_state.instruction_count;
    if (divergences) *divergences = validation_state.divergence_count;
}
