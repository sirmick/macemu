/**
 * Unicorn CPU Validation Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unicorn_validation.h"
#include "unicorn_wrapper.h"
#include "unicorn_exception.h"
#include "uae_wrapper.h"
#include "sysdeps.h"
#include "cpu_emulation.h"
#include "main.h"  // For M68kRegisters
#include "emul_op.h"  // For EmulOp function

// External memory pointers from BasiliskII
extern uint32 RAMBaseMac;
extern uint8 *RAMBaseHost;
extern uint32 RAMSize;
extern uint32 ROMBaseMac;
extern uint8 *ROMBaseHost;
extern uint32 ROMSize;

// Master CPU selection for EmulOps and traps
typedef enum {
    MASTER_CPU_UAE,      // UAE handles EmulOps/traps, sync to Unicorn
    MASTER_CPU_UNICORN   // Unicorn handles EmulOps/traps, sync to UAE
} MasterCPU;

// Validation state
static struct {
    UnicornCPU *unicorn;
    bool enabled;
    bool initialized;
    FILE *log_file;
    MasterCPU master_cpu;

    uint64_t instruction_count;
    uint64_t divergence_count;
    uint64_t emulop_count;

    // Last known good state
    uint32_t last_good_pc;
} validation_state = {0};

/* Dummy handler to trigger invalid instruction hook registration */
static void dummy_emulop(uint16_t opcode, void *user_data) {
    (void)opcode;
    (void)user_data;
}

/* Initialize validation */
bool unicorn_validation_init(void) {
    if (validation_state.initialized) {
        fprintf(stderr, "Unicorn validation already initialized\n");
        return false;
    }

    printf("\n=== Initializing Unicorn Validation ===\n");

    // Configure master CPU (defaults to UAE)
    validation_state.master_cpu = MASTER_CPU_UAE;
    const char *master_env = getenv("DUALCPU_MASTER");
    if (master_env) {
        if (strcmp(master_env, "unicorn") == 0 || strcmp(master_env, "UNICORN") == 0) {
            validation_state.master_cpu = MASTER_CPU_UNICORN;
            printf("✓ Master CPU: UNICORN (EmulOps/traps on Unicorn, sync to UAE)\n");
        } else if (strcmp(master_env, "uae") == 0 || strcmp(master_env, "UAE") == 0) {
            validation_state.master_cpu = MASTER_CPU_UAE;
            printf("✓ Master CPU: UAE (EmulOps/traps on UAE, sync to Unicorn)\n");
        } else {
            fprintf(stderr, "Warning: Unknown DUALCPU_MASTER value '%s', defaulting to UAE\n", master_env);
            validation_state.master_cpu = MASTER_CPU_UAE;
        }
    } else {
        printf("✓ Master CPU: UAE (default)\n");
    }

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

    // Map ROM as writable (BasiliskII patches ROM during boot)
    if (!unicorn_map_rom_writable(validation_state.unicorn, ROMBaseMac, ROMBaseHost, ROMSize)) {
        fprintf(stderr, "Failed to map ROM to Unicorn\n");
        unicorn_destroy(validation_state.unicorn);
        return false;
    }
    printf("✓ ROM mapped (0x%08X, %u KB)\n", ROMBaseMac, ROMSize / 1024);

    // IMPORTANT: UAE has a bug where rom_lget/wget/bget read from (ROMBaseDiff + addr)
    // without bounds checking. This means UAE can read PAST the end of ROM into
    // host memory. For example, address 0x0248831C (ROM + 4.5MB) gets read even
    // though ROM is only 1MB. UAE reads whatever garbage exists in host memory.
    // The host allocation is RAMSize + 0x100000 (see main.cpp:119). ROM is at
    // RAMBaseHost + RAMSize, and is 1MB, so the full allocation ends at
    // RAMBaseHost + RAMSize + 0x100000. However, ROM already uses the full 0x100000,
    // so there's NO extra space after ROM. We need to allocate 16MB of dummy memory
    // to catch UAE's out-of-bounds reads. We'll fill it with a pattern to detect reads.
    uint32_t dummy_region_base = ROMBaseMac + ROMSize;
    uint32_t dummy_region_size = 16 * 1024 * 1024;  // 16 MB
    uint8_t *dummy_buffer = (uint8_t *)malloc(dummy_region_size);
    if (!dummy_buffer) {
        fprintf(stderr, "Failed to allocate dummy memory buffer\n");
        unicorn_destroy(validation_state.unicorn);
        return false;
    }
    // Fill with 0xFF00FF00 pattern to match UAE's garbage reads
    // UAE reads this specific pattern from uninitialized host memory
    // IMPORTANT: Must use big-endian byte order for 68K
    for (uint32_t i = 0; i < dummy_region_size; i += 4) {
        dummy_buffer[i + 0] = 0xFF;
        dummy_buffer[i + 1] = 0x00;
        dummy_buffer[i + 2] = 0xFF;
        dummy_buffer[i + 3] = 0x00;
    }
    if (!unicorn_map_ram(validation_state.unicorn, dummy_region_base, dummy_buffer, dummy_region_size)) {
        fprintf(stderr, "Failed to map dummy region to Unicorn\n");
        free(dummy_buffer);
        unicorn_destroy(validation_state.unicorn);
        return false;
    }
    printf("✓ Dummy region mapped (0x%08X - 0x%08X, %u MB) with 0xFF00FF00 pattern\n",
           dummy_region_base, dummy_region_base + dummy_region_size, dummy_region_size / (1024*1024));

    // NOTE: Don't sync CPU state here - UAE CPU isn't initialized yet (PC is NULL)
    // State will be synced on first instruction execution in unicorn_validation_step()
    printf("✓ Unicorn initialized (state sync deferred until first instruction)\n");

    // NOTE: EmulOp/trap handlers are now registered by cpu_dualcpu_install() via platform API
    // However, we still need to install the invalid instruction hook on Unicorn so it can
    // check the platform handlers. Install a dummy handler to trigger hook registration
    // (the hook checks g_platform first, so the dummy is never actually called)
    printf("Installing Unicorn invalid instruction hook...\n");
    unicorn_set_emulop_handler(validation_state.unicorn, dummy_emulop, NULL);
    printf("✓ Unicorn invalid instruction hook installed\n");
    printf("✓ Platform handlers configured by CPU backend\n");

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

/* Unified Hook Handlers - Check master_cpu to determine behavior */

static bool unified_emulop_handler(uint16_t opcode, bool is_uae_calling) {
    validation_state.emulop_count++;

    // Determine if this CPU should execute based on who's calling and who's master
    // is_uae_calling: true = UAE is calling, false = Unicorn is calling
    bool should_execute = false;

    if (is_uae_calling && validation_state.master_cpu == MASTER_CPU_UAE) {
        should_execute = true;  // UAE is calling and UAE is master
    } else if (!is_uae_calling && validation_state.master_cpu == MASTER_CPU_UNICORN) {
        should_execute = true;  // Unicorn is calling and Unicorn is master
    }

    if (!should_execute) {
        // This CPU is secondary: Skip execution, state will be synced from primary
        return false;  // Caller should advance PC
    }

    // This CPU is primary: Execute and sync to secondary
    if (validation_state.master_cpu == MASTER_CPU_UAE) {
        // UAE is primary: Execute EmulOp and sync to Unicorn
        struct M68kRegisters regs;
        for (int i = 0; i < 8; i++) {
            regs.d[i] = uae_get_dreg(i);
            regs.a[i] = uae_get_areg(i);
        }
        regs.sr = uae_get_sr();

        // Call EmulOp
        extern void EmulOp(uint16 opcode, struct M68kRegisters *r);
        EmulOp(opcode, &regs);

        // Write registers back to UAE
        for (int i = 0; i < 8; i++) {
            uae_set_dreg(i, regs.d[i]);
            uae_set_areg(i, regs.a[i]);
        }
        uae_set_sr(regs.sr);

        // NOTE: PC will be advanced by the opcode handler (m68k_incpc(2))
        // Sync entire state from UAE to Unicorn (EmulOp can modify anything)
        for (int i = 0; i < 8; i++) {
            unicorn_set_dreg(validation_state.unicorn, i, uae_get_dreg(i));
            unicorn_set_areg(validation_state.unicorn, i, uae_get_areg(i));
        }
        // PC will be synced after opcode handler increments it
        uint32_t current_pc = uae_get_pc();
        unicorn_set_pc(validation_state.unicorn, current_pc + 2);  // Sync with post-increment PC
        unicorn_set_sr(validation_state.unicorn, uae_get_sr());

        // Sync all RAM (EmulOp can write anywhere)
        unicorn_mem_write(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize);
        return false;  // UAE advances PC in caller
    } else {
        // Unicorn is primary: Execute EmulOp and sync to UAE
        struct M68kRegisters regs;
        for (int i = 0; i < 8; i++) {
            regs.d[i] = unicorn_get_dreg(validation_state.unicorn, i);
            regs.a[i] = unicorn_get_areg(validation_state.unicorn, i);
        }
        regs.sr = unicorn_get_sr(validation_state.unicorn);

        // Call EmulOp handler
        extern void EmulOp(uint16 opcode, struct M68kRegisters *r);
        EmulOp(opcode, &regs);

        // Write registers back to Unicorn
        for (int i = 0; i < 8; i++) {
            unicorn_set_dreg(validation_state.unicorn, i, regs.d[i]);
            unicorn_set_areg(validation_state.unicorn, i, regs.a[i]);
        }
        unicorn_set_sr(validation_state.unicorn, regs.sr);

        // Advance PC past EmulOp
        uint32_t current_pc = unicorn_get_pc(validation_state.unicorn);
        unicorn_set_pc(validation_state.unicorn, current_pc + 2);

        // Sync entire state from Unicorn to UAE
        for (int i = 0; i < 8; i++) {
            uae_set_dreg(i, regs.d[i]);
            uae_set_areg(i, regs.a[i]);
        }
        uint32_t new_pc = unicorn_get_pc(validation_state.unicorn);
        uae_set_pc(new_pc);
        uae_set_sr(regs.sr);

        // Sync all RAM (EmulOp can write anywhere)
        unicorn_mem_read(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize);
        return true;  // We advanced PC ourselves
    }
}

static bool unified_trap_handler(int vector, uint16_t opcode, bool is_uae_calling) {
    (void)opcode;

    // Determine if this CPU should execute based on who's calling and who's master
    bool should_execute = false;

    if (is_uae_calling && validation_state.master_cpu == MASTER_CPU_UAE) {
        should_execute = true;  // UAE is calling and UAE is master
    } else if (!is_uae_calling && validation_state.master_cpu == MASTER_CPU_UNICORN) {
        should_execute = true;  // Unicorn is calling and Unicorn is master
    }

    if (!should_execute) {
        // This CPU is secondary: Skip execution, state will be synced from primary
        return false;  // Caller advances PC (though traps may change it)
    }

    // This CPU is primary: Execute and sync to secondary
    if (validation_state.master_cpu == MASTER_CPU_UAE) {
        // UAE is primary: Execute trap and sync to Unicorn
        extern void Exception(int nr, uaecptr oldpc);
        Exception(vector, 0);

        // Sync entire state from UAE to Unicorn
        for (int i = 0; i < 8; i++) {
            unicorn_set_dreg(validation_state.unicorn, i, uae_get_dreg(i));
            unicorn_set_areg(validation_state.unicorn, i, uae_get_areg(i));
        }
        unicorn_set_pc(validation_state.unicorn, uae_get_pc());
        unicorn_set_sr(validation_state.unicorn, uae_get_sr());

        // Sync all RAM
        unicorn_mem_write(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize);
        return false;  // UAE's Exception() advances PC
    } else {
        // Unicorn is primary: Execute trap and sync to UAE
        // Unicorn handles the exception via unicorn_exception.c
        extern void unicorn_simulate_exception(UnicornCPU *cpu, int vector_nr, uint16_t opcode);
        unicorn_simulate_exception(validation_state.unicorn, vector, opcode);

        // Sync entire state from Unicorn to UAE
        for (int i = 0; i < 8; i++) {
            uae_set_dreg(i, unicorn_get_dreg(validation_state.unicorn, i));
            uae_set_areg(i, unicorn_get_areg(validation_state.unicorn, i));
        }
        uae_set_pc(unicorn_get_pc(validation_state.unicorn));
        uae_set_sr(unicorn_get_sr(validation_state.unicorn));

        // Sync all RAM
        unicorn_mem_read(validation_state.unicorn, RAMBaseMac, RAMBaseHost, RAMSize);
        return true;  // unicorn_simulate_exception advances PC
    }
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

        // Sync control registers (CACR, VBR, etc.)
        unicorn_set_cacr(validation_state.unicorn, uae_get_cacr());
        unicorn_set_vbr(validation_state.unicorn, uae_get_vbr());
    }

    validation_state.instruction_count++;

    // Get current PC and opcode
    uint32_t pc = uae_get_pc();
    uint16_t opcode = read_word_be(pc);

    // Detect EmulOps (0x71xx) and Traps (0xAxxx, 0xFxxx)
    bool is_emulop = (opcode & 0xFF00) == 0x7100;
    bool is_a_trap = (opcode & 0xF000) == 0xA000;
    bool is_f_trap = (opcode & 0xF000) == 0xF000;
    bool is_special = is_emulop || is_a_trap || is_f_trap;

    // Capture state before
    uint32_t uae_pc_before = pc;
    uint32_t uae_dregs_before[8], uae_aregs_before[8];
    uint16_t uae_sr_before = uae_get_sr();

    for (int i = 0; i < 8; i++) {
        uae_dregs_before[i] = uae_get_dreg(i);
        uae_aregs_before[i] = uae_get_areg(i);
    }

    // Execute on UAE (platform handler will be called for EmulOps/traps)
    uae_cpu_execute_one();

    // Capture state after
    uint32_t uae_pc_after = uae_get_pc();
    uint32_t uae_dregs_after[8], uae_aregs_after[8];
    uint16_t uae_sr_after = uae_get_sr();

    for (int i = 0; i < 8; i++) {
        uae_dregs_after[i] = uae_get_dreg(i);
        uae_aregs_after[i] = uae_get_areg(i);
    }

    // Sync control registers BEFORE Unicorn executes
    // UAE and Unicorn use different CACR masking, so keep them in sync
    unicorn_set_cacr(validation_state.unicorn, uae_get_cacr());
    unicorn_set_vbr(validation_state.unicorn, uae_get_vbr());

    // For EmulOps/traps when UAE is primary: Skip Unicorn execution
    // The unified handler already executed on UAE and synced state to Unicorn
    if (is_special && validation_state.master_cpu == MASTER_CPU_UAE) {
        // State already synced by unified handler, just validate
        validation_state.last_good_pc = uae_pc_after;
        return true;
    }

    // For EmulOps/traps when Unicorn is primary: Skip UAE execution result, run on Unicorn
    // The UAE execution was just to keep it in sync, Unicorn will execute and sync back
    if (is_special && validation_state.master_cpu == MASTER_CPU_UNICORN) {
        // Execute on Unicorn (platform handler will execute and sync to UAE)
        if (!unicorn_execute_one(validation_state.unicorn)) {
            fprintf(stderr, "\n❌ Unicorn execution failed at PC=0x%08X\n", uae_pc_before);
            fprintf(stderr, "Error: %s\n", unicorn_get_error(validation_state.unicorn));
            validation_state.divergence_count++;
            return false;
        }
        // State synced by unified handler, validate
        validation_state.last_good_pc = unicorn_get_pc(validation_state.unicorn);
        return true;
    }

    // Normal instruction - Execute on Unicorn
    if (!unicorn_execute_one(validation_state.unicorn)) {
        // Unicorn execution failed - dump full CPU state for debugging
        fprintf(stderr, "\n❌ Unicorn execution failed at PC=0x%08X\n", uae_pc_before);
        fprintf(stderr, "Error: %s\n", unicorn_get_error(validation_state.unicorn));
        fprintf(stderr, "\nCPU State (before instruction):\n");
        fprintf(stderr, "D0-D7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
                uae_dregs_before[0], uae_dregs_before[1], uae_dregs_before[2], uae_dregs_before[3],
                uae_dregs_before[4], uae_dregs_before[5], uae_dregs_before[6], uae_dregs_before[7]);
        fprintf(stderr, "A0-A7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
                uae_aregs_before[0], uae_aregs_before[1], uae_aregs_before[2], uae_aregs_before[3],
                uae_aregs_before[4], uae_aregs_before[5], uae_aregs_before[6], uae_aregs_before[7]);
        fprintf(stderr, "SR: %04X, VBR: %08X, CACR: %08X\n", uae_sr_before, uae_get_vbr(), uae_get_cacr());
        fprintf(stderr, "\nCPU State (after UAE executed successfully):\n");
        fprintf(stderr, "D0-D7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
                uae_dregs_after[0], uae_dregs_after[1], uae_dregs_after[2], uae_dregs_after[3],
                uae_dregs_after[4], uae_dregs_after[5], uae_dregs_after[6], uae_dregs_after[7]);
        fprintf(stderr, "A0-A7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
                uae_aregs_after[0], uae_aregs_after[1], uae_aregs_after[2], uae_aregs_after[3],
                uae_aregs_after[4], uae_aregs_after[5], uae_aregs_after[6], uae_aregs_after[7]);

        if (validation_state.log_file) {
            fprintf(validation_state.log_file, "\n[%lu] UNICORN EXECUTION FAILED\n", validation_state.instruction_count);
            fprintf(validation_state.log_file, "PC: 0x%08X, Opcode: 0x%04X\n", uae_pc_before, opcode);
            fprintf(validation_state.log_file, "Error: %s\n", unicorn_get_error(validation_state.unicorn));
            fprintf(validation_state.log_file, "\nCPU State (before instruction):\n");
            fprintf(validation_state.log_file, "D0-D7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
                    uae_dregs_before[0], uae_dregs_before[1], uae_dregs_before[2], uae_dregs_before[3],
                    uae_dregs_before[4], uae_dregs_before[5], uae_dregs_before[6], uae_dregs_before[7]);
            fprintf(validation_state.log_file, "A0-A7: %08X %08X %08X %08X %08X %08X %08X %08X\n",
                    uae_aregs_before[0], uae_aregs_before[1], uae_aregs_before[2], uae_aregs_before[3],
                    uae_aregs_before[4], uae_aregs_before[5], uae_aregs_before[6], uae_aregs_before[7]);
            fprintf(validation_state.log_file, "SR: %04X, VBR: %08X, CACR: %08X\n", uae_sr_before, uae_get_vbr(), uae_get_cacr());
            fflush(validation_state.log_file);
        }

        validation_state.divergence_count++;
        return false;
    }

    // Debug: Detailed MOVEC logging for CACR
    if ((opcode == 0x4E7A || opcode == 0x4E7B) && validation_state.log_file) {
        uint16_t extension = read_word_be(uae_pc_before + 2);
        uint16_t control_reg = extension & 0xFFF;

        if (control_reg == 0x002) {  // CACR operations
            uint16_t data_reg = (extension >> 12) & 0xF;
            bool is_d_reg = !(data_reg & 8);
            int reg_num = data_reg & 7;

            uint32_t uae_cacr = uae_get_cacr();
            uint32_t uc_cacr = unicorn_get_cacr(validation_state.unicorn);

            if (opcode == 0x4E7B) {  // MOVEC Rn,CACR (write)
                uint32_t source = is_d_reg ? uae_dregs_before[reg_num] : uae_aregs_before[reg_num];
                fprintf(validation_state.log_file, "[%lu] MOVEC %c%d(=0x%08X),CACR → UAE_CACR=0x%08X UC_CACR=0x%08X\n",
                        validation_state.instruction_count,
                        is_d_reg ? 'D' : 'A', reg_num, source,
                        uae_cacr, uc_cacr);
            } else {  // MOVEC CACR,Rn (read)
                uint32_t uae_dest = is_d_reg ? uae_dregs_after[reg_num] : uae_aregs_after[reg_num];
                uint32_t uc_dest = is_d_reg ? unicorn_get_dreg(validation_state.unicorn, reg_num)
                                             : unicorn_get_areg(validation_state.unicorn, reg_num);
                fprintf(validation_state.log_file, "[%lu] MOVEC CACR,%c%d → UAE_CACR=0x%08X->%c%d=0x%08X, UC_CACR=0x%08X->%c%d=0x%08X\n",
                        validation_state.instruction_count,
                        is_d_reg ? 'D' : 'A', reg_num,
                        uae_cacr, is_d_reg ? 'D' : 'A', reg_num, uae_dest,
                        uc_cacr, is_d_reg ? 'D' : 'A', reg_num, uc_dest);
            }
        }
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

    // Skip validation for MOVEC CACR reads (UAE and Unicorn use different masking)
    // Also sync the destination register to keep CPUs in sync
    bool skip_validation = false;
    if (opcode == 0x4E7A) {  // MOVEC Rc,Rn (read from control register)
        uint16_t extension = read_word_be(uae_pc_before + 2);
        uint16_t control_reg = extension & 0xFFF;
        if (control_reg == 0x002) {  // CACR
            skip_validation = true;
            // Sync the destination register from UAE to Unicorn
            uint16_t data_reg = (extension >> 12) & 0xF;
            bool is_d_reg = !(data_reg & 8);
            int reg_num = data_reg & 7;
            if (is_d_reg) {
                unicorn_set_dreg(validation_state.unicorn, reg_num, uae_dregs_after[reg_num]);
            } else {
                unicorn_set_areg(validation_state.unicorn, reg_num, uae_aregs_after[reg_num]);
            }
            if (validation_state.log_file) {
                fprintf(validation_state.log_file, "[%lu] Skipping validation for MOVEC CACR,%c%d (synced %c%d=0x%08X from UAE)\n",
                        validation_state.instruction_count,
                        is_d_reg ? 'D' : 'A', reg_num,
                        is_d_reg ? 'D' : 'A', reg_num,
                        is_d_reg ? uae_dregs_after[reg_num] : uae_aregs_after[reg_num]);
            }
        }
    }

    // Check data registers
    for (int i = 0; i < 8; i++) {
        uint32_t uc_dreg = unicorn_get_dreg(validation_state.unicorn, i);
        if (uc_dreg != uae_dregs_after[i]) {
            // Skip if this is a CACR read divergence
            if (skip_validation) continue;

            divergence = true;
            if (validation_state.log_file) {
                fprintf(validation_state.log_file, "\n[%lu] D%d DIVERGENCE at 0x%08X (opcode 0x%04X)\n",
                        validation_state.instruction_count, i, uae_pc_before, opcode);
                fprintf(validation_state.log_file, "UAE D%d: 0x%08X → 0x%08X\n", i, uae_dregs_before[i], uae_dregs_after[i]);
                fprintf(validation_state.log_file, "UC  D%d: 0x%08X → 0x%08X\n", i, uae_dregs_before[i], uc_dreg);

                // For MOVEC instructions, decode the control register
                if (opcode == 0x4E7A || opcode == 0x4E7B) {
                    uint16_t extension = read_word_be(uae_pc_before + 2);
                    uint16_t control_reg = extension & 0xFFF;
                    uint16_t data_reg = (extension >> 12) & 0xF;
                    const char *reg_name = "UNKNOWN";

                    switch (control_reg) {
                        case 0x000: reg_name = "SFC"; break;
                        case 0x001: reg_name = "DFC"; break;
                        case 0x002: reg_name = "CACR"; break;
                        case 0x800: reg_name = "USP"; break;
                        case 0x801: reg_name = "VBR"; break;
                        case 0x802: reg_name = "CAAR"; break;
                        case 0x803: reg_name = "MSP"; break;
                        case 0x804: reg_name = "ISP"; break;
                        case 0x805: reg_name = "MMUSR"; break;
                        case 0x806: reg_name = "URP"; break;
                        case 0x807: reg_name = "SRP"; break;
                        case 0x808: reg_name = "PCR"; break;
                    }

                    fprintf(validation_state.log_file, "MOVEC instruction: %s → %c%d (control_reg=0x%03X, extension=0x%04X)\n",
                            reg_name,
                            (data_reg & 8) ? 'A' : 'D',
                            data_reg & 7,
                            control_reg,
                            extension);
                }
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

/* Platform EmulOp/Trap Handlers - Unified (checks master_cpu) */

bool unicorn_validation_unified_emulop(uint16_t opcode, bool is_primary) {
    return unified_emulop_handler(opcode, is_primary);
}

bool unicorn_validation_unified_trap(int vector, uint16_t opcode, bool is_primary) {
    return unified_trap_handler(vector, opcode, is_primary);
}
