/**
 * Dual-CPU Validation Harness Implementation
 *
 * Minimal implementation to execute UAE and Unicorn side-by-side
 */

#define _POSIX_C_SOURCE 199309L  /* For clock_gettime */

#include "dualcpu.h"
#include "unicorn_wrapper.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Forward declarations for UAE CPU interface */
extern void uae_cpu_init(void);
extern void uae_cpu_reset(void);
extern void uae_cpu_execute_one(void);
extern uint32_t uae_get_dreg(int reg);
extern uint32_t uae_get_areg(int reg);
extern uint32_t uae_get_pc(void);
extern uint16_t uae_get_sr(void);
extern void uae_set_dreg(int reg, uint32_t value);
extern void uae_set_areg(int reg, uint32_t value);
extern void uae_set_pc(uint32_t value);
extern void uae_set_sr(uint16_t value);
extern void uae_mem_map(uint32_t addr, uint32_t size);
extern void uae_mem_write(uint32_t addr, const void *data, uint32_t size);

struct DualCPU {
    /* CPU instances */
    UnicornCPU *unicorn;

    /* Memory regions (separate for each CPU) */
    uint8_t *uae_ram;
    uint8_t *unicorn_ram;
    uint32_t ram_base;
    uint32_t ram_size;

    /* ROM */
    uint8_t *uae_rom;
    uint8_t *unicorn_rom;
    uint32_t rom_base;
    uint32_t rom_size;

    /* Statistics */
    DualCPUStats stats;

    /* Error info */
    char error[512];
    CPUStateSnapshot uae_last;
    CPUStateSnapshot unicorn_last;

    /* Tracing */
    FILE *uae_trace;
    FILE *unicorn_trace;
    bool tracing_enabled;
};

/* Get current timestamp in nanoseconds */
static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Capture UAE CPU state */
static void capture_uae_state(DualCPU *dcpu, CPUStateSnapshot *state) __attribute__((unused));
static void capture_uae_state(DualCPU *dcpu, CPUStateSnapshot *state) {
    state->seq = dcpu->stats.instructions_executed;
    state->pc = uae_get_pc();

    for (int i = 0; i < 8; i++) {
        state->dregs[i] = uae_get_dreg(i);
        state->aregs[i] = uae_get_areg(i);
    }

    state->sr = uae_get_sr();
    state->ccr = state->sr & 0xFF;
    state->timestamp_ns = get_timestamp_ns();

    /* TODO: Fill in opcode, exception info */
    state->opcode = 0;
    state->opcode_len = 2;
    state->exception = 0;
    state->exception_num = 0;
    state->is_emulop = 0;
    state->emulop_num = 0;
}

/* Capture Unicorn CPU state */
static void capture_unicorn_state(DualCPU *dcpu, CPUStateSnapshot *state) {
    state->seq = dcpu->stats.instructions_executed;
    state->pc = unicorn_get_pc(dcpu->unicorn);

    for (int i = 0; i < 8; i++) {
        state->dregs[i] = unicorn_get_dreg(dcpu->unicorn, i);
        state->aregs[i] = unicorn_get_areg(dcpu->unicorn, i);
    }

    state->sr = unicorn_get_sr(dcpu->unicorn);
    state->ccr = state->sr & 0xFF;
    state->timestamp_ns = get_timestamp_ns();

    /* TODO: Fill in opcode, exception info */
    state->opcode = 0;
    state->opcode_len = 2;
    state->exception = 0;
    state->exception_num = 0;
    state->is_emulop = 0;
    state->emulop_num = 0;
}

/* Compare CPU states */
static bool compare_states(DualCPU *dcpu, const CPUStateSnapshot *uae, const CPUStateSnapshot *unicorn) __attribute__((unused));
static bool compare_states(DualCPU *dcpu, const CPUStateSnapshot *uae, const CPUStateSnapshot *unicorn) {
    /* Compare PC */
    if (uae->pc != unicorn->pc) {
        snprintf(dcpu->error, sizeof(dcpu->error),
                "PC divergence at instruction %lu: UAE=0x%08X Unicorn=0x%08X",
                uae->seq, uae->pc, unicorn->pc);
        return false;
    }

    /* Compare data registers */
    for (int i = 0; i < 8; i++) {
        if (uae->dregs[i] != unicorn->dregs[i]) {
            snprintf(dcpu->error, sizeof(dcpu->error),
                    "D%d divergence at instruction %lu: UAE=0x%08X Unicorn=0x%08X",
                    i, uae->seq, uae->dregs[i], unicorn->dregs[i]);
            return false;
        }
    }

    /* Compare address registers */
    for (int i = 0; i < 8; i++) {
        if (uae->aregs[i] != unicorn->aregs[i]) {
            snprintf(dcpu->error, sizeof(dcpu->error),
                    "A%d divergence at instruction %lu: UAE=0x%08X Unicorn=0x%08X",
                    i, uae->seq, uae->aregs[i], unicorn->aregs[i]);
            return false;
        }
    }

    /* Compare status register */
    if (uae->sr != unicorn->sr) {
        snprintf(dcpu->error, sizeof(dcpu->error),
                "SR divergence at instruction %lu: UAE=0x%04X Unicorn=0x%04X",
                uae->seq, uae->sr, unicorn->sr);
        return false;
    }

    return true;
}

/* Create dual-CPU harness */
DualCPU* dualcpu_create(void) {
    DualCPU *dcpu = calloc(1, sizeof(DualCPU));
    if (!dcpu) return NULL;

    /* Create Unicorn CPU */
    dcpu->unicorn = unicorn_create(UCPU_ARCH_M68K);
    if (!dcpu->unicorn) {
        free(dcpu);
        return NULL;
    }

    /* Initialize UAE CPU - stub for now */
    // uae_cpu_init();
    // uae_cpu_reset();

    return dcpu;
}

void dualcpu_destroy(DualCPU *dcpu) {
    if (!dcpu) return;

    if (dcpu->unicorn) {
        unicorn_destroy(dcpu->unicorn);
    }

    if (dcpu->uae_ram) free(dcpu->uae_ram);
    if (dcpu->unicorn_ram) free(dcpu->unicorn_ram);
    if (dcpu->uae_rom) free(dcpu->uae_rom);
    if (dcpu->unicorn_rom) free(dcpu->unicorn_rom);

    if (dcpu->uae_trace) fclose(dcpu->uae_trace);
    if (dcpu->unicorn_trace) fclose(dcpu->unicorn_trace);

    free(dcpu);
}

/* Memory setup */
bool dualcpu_map_ram(DualCPU *dcpu, uint32_t addr, uint32_t size) {
    if (!dcpu) return false;

    /* Allocate separate RAM for each CPU */
    dcpu->uae_ram = calloc(1, size);
    dcpu->unicorn_ram = calloc(1, size);
    if (!dcpu->uae_ram || !dcpu->unicorn_ram) {
        return false;
    }

    dcpu->ram_base = addr;
    dcpu->ram_size = size;

    /* Map in Unicorn */
    if (!unicorn_map_ram(dcpu->unicorn, addr, NULL, size)) {
        return false;
    }

    /* Map in UAE - stub */
    // uae_mem_map(addr, size);

    return true;
}

bool dualcpu_map_rom(DualCPU *dcpu, uint32_t addr, const void *rom_data, uint32_t size) {
    if (!dcpu || !rom_data) return false;

    /* Allocate separate ROM for each CPU */
    dcpu->uae_rom = malloc(size);
    dcpu->unicorn_rom = malloc(size);
    if (!dcpu->uae_rom || !dcpu->unicorn_rom) {
        return false;
    }

    /* Copy ROM data */
    memcpy(dcpu->uae_rom, rom_data, size);
    memcpy(dcpu->unicorn_rom, rom_data, size);

    dcpu->rom_base = addr;
    dcpu->rom_size = size;

    /* Map in Unicorn */
    if (!unicorn_map_rom(dcpu->unicorn, addr, rom_data, size)) {
        return false;
    }

    /* Map in UAE - stub */
    // uae_mem_map(addr, size);
    // uae_mem_write(addr, rom_data, size);

    return true;
}

bool dualcpu_mem_write(DualCPU *dcpu, uint32_t addr, const void *data, uint32_t size) {
    if (!dcpu || !data) return false;

    /* Write to Unicorn */
    if (!unicorn_mem_write(dcpu->unicorn, addr, data, size)) {
        return false;
    }

    /* Write to UAE - stub */
    // uae_mem_write(addr, data, size);

    return true;
}

/* Set initial state */
void dualcpu_set_pc(DualCPU *dcpu, uint32_t pc) {
    if (!dcpu) return;
    unicorn_set_pc(dcpu->unicorn, pc);
    // uae_set_pc(pc);
}

void dualcpu_set_dreg(DualCPU *dcpu, int reg, uint32_t value) {
    if (!dcpu) return;
    unicorn_set_dreg(dcpu->unicorn, reg, value);
    // uae_set_dreg(reg, value);
}

void dualcpu_set_areg(DualCPU *dcpu, int reg, uint32_t value) {
    if (!dcpu) return;
    unicorn_set_areg(dcpu->unicorn, reg, value);
    // uae_set_areg(reg, value);
}

void dualcpu_set_sr(DualCPU *dcpu, uint16_t sr) {
    if (!dcpu) return;
    unicorn_set_sr(dcpu->unicorn, sr);
    // uae_set_sr(sr);
}

/* Execute one instruction on both CPUs and compare */
bool dualcpu_execute_one(DualCPU *dcpu) {
    if (!dcpu) return false;

    CPUStateSnapshot unicorn_before, unicorn_after;

    /* Capture state before */
    // capture_uae_state(dcpu, &uae_before);
    capture_unicorn_state(dcpu, &unicorn_before);

    /* Execute on UAE */
    // uae_cpu_execute_one();

    /* Execute on Unicorn */
    if (!unicorn_execute_one(dcpu->unicorn)) {
        snprintf(dcpu->error, sizeof(dcpu->error),
                "Unicorn execution failed: %s", unicorn_get_error(dcpu->unicorn));
        return false;
    }

    /* Capture state after */
    // capture_uae_state(dcpu, &uae_after);
    capture_unicorn_state(dcpu, &unicorn_after);

    /* Save last states */
    // dcpu->uae_last = uae_after;
    dcpu->unicorn_last = unicorn_after;

    /* Compare states */
    // if (!compare_states(dcpu, &uae_after, &unicorn_after)) {
    //     dcpu->stats.divergences++;
    //     return false;
    // }

    dcpu->stats.instructions_executed++;
    return true;
}

bool dualcpu_execute_n(DualCPU *dcpu, uint64_t count) {
    for (uint64_t i = 0; i < count; i++) {
        if (!dualcpu_execute_one(dcpu)) {
            return false;
        }
    }
    return true;
}

/* Tracing */
void dualcpu_enable_tracing(DualCPU *dcpu, const char *uae_file, const char *unicorn_file) {
    if (!dcpu) return;

    if (uae_file) {
        dcpu->uae_trace = fopen(uae_file, "wb");
    }
    if (unicorn_file) {
        dcpu->unicorn_trace = fopen(unicorn_file, "wb");
    }
    dcpu->tracing_enabled = true;
}

void dualcpu_disable_tracing(DualCPU *dcpu) {
    if (!dcpu) return;

    if (dcpu->uae_trace) {
        fclose(dcpu->uae_trace);
        dcpu->uae_trace = NULL;
    }
    if (dcpu->unicorn_trace) {
        fclose(dcpu->unicorn_trace);
        dcpu->unicorn_trace = NULL;
    }
    dcpu->tracing_enabled = false;
}

/* Error handling */
const char* dualcpu_get_error(DualCPU *dcpu) {
    return dcpu ? dcpu->error : "Invalid DualCPU handle";
}

bool dualcpu_get_divergence(DualCPU *dcpu, CPUStateSnapshot *uae_state, CPUStateSnapshot *unicorn_state) {
    if (!dcpu) return false;
    if (uae_state) *uae_state = dcpu->uae_last;
    if (unicorn_state) *unicorn_state = dcpu->unicorn_last;
    return dcpu->stats.divergences > 0;
}

/* Statistics */
void dualcpu_get_stats(DualCPU *dcpu, DualCPUStats *stats) {
    if (dcpu && stats) {
        *stats = dcpu->stats;
    }
}
