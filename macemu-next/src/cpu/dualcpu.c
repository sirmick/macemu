/**
 * Dual-CPU Validation Harness Implementation
 *
 * Minimal implementation to execute UAE and Unicorn side-by-side
 */

#define _POSIX_C_SOURCE 199309L  /* For clock_gettime */

#include "dualcpu.h"
#include "unicorn_wrapper.h"
#include "uae_wrapper.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* UAE CPU interface now in uae_wrapper.h */

struct DualCPU {
    /* CPU instances */
    UnicornCPU *unicorn;

    /* Memory regions */
    /* UAE needs contiguous buffer for DIRECT_ADDRESSING */
    uint8_t *uae_memory;      /* Single contiguous buffer for RAM+ROM */
    uint32_t uae_memory_size; /* Total size of UAE buffer */

    /* Unicorn uses separate allocations */
    uint8_t *unicorn_ram;
    uint8_t *unicorn_rom;

    uint32_t ram_base;
    uint32_t ram_size;
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

    /* Initialize UAE CPU */
    if (!uae_cpu_init()) {
        free(dcpu);
        return NULL;
    }
    uae_cpu_reset();

    /* Ensure both CPUs start with identical zeroed register state */
    for (int i = 0; i < 8; i++) {
        unicorn_set_dreg(dcpu->unicorn, i, 0);
        unicorn_set_areg(dcpu->unicorn, i, 0);
        uae_set_dreg(i, 0);
        uae_set_areg(i, 0);
    }
    unicorn_set_sr(dcpu->unicorn, 0x2700);  /* Supervisor mode, interrupts disabled */
    uae_set_sr(0x2700);
    unicorn_set_pc(dcpu->unicorn, 0);
    uae_set_pc(0);

    return dcpu;
}

void dualcpu_destroy(DualCPU *dcpu) {
    if (!dcpu) return;

    if (dcpu->unicorn) {
        unicorn_destroy(dcpu->unicorn);
    }

    if (dcpu->uae_memory) free(dcpu->uae_memory);
    if (dcpu->unicorn_ram) free(dcpu->unicorn_ram);
    if (dcpu->unicorn_rom) free(dcpu->unicorn_rom);

    if (dcpu->uae_trace) fclose(dcpu->uae_trace);
    if (dcpu->unicorn_trace) fclose(dcpu->unicorn_trace);

    free(dcpu);
}

/* Memory setup */
bool dualcpu_map_ram(DualCPU *dcpu, uint32_t addr, uint32_t size) {
    if (!dcpu) return false;
    if (addr != 0) {
        snprintf(dcpu->error, sizeof(dcpu->error),
                "dualcpu_map_ram: RAM must start at address 0 (got 0x%X)", addr);
        return false;
    }

    dcpu->ram_base = addr;
    dcpu->ram_size = size;

    /* Allocate Unicorn RAM separately */
    dcpu->unicorn_ram = calloc(1, size);
    if (!dcpu->unicorn_ram) {
        return false;
    }

    /* Map in Unicorn */
    if (!unicorn_map_ram(dcpu->unicorn, addr, NULL, size)) {
        return false;
    }

    /* UAE: Don't allocate yet - wait for ROM mapping to know total size */

    return true;
}

bool dualcpu_map_rom(DualCPU *dcpu, uint32_t addr, const void *rom_data, uint32_t size) {
    if (!dcpu || !rom_data) return false;
    if (dcpu->ram_base != 0 || dcpu->ram_size == 0) {
        snprintf(dcpu->error, sizeof(dcpu->error),
                "dualcpu_map_rom: RAM must be mapped first at address 0");
        return false;
    }

    dcpu->rom_base = addr;
    dcpu->rom_size = size;

    /* Allocate Unicorn ROM separately */
    dcpu->unicorn_rom = malloc(size);
    if (!dcpu->unicorn_rom) {
        return false;
    }
    memcpy(dcpu->unicorn_rom, rom_data, size);

    /* Map in Unicorn */
    if (!unicorn_map_rom(dcpu->unicorn, addr, rom_data, size)) {
        return false;
    }

    /* UAE: Allocate single contiguous buffer from 0 to ROM_END */
    uint32_t rom_end = dcpu->rom_base + dcpu->rom_size;
    dcpu->uae_memory_size = rom_end;
    dcpu->uae_memory = calloc(1, dcpu->uae_memory_size);
    if (!dcpu->uae_memory) {
        return false;
    }

    /* Copy ROM data into UAE buffer at the correct offset */
    memcpy(dcpu->uae_memory + dcpu->rom_base, rom_data, size);
    /* RAM portion is already zeroed by calloc */

    /* Tell UAE about the memory layout */
    uae_mem_set_ram_ptr(dcpu->uae_memory, dcpu->uae_memory_size);

    return true;
}

bool dualcpu_mem_write(DualCPU *dcpu, uint32_t addr, const void *data, uint32_t size) {
    if (!dcpu || !data) return false;

    /* Write to Unicorn */
    if (!unicorn_mem_write(dcpu->unicorn, addr, data, size)) {
        return false;
    }

    /* Write to UAE */
    uae_mem_write(addr, data, size);

    return true;
}

/* Set initial state */
void dualcpu_set_pc(DualCPU *dcpu, uint32_t pc) {
    if (!dcpu) return;
    unicorn_set_pc(dcpu->unicorn, pc);
    uae_set_pc(pc);
}

void dualcpu_set_dreg(DualCPU *dcpu, int reg, uint32_t value) {
    if (!dcpu) return;
    unicorn_set_dreg(dcpu->unicorn, reg, value);
    uae_set_dreg(reg, value);
}

void dualcpu_set_areg(DualCPU *dcpu, int reg, uint32_t value) {
    if (!dcpu) return;
    unicorn_set_areg(dcpu->unicorn, reg, value);
    uae_set_areg(reg, value);
}

void dualcpu_set_sr(DualCPU *dcpu, uint16_t sr) {
    if (!dcpu) return;
    unicorn_set_sr(dcpu->unicorn, sr);
    uae_set_sr(sr);
}

/* Execute one instruction on both CPUs and compare */
bool dualcpu_execute_one(DualCPU *dcpu) {
    if (!dcpu) return false;

    CPUStateSnapshot uae_before, uae_after;
    CPUStateSnapshot unicorn_before, unicorn_after;

    /* Capture state before */
    capture_uae_state(dcpu, &uae_before);
    capture_unicorn_state(dcpu, &unicorn_before);

    /* Execute on UAE */
    uae_cpu_execute_one();

    /* Execute on Unicorn */
    if (!unicorn_execute_one(dcpu->unicorn)) {
        snprintf(dcpu->error, sizeof(dcpu->error),
                "Unicorn execution failed: %s", unicorn_get_error(dcpu->unicorn));
        return false;
    }

    /* Capture state after */
    capture_uae_state(dcpu, &uae_after);
    capture_unicorn_state(dcpu, &unicorn_after);

    /* Save last states */
    dcpu->uae_last = uae_after;
    dcpu->unicorn_last = unicorn_after;

    /* Compare states */
    if (!compare_states(dcpu, &uae_after, &unicorn_after)) {
        dcpu->stats.divergences++;
        return false;
    }

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
