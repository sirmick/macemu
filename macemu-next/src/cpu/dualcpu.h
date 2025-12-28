/**
 * Dual-CPU Validation Harness
 *
 * Runs UAE and Unicorn CPUs side-by-side in lockstep,
 * comparing state after each instruction to validate correctness.
 */

#ifndef DUALCPU_H
#define DUALCPU_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CPU State Snapshot (280 bytes per instruction) */
typedef struct {
    uint64_t seq;           /* Instruction number */
    uint32_t pc;            /* Program counter before */
    uint32_t pc_next;       /* Program counter after */
    uint32_t dregs[8];      /* D0-D7 */
    uint32_t aregs[8];      /* A0-A7 */
    uint32_t sr;            /* Status register */
    uint32_t ccr;           /* Condition codes */
    uint32_t opcode;        /* Opcode bytes */
    uint8_t  opcode_len;    /* Instruction length */
    uint8_t  exception;     /* Exception raised? */
    uint8_t  exception_num; /* Exception vector */
    uint8_t  is_emulop;     /* Is EmulOp? */
    uint16_t emulop_num;    /* EmulOp selector */
    uint64_t timestamp_ns;  /* Timestamp */
} __attribute__((packed)) CPUStateSnapshot;

/* Memory Operation Record (26 bytes) */
typedef struct {
    uint64_t seq;           /* Instruction that caused this */
    uint8_t  type;          /* 0=read, 1=write */
    uint32_t address;       /* Physical address */
    uint8_t  size;          /* Access size (1, 2, 4 bytes) */
    uint32_t value;         /* Value read/written */
    uint64_t timestamp_ns;
} __attribute__((packed)) MemoryOperation;

/* Dual-CPU Harness */
typedef struct DualCPU DualCPU;

/* Initialize dual-CPU harness */
DualCPU* dualcpu_create(void);
void dualcpu_destroy(DualCPU *dcpu);

/* Memory setup (both CPUs get separate RAM/ROM) */
bool dualcpu_map_ram(DualCPU *dcpu, uint32_t addr, uint32_t size);
bool dualcpu_map_rom(DualCPU *dcpu, uint32_t addr, const void *rom_data, uint32_t size);
bool dualcpu_map_memory(DualCPU *dcpu, uint32_t addr, uint32_t size);  /* Map arbitrary memory region */

/* Write to both CPUs' memory */
bool dualcpu_mem_write(DualCPU *dcpu, uint32_t addr, const void *data, uint32_t size);

/* Set initial CPU state (both CPUs) */
void dualcpu_set_pc(DualCPU *dcpu, uint32_t pc);
void dualcpu_set_dreg(DualCPU *dcpu, int reg, uint32_t value);
void dualcpu_set_areg(DualCPU *dcpu, int reg, uint32_t value);
void dualcpu_set_sr(DualCPU *dcpu, uint16_t sr);

/* Execution */
bool dualcpu_execute_one(DualCPU *dcpu);  /* Execute 1 instruction, compare state */
bool dualcpu_execute_n(DualCPU *dcpu, uint64_t count);  /* Execute N instructions */

/* Tracing (optional - for debugging) */
void dualcpu_enable_tracing(DualCPU *dcpu, const char *uae_trace_file, const char *unicorn_trace_file);
void dualcpu_disable_tracing(DualCPU *dcpu);

/* Get divergence info (if execution failed) */
const char* dualcpu_get_error(DualCPU *dcpu);
bool dualcpu_get_divergence(DualCPU *dcpu, CPUStateSnapshot *uae_state, CPUStateSnapshot *unicorn_state);

/* Statistics */
typedef struct {
    uint64_t instructions_executed;
    uint64_t divergences;
    uint64_t memory_ops;
    uint64_t exceptions;
} DualCPUStats;

void dualcpu_get_stats(DualCPU *dcpu, DualCPUStats *stats);

#ifdef __cplusplus
}
#endif

#endif /* DUALCPU_H */
