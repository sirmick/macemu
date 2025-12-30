/**
 * CPU Execution Tracing Infrastructure
 *
 * Controlled via environment variable CPU_TRACE:
 * - CPU_TRACE=0       : Disabled
 * - CPU_TRACE=N       : Trace first N instructions
 * - CPU_TRACE=start-end : Trace instructions in range
 */

#ifndef CPU_TRACE_H
#define CPU_TRACE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CPU trace state */
typedef struct {
	bool enabled;
	uint64_t start_count;   /* Start tracing at this instruction */
	uint64_t end_count;     /* Stop tracing at this instruction */
	uint64_t current_count; /* Current instruction count */
} CPUTraceState;

/* Initialize tracing from environment variable */
void cpu_trace_init(void);

/* Check if current instruction should be traced */
bool cpu_trace_should_log(void);

/* Increment instruction counter */
void cpu_trace_increment(void);

/* Log an instruction in standard format */
void cpu_trace_log(uint32_t pc, uint16_t opcode,
                   uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3,
                   uint32_t d4, uint32_t d5, uint32_t d6, uint32_t d7,
                   uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
                   uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7,
                   uint16_t sr);

/* Simplified log (just PC, OP, D0, D1, A0, A7, SR) */
void cpu_trace_log_simple(uint32_t pc, uint16_t opcode,
                          uint32_t d0, uint32_t d1,
                          uint32_t a0, uint32_t a7,
                          uint16_t sr);

#ifdef __cplusplus
}
#endif

#endif /* CPU_TRACE_H */
