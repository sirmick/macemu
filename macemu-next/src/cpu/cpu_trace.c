/**
 * CPU Execution Tracing Implementation
 */

#include "cpu_trace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static CPUTraceState g_trace = {0};

void cpu_trace_init(void) {
	const char *trace_env = getenv("CPU_TRACE");
	if (!trace_env) {
		g_trace.enabled = false;
		return;
	}

	/* Parse CPU_TRACE value */
	if (strchr(trace_env, '-')) {
		/* Range format: "start-end" */
		if (sscanf(trace_env, "%lu-%lu", &g_trace.start_count, &g_trace.end_count) == 2) {
			g_trace.enabled = true;
			fprintf(stderr, "[CPU trace enabled: instructions %lu-%lu]\n",
			        g_trace.start_count, g_trace.end_count);
		}
	} else {
		/* Simple count: "N" means trace first N instructions */
		long count = strtol(trace_env, NULL, 10);
		if (count > 0) {
			g_trace.enabled = true;
			g_trace.start_count = 0;
			g_trace.end_count = count;
			fprintf(stderr, "[CPU trace enabled: will trace first %ld instructions]\n", count);
		}
	}

	g_trace.current_count = 0;
}

bool cpu_trace_should_log(void) {
	if (!g_trace.enabled) return false;
	return (g_trace.current_count >= g_trace.start_count &&
	        g_trace.current_count < g_trace.end_count);
}

void cpu_trace_increment(void) {
	g_trace.current_count++;
}

void cpu_trace_log_simple(uint32_t pc, uint16_t opcode,
                          uint32_t d0, uint32_t d1,
                          uint32_t a0, uint32_t a7,
                          uint16_t sr) {
	fprintf(stderr, "[%04lu] PC=%08X OP=%04X | D0=%08X D1=%08X A0=%08X A7=%08X SR=%04X\n",
	        g_trace.current_count, pc, opcode, d0, d1, a0, a7, sr);
}

void cpu_trace_log(uint32_t pc, uint16_t opcode,
                   uint32_t d0, uint32_t d1, uint32_t d2, uint32_t d3,
                   uint32_t d4, uint32_t d5, uint32_t d6, uint32_t d7,
                   uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
                   uint32_t a4, uint32_t a5, uint32_t a6, uint32_t a7,
                   uint16_t sr) {
	fprintf(stderr, "[%04lu] PC=%08X OP=%04X | "
	        "D0=%08X D1=%08X D2=%08X D3=%08X D4=%08X D5=%08X D6=%08X D7=%08X | "
	        "A0=%08X A1=%08X A2=%08X A3=%08X A4=%08X A5=%08X A6=%08X A7=%08X | "
	        "SR=%04X\n",
	        g_trace.current_count, pc, opcode,
	        d0, d1, d2, d3, d4, d5, d6, d7,
	        a0, a1, a2, a3, a4, a5, a6, a7,
	        sr);
}
