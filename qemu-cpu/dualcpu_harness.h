/*
 * DualCPU Testing Harness - Header
 *
 * Runs UAE and QEMU CPUs side-by-side for validation.
 * Each CPU has separate memory. After each instruction,
 * states are compared to detect divergences immediately.
 *
 * Usage:
 *   Build with USE_DUALCPU=1 to enable
 *   DualCPU_Init() to initialize harness
 *   Hook is automatically called after each UAE instruction
 */

#ifndef DUALCPU_HARNESS_H
#define DUALCPU_HARNESS_H

#include "sysdeps.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize DualCPU testing harness
 *
 * This allocates separate memory for UAE and QEMU,
 * initializes both CPUs, and sets up comparison infrastructure.
 *
 * Must be called after UAE's Init680x0() but before Start680x0().
 *
 * Returns: true on success, false on failure
 */
bool DualCPU_Init(void);

/*
 * Shutdown DualCPU testing harness
 *
 * Frees memory, prints statistics, shuts down both CPUs.
 */
void DualCPU_Exit(void);

/*
 * Hook called after UAE executes one instruction
 *
 * This is automatically called from UAE's m68k_do_execute() loop
 * when USE_DUALCPU is enabled.
 *
 * Actions:
 *   1. Execute same instruction on QEMU
 *   2. Compare CPU states (PC, registers, SR)
 *   3. Periodically compare memory
 *   4. Abort if divergence detected
 */
void DualCPU_AfterInstruction(void);

/*
 * Get current instruction count
 */
uint64_t DualCPU_GetInstructionCount(void);

/*
 * Get divergence statistics
 */
void DualCPU_GetStats(uint64_t *total_instructions,
                      uint64_t *register_divergences,
                      uint64_t *memory_divergences);

#ifdef __cplusplus
}
#endif

#endif /* DUALCPU_HARNESS_H */
