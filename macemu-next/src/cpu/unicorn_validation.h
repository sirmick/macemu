/**
 * Unicorn CPU Validation Module
 *
 * Runs Unicorn CPU in lockstep with UAE for validation during actual BasiliskII execution.
 * This allows us to verify instruction-by-instruction compatibility during ROM boot and OS execution.
 */

#ifndef UNICORN_VALIDATION_H
#define UNICORN_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize Unicorn validation
 * - Creates Unicorn CPU instance
 * - Maps ROM to Unicorn
 * - Opens divergence log file
 *
 * Must be called AFTER InitAll() so ROM is loaded and patched
 */
bool unicorn_validation_init(void);

/**
 * Shutdown Unicorn validation
 * - Destroys Unicorn CPU
 * - Closes log file
 * - Prints statistics
 */
void unicorn_validation_shutdown(void);

/**
 * Validate one instruction
 * - Captures UAE state before
 * - Executes instruction on UAE
 * - Syncs memory to Unicorn
 * - Executes on Unicorn
 * - Compares states
 * - Logs divergences
 *
 * Returns: true if states match, false if divergence detected
 */
bool unicorn_validation_step(void);

/**
 * Check if validation is enabled
 */
bool unicorn_validation_enabled(void);

/**
 * Enable/disable validation at runtime
 */
void unicorn_validation_set_enabled(bool enabled);

/**
 * Get validation statistics
 */
void unicorn_validation_get_stats(uint64_t *instructions, uint64_t *divergences);

/**
 * Platform EmulOp/Trap Handlers
 *
 * These are called by the CPU wrappers when EmulOps or traps are encountered.
 * In dual-CPU mode, one CPU acts as primary (executes operation) and one as secondary (skips operation).
 */

/* Unified handlers - is_primary indicates which CPU is calling */
void unicorn_validation_uae_emulop_primary(uint16_t opcode, bool is_primary);
void unicorn_validation_uae_trap_primary(int vector, uint16_t opcode, bool is_primary);

#ifdef __cplusplus
}
#endif

#endif /* UNICORN_VALIDATION_H */
