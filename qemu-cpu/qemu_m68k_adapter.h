/*
 * QEMU M68K CPU Adapter for BasiliskII
 *
 * This adapter implements BasiliskII's CPU emulation API using QEMU's
 * m68k CPU emulation instead of the UAE CPU emulator.
 *
 * It provides the same interface as basilisk_glue.cpp but uses QEMU
 * under the hood.
 */

#ifndef QEMU_M68K_ADAPTER_H
#define QEMU_M68K_ADAPTER_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BasiliskII's register structure (from main.h) */
struct M68kRegisters {
    uint32_t d[8];
    uint32_t a[8];
    uint16_t sr;
};

/* CPU Initialization/Shutdown */
bool Init680x0_QEMU(void);
void Exit680x0_QEMU(void);

/* CPU Execution */
void Start680x0_QEMU(void);
void Execute68k_QEMU(uint32_t addr, struct M68kRegisters *r);
void Execute68kTrap_QEMU(uint16_t trap, struct M68kRegisters *r);

/* Interrupts */
void TriggerInterrupt_QEMU(void);
void TriggerNMI_QEMU(void);

/* Memory setup (called by BasiliskII during initialization) */
void QEMU_SetupMemory(uint8_t *ram_base, uint32_t ram_size,
                      uint8_t *rom_base, uint32_t rom_size);

#ifdef __cplusplus
}
#endif

#endif /* QEMU_M68K_ADAPTER_H */
