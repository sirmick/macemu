/**
 * Dual-CPU Harness Test
 *
 * Tests that we can create the harness, map memory, and execute
 * instructions with both CPUs (currently just Unicorn, UAE is stubbed)
 */

#include "../../src/cpu/dualcpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define RAM_SIZE (1 * 1024 * 1024)  /* 1MB */
#define RAM_BASE 0x00000000

void test_harness_creation() {
    printf("Test: Dual-CPU harness creation...\n");

    DualCPU *dcpu = dualcpu_create();
    assert(dcpu != NULL);

    printf("  ✓ Harness created\n");

    dualcpu_destroy(dcpu);

    printf("  [PASS]\n\n");
}

void test_memory_mapping() {
    printf("Test: Dual-CPU memory mapping...\n");

    DualCPU *dcpu = dualcpu_create();
    assert(dcpu != NULL);

    /* Map RAM */
    bool ok = dualcpu_map_ram(dcpu, RAM_BASE, RAM_SIZE);
    assert(ok);

    printf("  ✓ RAM mapped for both CPUs\n");

    dualcpu_destroy(dcpu);

    printf("  [PASS]\n\n");
}

void test_simple_execution() {
    printf("Test: Simple instruction execution...\n");

    DualCPU *dcpu = dualcpu_create();
    assert(dcpu != NULL);

    /* Map RAM */
    bool ok = dualcpu_map_ram(dcpu, RAM_BASE, RAM_SIZE);
    assert(ok);

    /* Write a simple M68K program:
     * 0x10000: MOVEQ #-19, D3   (opcode: 0x76ED)
     * 0x10002: NOP              (opcode: 0x4E71)
     */
    uint8_t program[] = { 0x76, 0xED, 0x4E, 0x71 };
    ok = dualcpu_mem_write(dcpu, 0x10000, program, sizeof(program));
    assert(ok);

    /* Set PC to start of program */
    dualcpu_set_pc(dcpu, 0x10000);

    printf("  ✓ Program loaded at 0x10000\n");

    /* Execute first instruction (MOVEQ #-19, D3) */
    ok = dualcpu_execute_one(dcpu);
    assert(ok);

    printf("  ✓ First instruction executed\n");

    /* Execute second instruction (NOP) */
    ok = dualcpu_execute_one(dcpu);
    assert(ok);

    printf("  ✓ Second instruction executed\n");

    /* Get statistics */
    DualCPUStats stats;
    dualcpu_get_stats(dcpu, &stats);

    printf("  ✓ Instructions executed: %lu\n", stats.instructions_executed);
    printf("  ✓ Divergences: %lu\n", stats.divergences);

    assert(stats.instructions_executed == 2);
    assert(stats.divergences == 0);  /* No divergences (UAE not active yet) */

    dualcpu_destroy(dcpu);

    printf("  [PASS]\n\n");
}

void test_register_initialization() {
    printf("Test: Register initialization...\n");

    DualCPU *dcpu = dualcpu_create();
    assert(dcpu != NULL);

    /* Set initial register values */
    dualcpu_set_dreg(dcpu, 0, 0x12345678);
    dualcpu_set_dreg(dcpu, 7, 0xDEADBEEF);
    dualcpu_set_areg(dcpu, 0, 0x00400000);
    dualcpu_set_areg(dcpu, 7, 0x00010000);  /* Stack pointer */
    dualcpu_set_sr(dcpu, 0x2700);  /* Supervisor mode, interrupts disabled */
    dualcpu_set_pc(dcpu, 0x00400400);

    printf("  ✓ Registers initialized on both CPUs\n");

    dualcpu_destroy(dcpu);

    printf("  [PASS]\n\n");
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("\n");
    printf("===========================================\n");
    printf("  Dual-CPU Harness Test Suite\n");
    printf("===========================================\n\n");

    test_harness_creation();
    test_memory_mapping();
    test_simple_execution();
    test_register_initialization();

    printf("===========================================\n");
    printf("  ✅ All tests PASSED!\n");
    printf("===========================================\n\n");

    printf("NOTE: UAE CPU is currently stubbed.\n");
    printf("      Next step: Integrate real UAE CPU.\n\n");

    return 0;
}
