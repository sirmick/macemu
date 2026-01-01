/**
 * Basic Unicorn M68K Test
 *
 * Tests that we can create a CPU, map memory, execute instructions,
 * and read registers.
 */

#include "../../src/cpu/unicorn_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define RAM_SIZE (1 * 1024 * 1024)  /* 1MB */
#define RAM_BASE 0x00000000

void test_basic_execution() {
    printf("Test: Basic M68K execution...\n");

    /* Create M68K CPU */
    UnicornCPU *cpu = unicorn_create(UCPU_ARCH_M68K);
    assert(cpu != NULL);

    /* Map RAM (no initial data) */
    bool ok = unicorn_map_ram(cpu, RAM_BASE, NULL, RAM_SIZE);
    assert(ok);

    /* Write a simple M68K program (big-endian):
     * 0x10000: MOVEQ #-19, D3   (opcode: 0x76ED)
     * 0x10002: NOP              (opcode: 0x4E71)
     */
    uint8_t program[] = { 0x76, 0xED, 0x4E, 0x71 };
    ok = unicorn_mem_write(cpu, 0x10000, program, sizeof(program));
    assert(ok);

    /* Set PC to start of program */
    unicorn_set_pc(cpu, 0x10000);

    /* Execute first instruction: MOVEQ #-19, D3 */
    ok = unicorn_execute_one(cpu);
    assert(ok);

    /* Check D3 register */
    uint32_t d3 = unicorn_get_dreg(cpu, 3);
    assert(d3 == 0xFFFFFFED);  /* -19 in two's complement */

    /* Check PC advanced */
    uint32_t pc = unicorn_get_pc(cpu);
    assert(pc == 0x10002);

    printf("  ✓ MOVEQ instruction works correctly\n");
    printf("  ✓ D3 = 0x%08X (expected 0xFFFFFFED)\n", d3);
    printf("  ✓ PC = 0x%08X (expected 0x00010002)\n", pc);

    /* Clean up */
    unicorn_destroy(cpu);

    printf("  [PASS]\n\n");
}

void test_register_access() {
    printf("Test: Register read/write...\n");

    UnicornCPU *cpu = unicorn_create(UCPU_ARCH_M68K);
    assert(cpu != NULL);

    /* Test data registers */
    for (int i = 0; i < 8; i++) {
        uint32_t test_value = 0x12345678 + i;
        unicorn_set_dreg(cpu, i, test_value);
        uint32_t value = unicorn_get_dreg(cpu, i);
        assert(value == test_value);
    }
    printf("  ✓ Data registers (D0-D7) work\n");

    /* Test address registers */
    for (int i = 0; i < 8; i++) {
        uint32_t test_value = 0xABCDEF00 + i;
        unicorn_set_areg(cpu, i, test_value);
        uint32_t value = unicorn_get_areg(cpu, i);
        assert(value == test_value);
    }
    printf("  ✓ Address registers (A0-A7) work\n");

    /* Test PC */
    unicorn_set_pc(cpu, 0xDEADBEEF);
    uint32_t pc = unicorn_get_pc(cpu);
    assert(pc == 0xDEADBEEF);
    printf("  ✓ Program counter works\n");

    /* Test SR */
    unicorn_set_sr(cpu, 0x2700);
    uint16_t sr = unicorn_get_sr(cpu);
    assert(sr == 0x2700);
    printf("  ✓ Status register works\n");

    unicorn_destroy(cpu);

    printf("  [PASS]\n\n");
}

void test_memory_mapping() {
    printf("Test: Memory mapping...\n");

    UnicornCPU *cpu = unicorn_create(UCPU_ARCH_M68K);
    assert(cpu != NULL);

    /* Map multiple memory regions at different addresses */
    bool ok1 = unicorn_map_ram(cpu, 0x00000000, NULL, 64 * 1024);
    bool ok2 = unicorn_map_ram(cpu, 0x10000000, NULL, 64 * 1024);
    assert(ok1 && ok2);

    printf("  ✓ Multiple memory regions mapped\n");

    /* Write test pattern to first region */
    uint8_t test_byte = 0xAB;
    bool ok = unicorn_mem_write(cpu, 0x1234, &test_byte, 1);
    assert(ok);

    /* Read it back */
    uint8_t read_byte = 0;
    ok = unicorn_mem_read(cpu, 0x1234, &read_byte, 1);
    assert(ok);
    assert(read_byte == 0xAB);

    printf("  ✓ Memory read/write works\n");

    unicorn_destroy(cpu);

    printf("  [PASS]\n\n");
}

/* Stub implementations for platform functions (not used by this test) */
#include "../../src/common/include/platform.h"
Platform g_platform;

void QuitEmulator() {}
void ErrorAlert(const char *msg) { fprintf(stderr, "ERROR: %s\n", msg); }
bool TwentyFourBitAddressing = false;

int main(int argc, char **argv) {
    printf("\n");
    printf("===========================================\n");
    printf("  Unicorn M68K Wrapper Test Suite\n");
    printf("===========================================\n\n");

    test_basic_execution();
    test_register_access();
    test_memory_mapping();

    printf("===========================================\n");
    printf("  ✅ All tests PASSED!\n");
    printf("===========================================\n\n");

    return 0;
}
