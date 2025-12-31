#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>

static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type,
                             uint64_t address, int size, int64_t value, void *user_data)
{
    const char *type_str;
    switch(type) {
        case UC_MEM_READ_UNMAPPED: type_str = "READ_UNMAPPED"; break;
        case UC_MEM_WRITE_UNMAPPED: type_str = "WRITE_UNMAPPED"; break;
        case UC_MEM_FETCH_UNMAPPED: type_str = "FETCH_UNMAPPED"; break;
        default: type_str = "UNKNOWN"; break;
    }

    uint32_t pc;
    uc_reg_read(uc, UC_M68K_REG_PC, &pc);

    printf("Memory error: %s at address 0x%08llX, size=%d, PC=0x%08X\n",
           type_str, (unsigned long long)address, size, pc);

    return false;  // Don't handle, let it fail
}

int main() {
    uc_engine *uc;
    uc_err err;
    
    // Initialize Unicorn for M68K
    err = uc_open(UC_ARCH_M68K, UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed to initialize Unicorn: %s\n", uc_strerror(err));
        return 1;
    }
    
    // Map 128KB RAM at 0x00000000 (for A6 pre-decrement read)
    uc_mem_map(uc, 0x00000000, 128 * 1024, UC_PROT_ALL);

    // Map 64KB RAM at 0x02000000 (for A7 stack area)
    uc_mem_map(uc, 0x02000000, 64 * 1024, UC_PROT_ALL);

    // Add hook for invalid memory access
    uc_hook mem_hook;
    uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                (void*)hook_mem_invalid, NULL, 1, 0);

    // M68K code to test ADDA bug
    uint8_t code[] = {
        0x2C, 0x7C, 0x00, 0x01, 0x00, 0x00,  // move.l #$00010000,a6
        0x2E, 0x7C, 0x02, 0x00, 0x01, 0x0A,  // move.l #$0200010A,a7
        0x3D, 0x3C, 0x00, 0x18,              // move.w #$0018,-(a6)
        0xDF, 0xD6,                          // adda.w -(a6),a7 ← BUG HERE
        0x4E, 0x71                           // nop (to see final state)
    };
    
    // Write code to memory
    uc_mem_write(uc, 0x1000, code, sizeof(code));
    
    // Execute
    err = uc_emu_start(uc, 0x1000, 0x1000 + sizeof(code), 0, 0);
    if (err) {
        printf("Execution failed: %s\n", uc_strerror(err));
    }
    
    // Read A7
    uint32_t a7;
    uc_reg_read(uc, UC_M68K_REG_A7, &a7);
    
    printf("ADDA.W -(A6),A7 test:\n");
    printf("  Initial A7: 0x0200010A\n");
    printf("  Value added: 0x0018 (sign-extended to 0x00000018)\n");
    printf("  Expected A7: 0x02000122 (0x0200010A + 0x00000018)\n");
    printf("  Actual A7:   0x%08X\n", a7);

    if (a7 == 0x02000122) {
        printf("  ✓ PASS\n");
    } else {
        printf("  ❌ FAIL - Unicorn bug confirmed!\n");
        printf("  Bug: Unicorn shifted the operand left by 16 bits (added 0x00180000 instead of 0x00000018)\n");
    }
    
    uc_close(uc);
    return (a7 == 0x02000122) ? 0 : 1;
}
