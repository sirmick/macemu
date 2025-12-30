/**
 * Unicorn Engine Wrapper Implementation
 */

#include "unicorn_wrapper.h"
#include <unicorn/unicorn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct UnicornCPU {
    uc_engine *uc;
    UnicornArch arch;
    char error[256];

    /* Hooks */
    EmulOpHandler emulop_handler;
    void *emulop_user_data;

    ExceptionHandler exception_handler;

    MemoryHookCallback memory_hook;
    void *memory_user_data;
    uc_hook mem_hook_handle;

    uc_hook invalid_insn_hook;
};

/* Helper: Convert uc_err to string and store in cpu->error */
static void set_error(UnicornCPU *cpu, uc_err err) {
    if (err != UC_ERR_OK) {
        snprintf(cpu->error, sizeof(cpu->error), "%s", uc_strerror(err));
    }
}

/* Invalid instruction hook for EmulOp handling */
static bool hook_invalid_insn(uc_engine *uc, void *user_data) {
    UnicornCPU *cpu = (UnicornCPU *)user_data;
    uint32_t pc;
    uint16_t opcode;

    uc_reg_read(uc, UC_M68K_REG_PC, &pc);
    uc_mem_read(uc, pc, &opcode, sizeof(opcode));

    /* M68K is big-endian, swap if needed */
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    opcode = __builtin_bswap16(opcode);
    #endif

    /* Check if EmulOp (0x71xx for M68K) */
    if ((opcode & 0xFF00) == 0x7100) {
        if (cpu->emulop_handler) {
            cpu->emulop_handler(opcode, cpu->emulop_user_data);
            /* Advance past EmulOp */
            pc += 2;
            uc_reg_write(uc, UC_M68K_REG_PC, &pc);
            return true;  /* Handled */
        }
    }

    /* Check for A-line trap (0xAxxx) */
    if ((opcode & 0xF000) == 0xA000) {
        if (cpu->exception_handler) {
            cpu->exception_handler(cpu, 10, opcode);
            return true;  /* Handled */
        }
    }

    /* Check for F-line trap (0xFxxx) */
    if ((opcode & 0xF000) == 0xF000) {
        if (cpu->exception_handler) {
            cpu->exception_handler(cpu, 11, opcode);
            return true;  /* Handled */
        }
    }

    return false;  /* Not handled, raise exception */
}

/* Memory access hook */
static void hook_memory(uc_engine *uc, uc_mem_type type,
                       uint64_t address, int size, int64_t value,
                       void *user_data)
{
    UnicornCPU *cpu = (UnicornCPU *)user_data;

    if (cpu->memory_hook) {
        UnicornMemType mem_type = (type == UC_MEM_READ || type == UC_MEM_READ_UNMAPPED) ?
                                  UCPU_MEM_READ : UCPU_MEM_WRITE;
        cpu->memory_hook(cpu, mem_type, address, (uint32_t)size,
                        (uint64_t)value, cpu->memory_user_data);
    }
}

/* CPU lifecycle */
UnicornCPU* unicorn_create(UnicornArch arch) {
    return unicorn_create_with_model(arch, -1);  /* Use default CPU model */
}

UnicornCPU* unicorn_create_with_model(UnicornArch arch, int cpu_model) {
    UnicornCPU *cpu = calloc(1, sizeof(UnicornCPU));
    if (!cpu) return NULL;

    cpu->arch = arch;

    uc_arch uc_arch;
    uc_mode uc_mode;

    switch (arch) {
        case UCPU_ARCH_M68K:
            uc_arch = UC_ARCH_M68K;
            uc_mode = UC_MODE_BIG_ENDIAN;
            break;
        case UCPU_ARCH_PPC:
            uc_arch = UC_ARCH_PPC;
            uc_mode = UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN;
            break;
        case UCPU_ARCH_PPC64:
            uc_arch = UC_ARCH_PPC;
            uc_mode = UC_MODE_PPC64 | UC_MODE_BIG_ENDIAN;
            break;
        default:
            free(cpu);
            return NULL;
    }

    uc_err err = uc_open(uc_arch, uc_mode, &cpu->uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to create Unicorn CPU: %s\n", uc_strerror(err));
        free(cpu);
        return NULL;
    }

    /* Set CPU model if specified */
    if (cpu_model >= 0) {
        err = uc_ctl_set_cpu_model(cpu->uc, cpu_model);
        if (err != UC_ERR_OK) {
            fprintf(stderr, "Failed to set Unicorn CPU model: %s\n", uc_strerror(err));
            uc_close(cpu->uc);
            free(cpu);
            return NULL;
        }
    }

    return cpu;
}

void unicorn_destroy(UnicornCPU *cpu) {
    if (!cpu) return;

    if (cpu->uc) {
        uc_close(cpu->uc);
    }
    free(cpu);
}

/* Memory mapping */
bool unicorn_map_ram(UnicornCPU *cpu, uint64_t addr, void *host_ptr, uint64_t size) {
    if (!cpu || !cpu->uc) return false;

    /* First map the memory region */
    uc_err err = uc_mem_map(cpu->uc, addr, size, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }

    /* Then write the host data into it (if host_ptr is not NULL) */
    if (host_ptr) {
        err = uc_mem_write(cpu->uc, addr, host_ptr, size);
        if (err != UC_ERR_OK) {
            set_error(cpu, err);
            return false;
        }
    }
    return true;
}

bool unicorn_map_rom(UnicornCPU *cpu, uint64_t addr, const void *host_ptr, uint64_t size) {
    if (!cpu || !cpu->uc) return false;

    /* ROM is read+exec, no write */
    uc_err err = uc_mem_map(cpu->uc, addr, size, UC_PROT_READ | UC_PROT_EXEC);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }

    /* Write ROM data */
    if (host_ptr) {
        err = uc_mem_write(cpu->uc, addr, host_ptr, size);
        if (err != UC_ERR_OK) {
            set_error(cpu, err);
            return false;
        }
    }
    return true;
}

bool unicorn_unmap(UnicornCPU *cpu, uint64_t addr, uint64_t size) {
    if (!cpu || !cpu->uc) return false;

    uc_err err = uc_mem_unmap(cpu->uc, addr, size);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }
    return true;
}

/* Memory access */
bool unicorn_mem_write(UnicornCPU *cpu, uint64_t addr, const void *data, size_t size) {
    if (!cpu || !cpu->uc || !data) return false;

    uc_err err = uc_mem_write(cpu->uc, addr, data, size);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }
    return true;
}

bool unicorn_mem_read(UnicornCPU *cpu, uint64_t addr, void *data, size_t size) {
    if (!cpu || !cpu->uc || !data) return false;

    uc_err err = uc_mem_read(cpu->uc, addr, data, size);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }
    return true;
}

/* Execution */
bool unicorn_execute_one(UnicornCPU *cpu) {
    if (!cpu || !cpu->uc) return false;

    uint64_t pc;
    uc_reg_read(cpu->uc,
                cpu->arch == UCPU_ARCH_M68K ? UC_M68K_REG_PC : UC_PPC_REG_PC,
                &pc);

    uc_err err = uc_emu_start(cpu->uc, pc, 0xFFFFFFFFFFFFFFFFULL, 0, 1);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }
    return true;
}

bool unicorn_execute_n(UnicornCPU *cpu, uint64_t count) {
    if (!cpu || !cpu->uc) return false;

    uint64_t pc;
    uc_reg_read(cpu->uc,
                cpu->arch == UCPU_ARCH_M68K ? UC_M68K_REG_PC : UC_PPC_REG_PC,
                &pc);

    uc_err err = uc_emu_start(cpu->uc, pc, 0xFFFFFFFFFFFFFFFFULL, 0, count);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }
    return true;
}

bool unicorn_execute_until(UnicornCPU *cpu, uint64_t end_addr) {
    if (!cpu || !cpu->uc) return false;

    uint64_t pc;
    uc_reg_read(cpu->uc,
                cpu->arch == UCPU_ARCH_M68K ? UC_M68K_REG_PC : UC_PPC_REG_PC,
                &pc);

    uc_err err = uc_emu_start(cpu->uc, pc, end_addr, 0, 0);
    if (err != UC_ERR_OK) {
        set_error(cpu, err);
        return false;
    }
    return true;
}

void unicorn_stop(UnicornCPU *cpu) {
    if (cpu && cpu->uc) {
        uc_emu_stop(cpu->uc);
    }
}

/* Registers - M68K */
uint32_t unicorn_get_dreg(UnicornCPU *cpu, int reg) {
    if (!cpu || !cpu->uc || reg < 0 || reg > 7) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_M68K_REG_D0 + reg, &value);
    return value;
}

uint32_t unicorn_get_areg(UnicornCPU *cpu, int reg) {
    if (!cpu || !cpu->uc || reg < 0 || reg > 7) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_M68K_REG_A0 + reg, &value);
    return value;
}

void unicorn_set_dreg(UnicornCPU *cpu, int reg, uint32_t value) {
    if (!cpu || !cpu->uc || reg < 0 || reg > 7) return;
    uc_reg_write(cpu->uc, UC_M68K_REG_D0 + reg, &value);
}

void unicorn_set_areg(UnicornCPU *cpu, int reg, uint32_t value) {
    if (!cpu || !cpu->uc || reg < 0 || reg > 7) return;
    uc_reg_write(cpu->uc, UC_M68K_REG_A0 + reg, &value);
}

uint32_t unicorn_get_pc(UnicornCPU *cpu) {
    if (!cpu || !cpu->uc) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_M68K_REG_PC, &value);
    return value;
}

void unicorn_set_pc(UnicornCPU *cpu, uint32_t value) {
    if (!cpu || !cpu->uc) return;
    uc_reg_write(cpu->uc, UC_M68K_REG_PC, &value);
}

uint16_t unicorn_get_sr(UnicornCPU *cpu) {
    if (!cpu || !cpu->uc) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_M68K_REG_SR, &value);
    return (uint16_t)value;
}

void unicorn_set_sr(UnicornCPU *cpu, uint16_t value) {
    if (!cpu || !cpu->uc) return;
    uint32_t v = value;
    uc_reg_write(cpu->uc, UC_M68K_REG_SR, &v);
}

/* Registers - PPC */
uint32_t unicorn_get_gpr(UnicornCPU *cpu, int reg) {
    if (!cpu || !cpu->uc || reg < 0 || reg > 31) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_PPC_REG_0 + reg, &value);
    return value;
}

void unicorn_set_gpr(UnicornCPU *cpu, int reg, uint32_t value) {
    if (!cpu || !cpu->uc || reg < 0 || reg > 31) return;
    uc_reg_write(cpu->uc, UC_PPC_REG_0 + reg, &value);
}

uint32_t unicorn_get_spr(UnicornCPU *cpu, int spr) {
    /* TODO: Implement SPR access based on SPR number */
    return 0;
}

void unicorn_set_spr(UnicornCPU *cpu, int spr, uint32_t value) {
    /* TODO: Implement SPR access based on SPR number */
}

uint32_t unicorn_get_msr(UnicornCPU *cpu) {
    if (!cpu || !cpu->uc) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_PPC_REG_MSR, &value);
    return value;
}

void unicorn_set_msr(UnicornCPU *cpu, uint32_t value) {
    if (!cpu || !cpu->uc) return;
    uc_reg_write(cpu->uc, UC_PPC_REG_MSR, &value);
}

/* Hooks */
void unicorn_set_emulop_handler(UnicornCPU *cpu, EmulOpHandler handler, void *user_data) {
    if (!cpu || !cpu->uc) return;

    cpu->emulop_handler = handler;
    cpu->emulop_user_data = user_data;

    if (handler && !cpu->invalid_insn_hook) {
        uc_hook_add(cpu->uc, &cpu->invalid_insn_hook, UC_HOOK_INSN_INVALID,
                   (void *)hook_invalid_insn, cpu, 1, 0);
    } else if (!handler && !cpu->exception_handler && cpu->invalid_insn_hook) {
        uc_hook_del(cpu->uc, cpu->invalid_insn_hook);
        cpu->invalid_insn_hook = 0;
    }
}

void unicorn_set_exception_handler(UnicornCPU *cpu, ExceptionHandler handler) {
    if (!cpu || !cpu->uc) return;

    cpu->exception_handler = handler;

    if (handler && !cpu->invalid_insn_hook) {
        uc_hook_add(cpu->uc, &cpu->invalid_insn_hook, UC_HOOK_INSN_INVALID,
                   (void *)hook_invalid_insn, cpu, 1, 0);
    } else if (!handler && !cpu->emulop_handler && cpu->invalid_insn_hook) {
        uc_hook_del(cpu->uc, cpu->invalid_insn_hook);
        cpu->invalid_insn_hook = 0;
    }
}

void unicorn_set_memory_hook(UnicornCPU *cpu, MemoryHookCallback callback, void *user_data) {
    if (!cpu || !cpu->uc) return;

    cpu->memory_hook = callback;
    cpu->memory_user_data = user_data;

    if (callback) {
        uc_hook_add(cpu->uc, &cpu->mem_hook_handle,
                   UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                   (void *)hook_memory, cpu, 1, 0);
    } else if (cpu->mem_hook_handle) {
        uc_hook_del(cpu->uc, cpu->mem_hook_handle);
        cpu->mem_hook_handle = 0;
    }
}

/* Internal access (for exception handler) */
void* unicorn_get_uc(UnicornCPU *cpu) {
    return cpu ? cpu->uc : NULL;
}

/* Error handling */
const char* unicorn_get_error(UnicornCPU *cpu) {
    return cpu ? cpu->error : "Invalid CPU handle";
}
