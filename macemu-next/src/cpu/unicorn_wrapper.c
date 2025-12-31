/**
 * Unicorn Engine Wrapper Implementation
 */

#include "unicorn_wrapper.h"
#include "platform.h"
#include "cpu_trace.h"
#include <unicorn/unicorn.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* MMIO Trap Region for JIT-compatible EmulOp handling */
#define TRAP_REGION_BASE  0xFF000000UL
#define TRAP_REGION_SIZE  0x00001000UL  /* 4KB = 2048 EmulOp slots */

/* Trap context for MMIO approach */
typedef struct {
    uint32_t saved_pc;     /* Original PC where 0x71xx was */
    bool in_emulop;        /* Currently handling EmulOp? */
    bool in_trap;          /* Currently handling A-line/F-line trap? */
    uint16_t trap_opcode;  /* Original trap opcode */
} TrapContext;

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

    uc_hook code_hook;  // UC_HOOK_CODE for EmulOps/traps (allows register modification)
    uc_hook trap_hook;  // UC_HOOK_MEM_FETCH_UNMAPPED for MMIO trap region
    uc_hook trace_hook; // UC_HOOK_MEM_READ for CPU tracing

    /* MMIO trap context */
    TrapContext trap_ctx;
};

/* Helper: Convert uc_err to string and store in cpu->error */
static void set_error(UnicornCPU *cpu, uc_err err) {
    if (err != UC_ERR_OK) {
        snprintf(cpu->error, sizeof(cpu->error), "%s", uc_strerror(err));
    }
}

/* MMIO Trap Handler - called when CPU fetches from unmapped trap region
 * This fires even in JIT mode, making it reliable for EmulOp handling
 */
static void trap_mem_fetch_handler(uc_engine *uc, uc_mem_type type,
                                   uint64_t address, int size,
                                   int64_t value, void *user_data) {
    UnicornCPU *cpu = (UnicornCPU *)user_data;

    /* Verify address is in trap region */
    if (address < TRAP_REGION_BASE ||
        address >= TRAP_REGION_BASE + TRAP_REGION_SIZE) {
        fprintf(stderr, "ERROR: Unexpected unmapped fetch at 0x%08lx\n", address);
        return;
    }

    if (!cpu->trap_ctx.in_emulop && !cpu->trap_ctx.in_trap) {
        fprintf(stderr, "WARNING: Trap region access without INSN_INVALID at 0x%08lx\n", address);
        return;
    }

    /* Handle EmulOp */
    if (cpu->trap_ctx.in_emulop) {
        /* Calculate EmulOp number from trap address */
        uint32_t emulop_num = (address - TRAP_REGION_BASE) / 2;
        uint16_t opcode = 0x7100 + emulop_num;

        /* Call platform EmulOp handler (same as UAE uses) */
        if (g_platform.emulop_handler) {
            bool pc_advanced = g_platform.emulop_handler(opcode, false);

            /* Restore PC to instruction AFTER the 0x71xx */
            uint32_t next_pc = cpu->trap_ctx.saved_pc + (pc_advanced ? 0 : 2);
            uc_reg_write(uc, UC_M68K_REG_PC, &next_pc);

            cpu->trap_ctx.in_emulop = false;
            return;
        }
    }

    /* Handle A-line/F-line trap */
    if (cpu->trap_ctx.in_trap) {
        uint16_t opcode = cpu->trap_ctx.trap_opcode;
        int vector = ((opcode & 0xF000) == 0xA000) ? 0xA : 0xB;

        if (g_platform.trap_handler) {
            g_platform.trap_handler(vector, opcode, false);
            /* Handler manages PC, just clear trap flag */
            cpu->trap_ctx.in_trap = false;
            return;
        }
    }

    fprintf(stderr, "ERROR: Trap handler not available for address 0x%08lx\n", address);
}

/* Invalid instruction hook for EmulOp/trap handling
 * NOTE: Requires m68k_stop_interrupt() patch in Unicorn (see external/unicorn/qemu/target/m68k/unicorn.c)
 */
/* CODE hook - called BEFORE each instruction executes
 * This allows register modifications to persist (unlike INSN_INVALID hook)
 * Fast-path: Only checks opcodes that look like EmulOps/traps (0x7xxx, 0xAxxx, 0xFxxx)
 *
 * NOTE: This function is non-static so it can be registered from cpu_unicorn.cpp
 * for Unicorn-only mode (which uses platform handlers instead of per-CPU handlers)
 */
void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    UnicornCPU *cpu = (UnicornCPU *)user_data;
    uint32_t pc = (uint32_t)address;
    uint16_t opcode;

    /* Read opcode at PC */
    uc_mem_read(uc, pc, &opcode, sizeof(opcode));

    /* M68K is big-endian, swap if needed */
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    opcode = __builtin_bswap16(opcode);
    #endif

    /* Fast path: Skip normal instructions */
    uint8_t opcode_high = (opcode >> 12) & 0xF;
    if (opcode_high != 0x7 && opcode_high != 0xA && opcode_high != 0xF) {
        return;  // Not an EmulOp or trap, continue normally
    }

    /* Check platform handlers first (g_platform declared in platform.h) */

    /* Check if EmulOp (0x71xx for M68K) */
    if ((opcode & 0xFF00) == 0x7100) {
        if (g_platform.emulop_handler) {
            /* Platform handler - pass is_primary=false for Unicorn */
            bool pc_advanced = g_platform.emulop_handler(opcode, false);

            /* Sync ALL registers back from platform to Unicorn after EmulOp */
            /* This is necessary for Unicorn-only mode where platform == Unicorn */
            if (g_platform.cpu_get_dreg && g_platform.cpu_get_areg) {
                for (int i = 0; i < 8; i++) {
                    uint32_t d = g_platform.cpu_get_dreg(i);
                    uint32_t a = g_platform.cpu_get_areg(i);
                    uc_reg_write(uc, UC_M68K_REG_D0 + i, &d);
                    uc_reg_write(uc, UC_M68K_REG_A0 + i, &a);
                }
                if (g_platform.cpu_get_sr) {
                    uint16_t sr = g_platform.cpu_get_sr();
                    uc_reg_write(uc, UC_M68K_REG_SR, &sr);
                }
            }

            /* Advance past EmulOp only if handler didn't */
            if (!pc_advanced) {
                pc += 2;
                uc_reg_write(uc, UC_M68K_REG_PC, &pc);
            }

            /* IMPORTANT: Stop emulation to let register writes take effect
             * UC_HOOK_CODE is called BEFORE instruction execution, so:
             * 1. Handler modifies registers (A7, etc.)
             * 2. We write them to Unicorn here
             * 3. uc_emu_stop() exits cleanly
             * 4. Next uc_emu_start() generates new TB with updated registers
             * This is the ONLY way to make register modifications persist in Unicorn.
             */
            uc_emu_stop(uc);
            return;
        }
        /* Fallback to per-CPU handler */
        if (cpu->emulop_handler) {
            cpu->emulop_handler(opcode, cpu->emulop_user_data);
            pc += 2;
            uc_reg_write(uc, UC_M68K_REG_PC, &pc);
            uc_emu_stop(uc);
            return;
        }
    }

    /* Check for A-line trap (0xAxxx) */
    if ((opcode & 0xF000) == 0xA000) {
        if (g_platform.trap_handler) {
            /* Platform handler - pass is_primary=false for Unicorn */
            g_platform.trap_handler(0xA, opcode, false);
            /* Handler handles PC advancement for traps */
            uc_emu_stop(uc);
            return;
        }
        /* Fallback to per-CPU handler */
        if (cpu->exception_handler) {
            cpu->exception_handler(cpu, 10, opcode);
            uc_emu_stop(uc);
            return;
        }
    }

    /* Check for F-line trap (0xFxxx) */
    if ((opcode & 0xF000) == 0xF000) {
        if (g_platform.trap_handler) {
            /* Platform handler - pass is_primary=false for Unicorn */
            g_platform.trap_handler(0xB, opcode, false);
            /* Handler handles PC advancement for traps */
            uc_emu_stop(uc);
            return;
        }
        /* Fallback to per-CPU handler */
        if (cpu->exception_handler) {
            cpu->exception_handler(cpu, 11, opcode);
            uc_emu_stop(uc);
            return;
        }
    }

    /* Not an EmulOp/trap we handle - let it execute normally */
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

/* Memory read trace hook for CPU_TRACE_MEMORY */
static void hook_mem_trace(uc_engine *uc, uc_mem_type type,
                           uint64_t address, int size, int64_t value,
                           void *user_data)
{
    /* Only trace reads */
    if (type != UC_MEM_READ) return;

    /* Read the actual value from memory */
    uint32_t val = 0;
    uc_mem_read(uc, address, &val, size);

    /* Byte-swap if needed (M68K is big-endian) */
    if (size == 2) {
        val = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
    } else if (size == 4) {
        val = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
              ((val & 0xFF0000) >> 8) | ((val >> 24) & 0xFF);
    }

    cpu_trace_log_mem_read((uint32_t)address, val, size);
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

    /* Register MMIO trap hook for JIT-compatible EmulOp/trap handling */
    /* IMPORTANT: Don't map the trap region - leave it unmapped! */
    err = uc_hook_add(cpu->uc, &cpu->trap_hook,
                     UC_HOOK_MEM_FETCH_UNMAPPED,
                     trap_mem_fetch_handler,
                     cpu,  /* user_data */
                     TRAP_REGION_BASE,
                     TRAP_REGION_BASE + TRAP_REGION_SIZE - 1);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to register MMIO trap hook: %s\n", uc_strerror(err));
        uc_close(cpu->uc);
        free(cpu);
        return NULL;
    }

    /* Initialize trap context */
    cpu->trap_ctx.saved_pc = 0;
    cpu->trap_ctx.in_emulop = false;
    cpu->trap_ctx.in_trap = false;
    cpu->trap_ctx.trap_opcode = 0;

    /* Install memory trace hook if CPU_TRACE_MEMORY is enabled */
    if (cpu_trace_memory_enabled()) {
        err = uc_hook_add(cpu->uc, &cpu->trace_hook,
                         UC_HOOK_MEM_READ,
                         hook_mem_trace,
                         cpu,  /* user_data */
                         1, 0);  /* All addresses */
        if (err != UC_ERR_OK) {
            fprintf(stderr, "Warning: Failed to register memory trace hook: %s\n", uc_strerror(err));
            /* Not fatal - continue without memory tracing */
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

bool unicorn_map_rom_writable(UnicornCPU *cpu, uint64_t addr, const void *host_ptr, uint64_t size) {
    if (!cpu || !cpu->uc) return false;

    /* ROM mapped as writable for validation/debugging (BasiliskII patches ROM during boot) */
    uc_err err = uc_mem_map(cpu->uc, addr, size, UC_PROT_ALL);
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
        /* Check for illegal instruction (EmulOps and traps) */
        if (err == UC_ERR_INSN_INVALID && cpu->arch == UCPU_ARCH_M68K) {
            /* Read opcode at PC */
            uint16_t opcode;
            if (uc_mem_read(cpu->uc, (uint32_t)pc, &opcode, sizeof(opcode)) == UC_ERR_OK) {
                /* M68K is big-endian, swap if needed */
                #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
                opcode = __builtin_bswap16(opcode);
                #endif

                static int illegal_count = 0;
                if (illegal_count < 10 || illegal_count > 3685) {
                    fprintf(stderr, "[ILLEGAL #%d] PC=0x%08X opcode=0x%04X\n",
                           illegal_count, (uint32_t)pc, opcode);
                }
                illegal_count++;

                /* MMIO Trap Approach: Redirect PC to unmapped region */

                /* Handle EmulOp (0x71xx) via MMIO trap */
                if ((opcode & 0xFF00) == 0x7100) {
                    /* Save original PC */
                    cpu->trap_ctx.saved_pc = (uint32_t)pc;
                    cpu->trap_ctx.in_emulop = true;

                    /* Calculate trap address in unmapped region */
                    uint32_t emulop_num = opcode & 0xFF;
                    uint32_t trap_addr = TRAP_REGION_BASE + (emulop_num * 2);

                    /* Redirect PC to trap region */
                    uint64_t trap_addr_64 = trap_addr;
                    uc_reg_write(cpu->uc, UC_M68K_REG_PC, &trap_addr_64);

                    /* Resume execution - will trigger UC_HOOK_MEM_FETCH_UNMAPPED */
                    err = uc_emu_start(cpu->uc, trap_addr, 0xFFFFFFFFFFFFFFFFULL, 0, 1);

                    /* Trap handler executed, check if successful */
                    return (err == UC_ERR_OK || !cpu->trap_ctx.in_emulop);
                }

                /* Handle A-line trap (0xAxxx) via MMIO trap */
                if ((opcode & 0xF000) == 0xA000) {
                    cpu->trap_ctx.saved_pc = (uint32_t)pc;
                    cpu->trap_ctx.in_trap = true;
                    cpu->trap_ctx.trap_opcode = opcode;

                    /* Use offset 0x800 in trap region for A-line traps */
                    uint32_t trap_addr = TRAP_REGION_BASE + 0x800;
                    uint64_t trap_addr_64 = trap_addr;
                    uc_reg_write(cpu->uc, UC_M68K_REG_PC, &trap_addr_64);

                    err = uc_emu_start(cpu->uc, trap_addr, 0xFFFFFFFFFFFFFFFFULL, 0, 1);
                    return (err == UC_ERR_OK || !cpu->trap_ctx.in_trap);
                }

                /* Handle F-line trap (0xFxxx) via MMIO trap */
                if ((opcode & 0xF000) == 0xF000) {
                    cpu->trap_ctx.saved_pc = (uint32_t)pc;
                    cpu->trap_ctx.in_trap = true;
                    cpu->trap_ctx.trap_opcode = opcode;

                    /* Use offset 0x900 in trap region for F-line traps */
                    uint32_t trap_addr = TRAP_REGION_BASE + 0x900;
                    uint64_t trap_addr_64 = trap_addr;
                    uc_reg_write(cpu->uc, UC_M68K_REG_PC, &trap_addr_64);

                    err = uc_emu_start(cpu->uc, trap_addr, 0xFFFFFFFFFFFFFFFFULL, 0, 1);
                    return (err == UC_ERR_OK || !cpu->trap_ctx.in_trap);
                }
            }
        }

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

/* Registers - M68K control registers */
uint32_t unicorn_get_cacr(UnicornCPU *cpu) {
    if (!cpu || !cpu->uc) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_M68K_REG_CR_CACR, &value);
    return value;
}

void unicorn_set_cacr(UnicornCPU *cpu, uint32_t value) {
    if (!cpu || !cpu->uc) return;
    uc_reg_write(cpu->uc, UC_M68K_REG_CR_CACR, &value);
}

uint32_t unicorn_get_vbr(UnicornCPU *cpu) {
    if (!cpu || !cpu->uc) return 0;
    uint32_t value;
    uc_reg_read(cpu->uc, UC_M68K_REG_CR_VBR, &value);
    return value;
}

void unicorn_set_vbr(UnicornCPU *cpu, uint32_t value) {
    if (!cpu || !cpu->uc) return;
    uc_reg_write(cpu->uc, UC_M68K_REG_CR_VBR, &value);
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

    if (handler && !cpu->code_hook) {
        /* Use UC_HOOK_CODE - called BEFORE instruction execution
         * This allows register modifications to persist (unlike INSN_INVALID)
         * Fast-path filtering in hook_code() keeps overhead minimal */
        fprintf(stderr, "[UNICORN] Registering UC_HOOK_CODE for EmulOp handling\n");
        uc_hook_add(cpu->uc, &cpu->code_hook, UC_HOOK_CODE,
                   (void *)hook_code, cpu, 1, 0);
    } else if (!handler && !cpu->exception_handler && cpu->code_hook) {
        fprintf(stderr, "[UNICORN] Unregistering UC_HOOK_CODE\n");
        uc_hook_del(cpu->uc, cpu->code_hook);
        cpu->code_hook = 0;
    }
}

void unicorn_set_exception_handler(UnicornCPU *cpu, ExceptionHandler handler) {
    if (!cpu || !cpu->uc) return;

    cpu->exception_handler = handler;

    if (handler && !cpu->code_hook) {
        /* Use UC_HOOK_CODE for trap handling */
        uc_hook_add(cpu->uc, &cpu->code_hook, UC_HOOK_CODE,
                   (void *)hook_code, cpu, 1, 0);
    } else if (!handler && !cpu->emulop_handler && cpu->code_hook) {
        uc_hook_del(cpu->uc, cpu->code_hook);
        cpu->code_hook = 0;
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
