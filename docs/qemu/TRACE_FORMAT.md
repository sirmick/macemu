# CPU Execution Trace Format

## Binary Trace Format (for performance)

Each trace entry is a fixed-size structure for fast writing:

```c
// Version 1.0 - 128 bytes per entry
struct TraceEntry_v1 {
    uint64_t seq_number;        // Sequential instruction number
    uint32_t pc;                // Program counter
    uint32_t opcode;            // Raw instruction bytes (4 bytes for PPC, 2-10 for m68k)

    // CPU state AFTER instruction execution
    uint32_t registers[16];     // D0-D7/A0-A7 or R0-R15
    uint32_t sr_ccr;            // Status/Condition register
    uint32_t sp;                // Stack pointer

    // Memory access tracking (if any)
    uint8_t  mem_access_type;   // 0=none, 1=read, 2=write, 3=both
    uint32_t mem_address;
    uint32_t mem_value;
    uint8_t  mem_size;          // 1, 2, or 4 bytes

    // Exception/trap info
    uint8_t  exception;         // 0=none, 1-255=exception number
    uint8_t  is_emulop;         // 1 if EmulOp/NativeOp
    uint16_t emulop_selector;

    uint8_t  padding[48];       // Reserved for future use
} __attribute__((packed));
```

## Text Trace Format (for debugging/analysis)

Human-readable format for post-mortem analysis:

```
[0000000001] PC=00000100 SR=2700 D0=00000000 D1=00000000 ... A7=00001000
             OPCODE: 4e71           NOP

[0000000002] PC=00000102 SR=2700 D0=00001234 D1=00000000 ... A7=00001000
             OPCODE: 303c1234       MOVE.W  #$1234,D0

[0000000003] PC=00000106 SR=2700 D0=00001234 D1=00000000 ... A7=00000ffc
             OPCODE: 48e7fffe       MOVEM.L D1-D7/A0-A6,-(A7)
             MEM_W: 00000ffc = d1d2d3d4 (multi-word write)

[0000000004] PC=0000010a SR=2700 D0=00001234 ... A7=00000ffc
             OPCODE: 4e42           TRAP    #2
             EXCEPTION: Vector 34 (TRAP #2)
```

## Differential Trace (comparing two traces)

```
DIVERGENCE at instruction 42,891:

LEGACY (UAE):
  [0000042891] PC=0040a3c2 SR=2004 D0=00000001 D1=0040a000 ...
               OPCODE: 51c8fffc       DBF D0,$40a3c0

QEMU:
  [0000042891] PC=0040a3c2 SR=2004 D0=00000001 D1=0040a000 ...
               OPCODE: 51c8fffc       DBF D0,$40a3c0

DIVERGENCE POINT:
  - Legacy PC after: 0040a3c0  (branch taken)
  - QEMU PC after:   0040a3c4  (branch NOT taken)
  - Reason: DBcc condition evaluation differs
```

## Compression

For long traces, use:
- LZ4 compression on binary traces (5-10x compression)
- Index files for fast seeking to specific instructions
