# QEMU Build Dependencies for macemu

This document tracks all the build dependencies needed to compile QEMU as part of the macemu project.

## Purpose

We're integrating QEMU's m68k and PPC CPU emulation into BasiliskII and SheepShaver to gain:
- ARM64 JIT support
- Better CPU maintenance (QEMU team maintains it)
- Modern TCG compiler infrastructure

## QEMU Version

- **Repository**: https://github.com/qemu/qemu.git
- **Location**: `macemu/qemu/` (git submodule)
- **Version**: v10.2.0+ (latest mainline)
- **Targets**: `m68k-softmmu`, `ppc-softmmu`

## Build Dependencies

### Essential Build Tools

```bash
sudo apt-get install -y \
    build-essential \
    git \
    ninja-build \
    pkg-config
```

### Python Environment

QEMU requires Python 3.8+ with venv support:

```bash
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv
```

### Required Libraries

```bash
sudo apt-get install -y \
    libglib2.0-dev \
    libpixman-1-dev \
    zlib1g-dev
```

### Optional Libraries (for minimal build, may be needed)

```bash
# Check if these are actually required during configure:
sudo apt-get install -y \
    libfdt-dev \
    libcap-ng-dev
```

## QEMU Configure Options

We use a minimal configuration targeting only what we need:

```bash
cd qemu
./configure \
    --target-list=m68k-softmmu,ppc-softmmu \
    --enable-debug \
    --disable-docs \
    --disable-guest-agent \
    --disable-tools \
    --disable-vnc \
    --disable-gtk \
    --disable-sdl \
    --disable-curses \
    --disable-slirp \
    --disable-spice \
    --disable-qom-cast-debug \
    --without-default-devices
```

### What This Disables

- **--disable-docs**: No documentation generation (saves sphinx dependency)
- **--disable-guest-agent**: No QEMU guest agent
- **--disable-tools**: No qemu-img, qemu-nbd, etc. (we only need the CPU)
- **--disable-vnc/gtk/sdl/curses**: No UI (we have our own)
- **--disable-slirp**: No network emulation
- **--disable-spice**: No SPICE protocol
- **--without-default-devices**: Minimal device set (we use EmulOps)

### What We Keep

- **TCG (JIT compiler)**: Enabled by default
- **softmmu**: Full system mode with supervisor/user privilege levels
- **Debug symbols**: `--enable-debug` for development

## Build Process

```bash
# After configure succeeds:
cd qemu/build
ninja
```

Expected build time: ~5-10 minutes on modern hardware

## Build Artifacts

After successful build:

```
qemu/build/
├── qemu-system-m68k       # m68k CPU emulator (we'll link against this)
├── qemu-system-ppc        # PPC CPU emulator (for SheepShaver)
├── libqemu-m68k-softmmu.fa.p/
└── libqemu-ppc-softmmu.fa.p/
```

We'll extract the CPU core libraries from these builds.

## Integration Plan

1. **Phase 1**: Build QEMU successfully ✓ (in progress)
2. **Phase 2**: Create patches for illegal instruction hooks (~30 lines)
3. **Phase 3**: Link QEMU libraries into BasiliskII/SheepShaver
4. **Phase 4**: Create adapter layer (qemu_cpu_adapter.cpp)
5. **Phase 5**: DualCPU testing harness

## Troubleshooting

### Missing glib-2.0

```
ERROR: Dependency "glib-2.0" not found
```

**Solution**:
```bash
sudo apt-get install libglib2.0-dev
```

### Missing ninja

```
ERROR: Cannot find Ninja
```

**Solution**:
```bash
sudo apt-get install ninja-build
```

### Python venv error

```
ERROR: python venv creation failed
```

**Solution**:
```bash
sudo apt-get install python3-venv
```

### Missing pixman

```
ERROR: Dependency "pixman-1" not found
```

**Solution**:
```bash
sudo apt-get install libpixman-1-dev
```

## Quick Install All Dependencies

For Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    git \
    ninja-build \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    libglib2.0-dev \
    libpixman-1-dev \
    zlib1g-dev
```

### Installation Status (2024-12-24)

✅ **All dependencies installed successfully**:
- python3-venv
- ninja-build
- libglib2.0-dev
- libpixman-1-dev

✅ **QEMU configure completed successfully**

✅ **QEMU build completed successfully**

Build artifacts:
- `/home/mick/macemu/qemu/build/qemu-system-m68k` (22 MB)
- `/home/mick/macemu/qemu/build/qemu-system-ppc` (25 MB)

Version: QEMU emulator version 10.2.50 (v10.2.0-1-g8dd5bceb2f)

## Next Steps

Now that QEMU builds successfully:
1. ✅ Test basic execution: Both binaries work correctly
2. ✅ Created illegal instruction hook patches (see `qemu-patches/README.md`)
3. **Next**: Apply patches and rebuild QEMU
4. **Then**: Build proof-of-concept adapter

## Notes

- QEMU uses Meson build system (bundled in python wheels)
- We're building QEMU as a library, not a standalone emulator
- The `--without-default-devices` flag significantly reduces build size
- Debug symbols (`--enable-debug`) are useful during development, can be removed for release

## Last Updated

2024-12-24 - Initial dependency documentation
