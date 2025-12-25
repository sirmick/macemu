# MacEmu Massive Refactor & Cleanup Plan

**Status**: Planning Phase
**Target Completion**: Post-QEMU CPU Integration (Week 4+)
**Scope**: Highly invasive, breaking changes expected

---

## Executive Summary

This document outlines a comprehensive refactor of the macemu codebase to modernize the build system, remove legacy platform support, eliminate deprecated UI code, and streamline the architecture around the web-streaming interface and QEMU CPU integration.

**Key Objectives**:
1. **Platform Support**: Linux, macOS, Windows ONLY (modern versions)
2. **Single Interface**: Web UI only (remove all native GUIs)
3. **Build System**: Complete migration to Meson
4. **CPU Emulation**: Full QEMU CPU integration (replace UAE CPU)
5. **Code Reduction**: ~40-50% reduction in source files

---

## Current State Analysis

### Codebase Size
- **BasiliskII**: 58 MB (567 files across 16 platform dirs)
- **SheepShaver**: 6.0 MB
- **web-streaming**: 8.4 GB (mostly libdatachannel deps)
- **qemu**: 663 MB (full submodule)
- **qemu-cpu**: 28 KB (adapter layer)
- **Total C++ files**: 4,419 files

### Platform Directories (Current)
```
BasiliskII/src/
├── AmigaOS/           ← DELETE (14 files)
├── BeOS/              ← DELETE (18 files)
├── CrossPlatform/     ← KEEP (3 files: sigsegv, vm_alloc, video_blit)
├── dummy/             ← REVIEW
├── include/           ← KEEP
├── IPC/               ← KEEP (new web-streaming protocol)
├── MacOSX/            ← MERGE into unified macOS
├── native_cpu/        ← DELETE (replaced by QEMU)
├── powerrom_cpu/      ← DELETE (replaced by QEMU)
├── SDL/               ← DELETE (web UI only)
├── slirp/             ← KEEP (networking)
├── uae_cpu/           ← DELETE (replaced by QEMU)
├── uae_cpu_2021/      ← DELETE (replaced by QEMU)
├── Unix/              ← MERGE into platform-specific dirs
│   ├── Irix/          ← DELETE
│   ├── Solaris/       ← DELETE
│   ├── FreeBSD/       ← DELETE (unless needed for testing)
│   ├── Linux/         ← KEEP
│   └── Darwin/        ← MERGE into macOS
├── Windows/           ← KEEP (modernize)
└── ...

SheepShaver/src/
├── BeOS/              ← DELETE
├── Unix/Irix/         ← DELETE
└── ... (similar structure)
```

**Files to Delete**: ~56 obsolete platform files + entire directories = ~150-200 files

---

## Phase 1: Platform Code Removal

### 1.1 Delete Obsolete Platforms
**Estimated Effort**: 2-3 days
**Risk Level**: Low (dead code)

**Platforms to Remove**:
- AmigaOS (14 files)
- BeOS (18 files in BasiliskII, more in SheepShaver)
- Irix (Unix/Irix subdirs)
- Solaris (Unix/Solaris subdirs)
- FreeBSD (if not critical)

**Actions**:
```bash
# BasiliskII
rm -rf BasiliskII/src/AmigaOS
rm -rf BasiliskII/src/BeOS
rm -rf BasiliskII/src/Unix/Irix
rm -rf BasiliskII/src/Unix/Solaris
rm -rf BasiliskII/src/Unix/FreeBSD  # Optional

# SheepShaver
rm -rf SheepShaver/src/BeOS
rm -rf SheepShaver/src/Unix/Irix
```

**Build System Cleanup**:
- Remove corresponding configure.ac checks
- Remove Makefile.in platform-specific rules
- Remove IDE project files (Xcode .xcodeproj, Visual Studio .sln/.vcxproj for old platforms)

---

### 1.2 Remove SDL & Native GUI Support
**Estimated Effort**: 3-5 days
**Risk Level**: Medium (affects user workflows)

**UI Code to Remove**:
- All GTK 2/3 prefs editors (15 files found)
- SDL video/audio backends (6 files)
- X11 video_x.cpp
- MacOSX native GUI (Cocoa)
- Windows GDI/DirectX backends

**Files**:
```
BasiliskII/src/Unix/prefs_editor_gtk.cpp
BasiliskII/src/Unix/prefs_editor_gtk3.cpp
BasiliskII/src/Unix/ui/*.ui (GTK UI definitions)
BasiliskII/src/SDL/*.cpp (video_sdl*.cpp, audio_sdl*.cpp)
BasiliskII/src/Unix/video_x.cpp
BasiliskII/src/MacOSX/*.mm (Cocoa GUI)
BasiliskII/src/Windows/prefs_editor_gtk.cpp
```

**Replacement**:
- **Web UI Only**: All configuration via web-streaming/client/
- **IPC Protocol**: Video/audio/input via shared memory (already implemented)

**Dependencies to Remove**:
- GTK+ 2/3 (configure checks, pkg-config)
- SDL 1/2/3 (configure checks, framework detection)
- X11/XFree86 DGA/VidMode extensions
- DirectX (Windows)

---

### 1.3 Consolidate Platform Layers
**Estimated Effort**: 5-7 days
**Risk Level**: High (core functionality)

**Current Structure**:
```
BasiliskII/src/Unix/main_unix.cpp
BasiliskII/src/Windows/main_windows.cpp
BasiliskII/src/MacOSX/... (scattered)
```

**Target Structure**:
```
BasiliskII/src/
├── core/              # Platform-independent emulation
│   ├── cpu/           # QEMU CPU adapter
│   ├── rom/           # ROM patches
│   ├── devices/       # ADB, serial, SCSI, etc.
│   └── ...
├── platform/          # Platform-specific code
│   ├── linux/         # Linux-only code
│   ├── macos/         # macOS-only code (merged Unix/Darwin/MacOSX)
│   └── windows/       # Windows-only code
├── ipc/               # Web-streaming IPC (headless mode)
├── utils/             # Cross-platform utilities (vm_alloc, sigsegv)
└── ...
```

**Merge Strategy**:
- Combine `Unix/`, `Unix/Darwin/`, `MacOSX/` → `platform/macos/`
- Move `Unix/Linux/` → `platform/linux/`
- Keep `Windows/` → `platform/windows/`
- Extract common code → `core/` and `utils/`

---

## Phase 2: QEMU CPU Integration

### 2.1 Remove Old CPU Emulators
**Estimated Effort**: 3-4 days
**Risk Level**: Critical (depends on QEMU completion)

**Directories to Delete** (post-QEMU validation):
```
BasiliskII/src/uae_cpu/         # 68k UAE CPU (~50 files)
BasiliskII/src/uae_cpu_2021/    # 68k UAE CPU 2021 variant
BasiliskII/src/native_cpu/      # Native CPU backend
BasiliskII/src/powerrom_cpu/    # PowerPC ROM CPU
SheepShaver/... (similar)
```

**Dependencies**:
- ✅ Wait for QEMU Week 4 completion
- ✅ Validate execution pipeline
- ✅ Test ROM booting
- ✅ Performance benchmarks

**Replacement**:
- Single `qemu-cpu/` adapter (already ~28KB, minimal)
- Link against QEMU as library
- Remove all JIT compiler build scaffolding (gencpu, gencomp, etc.)

---

### 2.2 Unify CPU Build System
**Estimated Effort**: 2-3 days
**Risk Level**: Medium

**Current**:
- Multiple configure.ac CPU selection flags
- Separate Xcode projects for uae_cpu variants
- Conditional compilation maze

**Target**:
- Single QEMU linkage
- Remove configure flags: `--enable-jit-compiler`, `--enable-addressing`, etc.
- Remove CPU selection logic (always QEMU)

---

## Phase 3: Meson Build System Migration

### 3.1 Why Meson?
- **Modern**: Python-based, cross-platform
- **Fast**: Ninja backend
- **Clean**: No autotools spaghetti (configure.ac = 2000+ lines)
- **QEMU Compatibility**: QEMU already uses Meson (663M of meson.build files)
- **Dependencies**: Native pkg-config, library detection

### 3.2 Migration Strategy
**Estimated Effort**: 7-10 days
**Risk Level**: High (build breakage)

#### Step 1: Create Top-Level `meson.build`
```meson
project('macemu', ['c', 'cpp'],
  version: '2.0.0',
  license: 'GPL-2.0',
  default_options: [
    'cpp_std=c++17',
    'warning_level=2',
    'optimization=2',
  ]
)

# Platform detection
is_linux = host_machine.system() == 'linux'
is_macos = host_machine.system() == 'darwin'
is_windows = host_machine.system() == 'windows'

if not (is_linux or is_macos or is_windows)
  error('Unsupported platform. Only Linux, macOS, and Windows are supported.')
endif

# Subprojects
qemu_proj = subproject('qemu')  # Use QEMU as Meson subproject
libdatachannel_proj = subproject('libdatachannel')

# Subdirectories
subdir('BasiliskII')
subdir('SheepShaver')
subdir('web-streaming')
```

#### Step 2: Per-Module `meson.build`
```
BasiliskII/meson.build
SheepShaver/meson.build
web-streaming/meson.build
```

#### Step 3: Replace Autotools
**Delete**:
```
configure.ac (2000+ lines)
Makefile.in
aclocal.m4
autogen.sh
m4/ macros
config.guess, config.sub
install-sh
```

**Keep** (transition period):
```
configure.ac → meson.build translation reference
README.md build instructions
```

### 3.3 Dependency Detection
**Current** (autotools):
```bash
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_HEADER([SDL2/SDL.h])
PKG_CHECK_MODULES([GTK], [gtk+-3.0])  # Remove
```

**Target** (Meson):
```meson
# Required
thread_dep = dependency('threads')
libssl_dep = dependency('libssl')
libcrypto_dep = dependency('libcrypto')

# web-streaming specific
yuv_dep = dependency('libyuv')
opus_dep = dependency('opus')
openh264_dep = dependency('openh264')
svtav1_dep = dependency('SvtAv1Enc')

# Platform-specific
if is_linux
  rt_dep = dependency('rt')
endif

if is_macos
  corefoundation_dep = dependency('appleframeworks', modules: ['CoreFoundation'])
endif
```

---

### 3.4 Build Targets

#### BasiliskII Binary
```meson
basiliskii_sources = files(
  'src/core/main.cpp',
  'src/core/cpu/qemu_adapter.cpp',
  'src/core/devices/adb.cpp',
  # ... (unified sources)
)

if is_linux
  basiliskii_sources += files('src/platform/linux/sys_linux.cpp')
elif is_macos
  basiliskii_sources += files('src/platform/macos/sys_darwin.cpp')
elif is_windows
  basiliskii_sources += files('src/platform/windows/sys_windows.cpp')
endif

basiliskii = executable('BasiliskII',
  basiliskii_sources,
  dependencies: [qemu_dep, thread_dep, ipc_dep],
  install: true
)
```

#### Web Streaming Server
```meson
webrtc_server = executable('macemu-webrtc',
  files(
    'web-streaming/server/server.cpp',
    'web-streaming/server/h264_encoder.cpp',
    'web-streaming/server/av1_encoder.cpp',
    # ...
  ),
  dependencies: [
    libdatachannel_dep,
    yuv_dep,
    opus_dep,
    openh264_dep,
    svtav1_dep,
  ],
  install: true
)
```

---

### 3.5 Cross-Compilation
Meson natively supports cross-compilation via cross-files:

```ini
# linux-to-windows.cross
[binaries]
c = 'x86_64-w64-mingw32-gcc'
cpp = 'x86_64-w64-mingw32-g++'
ar = 'x86_64-w64-mingw32-ar'
strip = 'x86_64-w64-mingw32-strip'

[host_machine]
system = 'windows'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'
```

**Build**:
```bash
meson setup builddir --cross-file linux-to-windows.cross
meson compile -C builddir
```

---

## Phase 4: Web UI Consolidation

### 4.1 Remove All Local UI Code
**Estimated Effort**: 1-2 days
**Risk Level**: Low (web UI already works)

**Current**:
- GTK prefs editor (multiple versions)
- SDL window management
- X11 keyboard/mouse handling
- Windows message loop

**Target**:
- **Headless only** (IPC mode)
- All input via WebRTC (`web-streaming/server/`)
- All config via web UI (`web-streaming/client/`)

**Benefits**:
- Single codebase for all platforms
- No GUI framework dependencies (GTK, SDL, X11)
- Remote access built-in
- Mobile-friendly UI

---

### 4.2 Storage Manager as Config Backend
**Current**: `web-streaming/server/storage_manager.cpp` (already implemented)

**Functionality**:
- ROM selection
- Disk image management
- Preferences (screen size, RAM, etc.)
- Codec selection (H.264, AV1, PNG)

**Integration**:
- Replace GTK prefs with JSON config files
- Web UI sends config updates via WebRTC data channel
- Server validates and writes to `storage/config.json`

---

## Phase 5: Directory Structure Redesign

### 5.1 Current Problems
- Scattered platform code (Unix/, Windows/, MacOSX/)
- Duplicate files (multiple prefs_editor_*.cpp)
- Deep nesting (BasiliskII/src/Unix/Linux/NetDriver/)
- Unclear separation of concerns

### 5.2 Proposed Structure
```
macemu/
├── meson.build                    # Top-level build
├── meson_options.txt              # Build options
├── README.md
├── LICENSE
│
├── BasiliskII/
│   ├── meson.build
│   └── src/
│       ├── core/                  # Platform-independent
│       │   ├── main.cpp
│       │   ├── cpu/
│       │   │   ├── qemu_adapter.cpp  # Single CPU backend
│       │   │   └── qemu_adapter.h
│       │   ├── devices/
│       │   │   ├── adb.cpp
│       │   │   ├── serial.cpp
│       │   │   ├── scsi.cpp
│       │   │   ├── cdrom.cpp
│       │   │   └── ...
│       │   ├── rom/
│       │   │   ├── rom_patches.cpp
│       │   │   ├── slot_rom.cpp
│       │   │   └── rsrc_patches.cpp
│       │   ├── macos/             # Mac OS emulation
│       │   │   ├── emul_op.cpp
│       │   │   ├── macos_util.cpp
│       │   │   └── ...
│       │   └── ipc/               # Web-streaming IPC
│       │       ├── video_ipc.cpp
│       │       ├── audio_ipc.cpp
│       │       ├── input_ipc.cpp
│       │       └── ipc_protocol.h
│       │
│       ├── platform/              # Platform-specific
│       │   ├── linux/
│       │   │   ├── sys_linux.cpp
│       │   │   ├── timer_linux.cpp
│       │   │   └── scsi_linux.cpp
│       │   ├── macos/
│       │   │   ├── sys_darwin.cpp
│       │   │   ├── timer_macos.cpp
│       │   │   └── audio_macosx.cpp
│       │   └── windows/
│       │       ├── sys_windows.cpp
│       │       ├── timer_windows.cpp
│       │       └── ether_windows.cpp
│       │
│       └── utils/                 # Cross-platform utilities
│           ├── vm_alloc.cpp       # Virtual memory
│           ├── sigsegv.cpp        # Signal handling
│           ├── video_blit.cpp     # Pixel format conversion
│           └── ...
│
├── SheepShaver/
│   ├── meson.build
│   └── src/
│       └── ... (similar structure)
│
├── web-streaming/
│   ├── meson.build
│   ├── server/
│   │   ├── server.cpp
│   │   ├── h264_encoder.cpp
│   │   ├── av1_encoder.cpp
│   │   ├── png_encoder.cpp
│   │   ├── opus_encoder.cpp
│   │   ├── storage_manager.cpp
│   │   └── ...
│   ├── client/
│   │   ├── index.html
│   │   └── app.js
│   └── storage/
│       ├── roms/
│       ├── images/
│       └── config.json
│
├── qemu/                          # QEMU submodule (unchanged)
│   └── ... (663 MB)
│
├── qemu-cpu/                      # QEMU adapter (kept minimal)
│   ├── qemu_m68k_adapter.cpp
│   └── qemu_m68k_adapter.h
│
├── cxmon/                         # Debugger (keep as-is)
│   └── ...
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── BUILD.md                   # Meson build instructions
│   ├── MIGRATION.md               # Refactor migration guide
│   └── qemu/
│       └── ... (QEMU integration docs)
│
└── subprojects/                   # Meson subprojects
    ├── qemu.wrap
    └── libdatachannel.wrap
```

---

### 5.3 Migration Mapping

| Old Path | New Path | Notes |
|----------|----------|-------|
| `BasiliskII/src/Unix/main_unix.cpp` | `BasiliskII/src/core/main.cpp` | Merge with Windows/Mac main |
| `BasiliskII/src/Windows/main_windows.cpp` | (merged) | Platform init → `platform/windows/` |
| `BasiliskII/src/MacOSX/*.cpp` | `platform/macos/` | Merge Darwin + MacOSX |
| `BasiliskII/src/uae_cpu/` | **DELETE** | Replaced by `qemu-cpu/` |
| `BasiliskII/src/IPC/` | `core/ipc/` | Rename for clarity |
| `BasiliskII/src/Unix/prefs_editor_gtk*.cpp` | **DELETE** | Web UI only |
| `BasiliskII/src/SDL/` | **DELETE** | Web UI only |
| `BasiliskII/src/CrossPlatform/` | `utils/` | Rename |

---

## Phase 6: Dependency Cleanup

### 6.1 Remove Dependencies
**GTK+ 2/3**:
- Used only for prefs editor
- **Remove**: All GTK pkg-config checks, UI files

**SDL 1/2/3**:
- Used for video/audio/input
- **Remove**: All SDL configure checks, framework detection

**X11/XFree86**:
- Linux-specific video (DGA, VidMode extensions)
- **Remove**: X11 checks, video_x.cpp

**DirectX (Windows)**:
- Old Windows video backend
- **Remove**: DirectX checks (keep modern Windows APIs only)

**ESD (Enlightenment Sound Daemon)**:
- Ancient Linux audio
- **Remove**: --with-esd configure flag

---

### 6.2 Keep Dependencies
**Core**:
- `libpthread` (threading)
- `librt` (Linux: shared memory, timers)
- `libssl`, `libcrypto` (OpenSSL: WebRTC, crypto)

**Web Streaming**:
- `libdatachannel` (WebRTC)
- `libyuv` (color space conversion)
- `libopus` (audio codec)
- `libopenh264` (H.264 video codec)
- `SvtAv1Enc` (AV1 video codec)

**QEMU**:
- QEMU libraries (built as subproject)
- GLib (QEMU dependency)

**Platform-Specific**:
- macOS: `CoreFoundation`, `CoreAudio`, `IOKit`
- Windows: `ws2_32`, `iphlpapi` (networking)

---

### 6.3 Dependency Management (Meson Wraps)
Meson supports dependency wrapping for missing libraries:

```
subprojects/libdatachannel.wrap
subprojects/qemu.wrap
```

**Fallback**:
```meson
libdatachannel_dep = dependency('libdatachannel',
  fallback: ['libdatachannel', 'libdatachannel_dep'],
  required: true
)
```

---

## Phase 7: Testing & Validation

### 7.1 Test Matrix
| Platform | Build | Boot ROM | Video | Audio | Input | Networking |
|----------|-------|----------|-------|-------|-------|------------|
| Linux x64 | ✅ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| Linux ARM64 | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| macOS x64 | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| macOS ARM64 | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| Windows x64 | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |

### 7.2 Regression Tests
**Critical**:
- ROM boots to desktop (Mac OS 7/8)
- Video refresh works (web UI shows screen)
- Mouse/keyboard input works
- Audio playback works
- Disk images mount
- Networking (SLIRP) works

**Performance**:
- QEMU CPU vs UAE CPU benchmarks
- Frame encoding latency (H.264, AV1, PNG)
- Audio sync drift

**Build**:
- Clean build from scratch
- Incremental rebuild speed
- Cross-compilation (Linux → Windows)

---

### 7.3 Compatibility Breaks
**Expected**:
- Old config files (GTK prefs → JSON migration)
- Command-line flags (SDL-specific options removed)
- Native GUI users (must use web UI)
- Unsupported platforms (AmigaOS, BeOS, etc.)

**Migration Guide**:
```
docs/MIGRATION.md
- Old configure flags → Meson options
- GTK prefs → Web UI workflow
- SDL video → IPC headless mode
```

---

## Implementation Phases

### Timeline (Post-QEMU Week 4)

| Phase | Duration | Effort | Risk | Blocker |
|-------|----------|--------|------|---------|
| **Phase 1**: Platform Removal | 1 week | Medium | Low | None |
| **Phase 2**: QEMU CPU | 1 week | High | Critical | QEMU Week 4 ✅ |
| **Phase 3**: Meson Migration | 2 weeks | Very High | High | Phase 1 |
| **Phase 4**: Web UI Consolidation | 1 week | Low | Low | Phase 1 |
| **Phase 5**: Directory Restructure | 1 week | High | Medium | Phase 1-4 |
| **Phase 6**: Dependency Cleanup | 3 days | Medium | Low | Phase 3 |
| **Phase 7**: Testing & Validation | 2 weeks | High | Critical | All phases |
| **Total** | **~7-8 weeks** | | | |

---

### Phase Execution Order

**Week 1-2**: Foundation Cleanup
1. Delete obsolete platforms (AmigaOS, BeOS, Irix, Solaris)
2. Remove SDL/GTK UI code
3. Validate web UI still works

**Week 3-4**: QEMU Integration
4. Remove UAE CPU code (post-QEMU validation)
5. Unify CPU build system
6. Test QEMU execution pipeline

**Week 5-6**: Meson Migration
7. Create top-level `meson.build`
8. Migrate BasiliskII build
9. Migrate web-streaming build
10. Test cross-platform builds

**Week 7**: Restructure
11. Reorganize directory structure
12. Update include paths
13. Validate incremental builds

**Week 8-9**: Testing
14. Full regression testing
15. Performance benchmarks
16. Documentation updates

---

## Breaking Changes Summary

### For Users
- **No more native GUIs**: Must use web browser
- **No SDL builds**: IPC headless mode only
- **Config migration**: GTK prefs → JSON/web UI
- **Platform drops**: AmigaOS, BeOS, Irix, Solaris, FreeBSD (maybe)

### For Developers
- **Build system**: autotools → Meson
- **CPU emulation**: UAE → QEMU
- **Directory structure**: Flat platform dirs → `core/`, `platform/`, `utils/`
- **Include paths**: Massive changes (all `#include` statements)

### For Packagers
- **New dependencies**: Meson, Ninja
- **Removed dependencies**: GTK, SDL, X11 (optional)
- **Build commands**:
  ```bash
  # Old
  ./configure && make && make install

  # New
  meson setup builddir
  meson compile -C builddir
  meson install -C builddir
  ```

---

## Risk Mitigation

### Critical Risks
1. **QEMU CPU not ready**: Wait for Week 4 completion + validation
2. **Build breaks**: Maintain autotools in parallel during Meson migration
3. **Platform-specific bugs**: Test matrix for Linux/macOS/Windows
4. **Performance regression**: Benchmark QEMU vs UAE before removal

### Rollback Strategy
- **Git branches**: Create `refactor-2.0` branch (do NOT merge to master until validated)
- **Autotools**: Keep configure.ac until Meson proven
- **UAE CPU**: Keep as compile-time option during transition

---

## Success Criteria

### Build System
- ✅ Builds on Linux, macOS, Windows with Meson
- ✅ Cross-compilation works (Linux → Windows)
- ✅ Clean build < 5 minutes (incremental < 30 seconds)
- ✅ No autotools files in repo

### Code Reduction
- ✅ Delete 150-200 files (40-50% reduction in BasiliskII/src)
- ✅ Remove 3-4 CPU emulator directories
- ✅ Single platform layer per OS (no Unix/MacOSX/Darwin split)

### Functionality
- ✅ ROM boots to Mac OS desktop
- ✅ Video/audio/input work via web UI
- ✅ No regressions from current master

### Documentation
- ✅ Updated BUILD.md with Meson instructions
- ✅ MIGRATION.md for users upgrading
- ✅ ARCHITECTURE.md reflects new structure

---

## Open Questions

1. **SheepShaver**: Apply same refactor? (Currently 6.0 MB, similar structure)
2. **FreeBSD**: Keep or remove? (Minor platform, low usage)
3. **JIT**: Remove entirely or keep for future QEMU TCG experiments?
4. **cxmon**: Keep as separate subproject or integrate?
5. **SLIRP**: Keep bundled or use system library?
6. **libdatachannel**: Vendor or system dependency?

---

## Next Steps (Immediate)

1. **Wait for QEMU Week 4 completion** (execution pipeline, ROM boot)
2. **Create `refactor-2.0` branch** (protect master)
3. **Start Phase 1**: Delete obsolete platforms (low-risk, quick wins)
4. **Prototype Meson build**: Start with web-streaming (smallest, cleanest)
5. **Document breaking changes**: User-facing migration guide

---

## Notes

- This is a **planning document**. Execution will adapt as needed.
- **QEMU CPU integration is the critical blocker**. Do not remove UAE CPU until QEMU is production-ready.
- **Test early, test often**. Each phase should have validation milestones.
- **Communicate breaking changes** to users/packagers well in advance.

---

**Document Version**: 1.0
**Last Updated**: 2025-12-24
**Status**: Draft (awaiting review)
