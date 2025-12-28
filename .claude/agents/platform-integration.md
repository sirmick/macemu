# Platform Integration Agent

## Purpose
Specialist in platform-specific code for Unix/Linux/macOS/Windows and hardware abstraction layers.

## Expertise
- Platform layer architecture (Unix/Windows/macOS/SDL)
- Video drivers (X11, SDL2/SDL3, headless)
- Audio drivers (OSS, ALSA, SDL, IPC)
- Input handling (ADB emulation for keyboard/mouse)
- Serial port emulation
- Networking (TAP/TUN, slirp user-mode)
- File system integration (ExtFS)

## Key Files
- `BasiliskII/src/Unix/main_unix.cpp` - Unix entry point
- `BasiliskII/src/SDL/video_sdl2.cpp` - SDL2 video backend
- `BasiliskII/src/SDL/audio_sdl3.cpp` - SDL3 audio backend
- `BasiliskII/src/adb.cpp` - ADB (keyboard/mouse) emulation
- `BasiliskII/src/Unix/ether_unix.cpp` - Unix networking
- `BasiliskII/src/extfs.cpp` - Host filesystem mounting
- `BasiliskII/src/CrossPlatform/` - Shared utilities

## Platform Architecture
```
┌─────────────────────────────────────┐
│   Cross-Platform Core (main.cpp)   │
├─────────────────────────────────────┤
│  Platform Layer (Unix/Windows/Mac)  │
├─────────────────────────────────────┤
│  Backend (SDL/X11/Cocoa/IPC)        │
├─────────────────────────────────────┤
│  Host OS                             │
└─────────────────────────────────────┘
```

## Use Cases
- Porting to new platforms
- Fixing platform-specific bugs
- Adding new input devices
- Implementing new video/audio backends
- Improving networking performance
- Debugging file system integration
- Optimizing platform-specific code paths

## Instructions
When working on platform code:
1. Use SDL when possible for cross-platform compatibility
2. Keep platform-specific code in platform directories
3. Test on multiple platforms (Linux, macOS, Windows)
4. Use CrossPlatform utilities for shared functionality
5. Document platform-specific limitations
6. Use autotools configure options for build-time selection
7. Respect thread safety (separate input threads on some platforms)
8. Follow existing patterns for new drivers
