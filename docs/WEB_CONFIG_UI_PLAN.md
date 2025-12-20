# Web Configuration UI Plan

Add a browser-based configuration interface to the WebRTC streaming client.

## Overview

Allow users to configure Basilisk II settings via the web UI, with changes saved to a prefs file that takes effect on restart.

## Storage Directory

A configurable storage directory (default: `./storage/` relative to executable, or `BASILISK_STORAGE` env var) contains:
- ROM files (`*.rom`, `*.ROM`)
- Disk images (`*.img`, `*.dsk`, `*.hfv`, `*.iso`)

The server scans this directory and provides lists to the UI via API.

## API Endpoints

### GET /api/config
Returns current configuration as JSON:
```json
{
  "rom": "Quadra700.ROM",
  "disks": ["System7.img", "Apps.img"],
  "ramsize": 16,
  "screen": {"width": 800, "height": 600},
  "cpu": 4,
  "fpu": true,
  "modelid": 14,
  "jit": true,
  "sound": true,
  "frameskip": 2
}
```

### GET /api/storage
Returns available files in storage directory:
```json
{
  "roms": ["Quadra700.ROM", "Performa.ROM"],
  "disks": ["System7.img", "Apps.img", "Games.iso"],
  "path": "/home/user/storage"
}
```

### POST /api/config
Saves configuration. Body is same format as GET response.
Returns: `{"success": true}` or `{"error": "message"}`

Note: Changes require emulator restart to take effect.

## Settings to Support

### Essential

| Setting | Pref Key | UI Element | Values |
|---------|----------|------------|--------|
| ROM | `rom` | Dropdown | Scanned from storage/*.rom |
| Disk Images | `disk` | Multi-select list | Scanned from storage/*.img |
| RAM Size | `ramsize` | Dropdown | 8, 16, 32, 64, 128, 256, 512 MB |
| Resolution | `screen` | Dropdown | 640x480, 800x600, 1024x768, 1280x1024 |

### Advanced (collapsible)

| Setting | Pref Key | UI Element | Values |
|---------|----------|------------|--------|
| CPU Type | `cpu` | Dropdown | 68020, 68030, 68040 |
| FPU | `fpu` | Checkbox | Enable 68881 FPU |
| Mac Model | `modelid` | Dropdown | 5=Mac II, 14=Quadra 900, etc. |
| JIT | `jit` | Checkbox | Enable JIT compiler |
| Sound | `nosound` | Checkbox (inverted) | Enable sound |
| Frame Skip | `frameskip` | Dropdown | 0, 1, 2, 4, 8 |

## UI Design

```
+------------------------------------------+
|  [Basilisk II]              [Settings]   |
+------------------------------------------+
|                                          |
|                                          |
|           <video stream>                 |
|                                          |
|                                          |
+------------------------------------------+
|  Status: Connected | FPS: 30 | Peers: 1  |
+------------------------------------------+

Settings Panel (slide-in from right or modal):
+------------------------------------------+
|  Settings                           [X]  |
+------------------------------------------+
|                                          |
|  ROM File                                |
|  [Quadra700.ROM                    ▼]   |
|                                          |
|  Disk Images                             |
|  [✓] System7.img                         |
|  [ ] Apps.img                            |
|  [ ] Games.iso                           |
|                                          |
|  RAM Size                                |
|  [16 MB                            ▼]   |
|                                          |
|  Resolution                              |
|  [800 x 600                        ▼]   |
|                                          |
|  ▶ Advanced Settings                     |
|  +--------------------------------------+|
|  | CPU: [68040 ▼]  FPU: [✓]            ||
|  | Model: [Quadra 900 ▼]               ||
|  | JIT: [✓]  Sound: [✓]                ||
|  +--------------------------------------+|
|                                          |
|  [Save & Restart]                        |
|                                          |
|  Note: Changes require restart           |
+------------------------------------------+
```

## Implementation

### Backend Changes (datachannel_webrtc.cpp)

1. Add storage directory scanning:
```cpp
std::vector<std::string> scan_storage_files(const char* extension);
std::string get_storage_path();
```

2. Add config read/write:
```cpp
std::string read_config_json();
bool write_config_from_json(const std::string& json);
```

3. Add HTTP route handling in `handle_http_request()`:
```cpp
if (path == "/api/config" && method == "GET") { ... }
if (path == "/api/config" && method == "POST") { ... }
if (path == "/api/storage" && method == "GET") { ... }
```

4. Prefs file location:
- Default: `~/.basilisk_ii_prefs` or `basilisk_ii_prefs` in current dir
- Can be overridden with `BASILISK_PREFS` env var

### Frontend Changes (embedded HTML/JS)

1. Add settings button to header
2. Add settings panel/modal HTML
3. Add JavaScript:
   - `loadConfig()` - GET /api/config
   - `loadStorage()` - GET /api/storage
   - `saveConfig()` - POST /api/config
   - UI event handlers for form elements

### File Format

Standard Basilisk II prefs format:
```
rom /path/to/storage/Quadra700.ROM
disk /path/to/storage/System7.img
disk /path/to/storage/Apps.img
ramsize 16777216
screen win/800/600
cpu 4
fpu true
modelid 14
jit true
nosound false
frameskip 2
```

## Mac Model IDs

| ID | Model |
|----|-------|
| 5 | Mac II |
| 6 | Mac IIx |
| 7 | Mac IIcx |
| 11 | Mac IIci |
| 13 | Mac IIfx |
| 14 | Quadra 900 |
| 18 | Quadra 700 |

## Milestones

### Phase 1: Backend API
- [ ] Add storage directory scanning
- [ ] Add GET /api/config endpoint
- [ ] Add GET /api/storage endpoint
- [ ] Add POST /api/config endpoint
- [ ] Write prefs file in standard format

### Phase 2: Frontend UI
- [ ] Add settings button
- [ ] Add settings panel HTML
- [ ] Populate dropdowns from /api/storage
- [ ] Load current config on open
- [ ] Save config and show restart message

### Phase 3: Polish
- [ ] Add validation (ROM required, etc.)
- [ ] Add error handling/display
- [ ] Style improvements
- [ ] Test across browsers
