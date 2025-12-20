# IPC Design for Standalone WebRTC Server

Design for moving the WebRTC server to a standalone process that communicates with BasiliskII/SheepShaver via IPC.

## Overview

```
┌─────────────────┐         IPC          ┌─────────────────┐
│   BasiliskII    │◄───────────────────►│  macemu-webrtc  │
│  or SheepShaver │                      │     server      │
└─────────────────┘                      └─────────────────┘
        │                                        │
        ▼                                        ▼
   Mac OS Guest                            Web Browsers
```

## IPC Mechanisms

### Video Frames: POSIX Shared Memory

**Why**: Video is high-bandwidth (~57 MB/s at 800×600×4×30fps). Shared memory provides zero-copy transfer.

**Location**: `/dev/shm/macemu-video`

```cpp
struct SharedVideoBuffer {
    uint32_t magic;                     // 0x4D454D55 "MEMU"
    uint32_t version;                   // Protocol version (1)
    uint32_t width;                     // Frame width in pixels
    uint32_t height;                    // Frame height in pixels
    uint32_t stride;                    // Bytes per row
    std::atomic<uint32_t> write_index;  // Current write buffer (0-2)
    std::atomic<uint32_t> read_index;   // Last read buffer
    std::atomic<uint64_t> frame_count;  // Total frames written
    std::atomic<uint64_t> timestamp_us; // Timestamp of current frame
    uint8_t frames[3][MAX_FRAME_SIZE];  // Triple buffer (RGBA)
};
```

**Triple Buffering**:
- Emulator writes to `(write_index + 1) % 3`
- After write complete, atomically updates `write_index`
- Server reads from `write_index` (never the one being written)
- No locks needed, no tearing, no blocking

### Audio: Shared Memory Ring Buffer

**Why**: Audio is medium-bandwidth (~176 KB/s) but latency-sensitive.

**Location**: `/dev/shm/macemu-audio`

```cpp
struct SharedAudioBuffer {
    uint32_t magic;                     // 0x4D415544 "MAUD"
    uint32_t version;                   // Protocol version (1)
    uint32_t sample_rate;               // e.g., 44100
    uint32_t channels;                  // 1 or 2
    uint32_t format;                    // 0=S16LE, 1=F32LE
    uint32_t buffer_size;               // Ring buffer size in bytes
    std::atomic<uint32_t> write_pos;    // Write position
    std::atomic<uint32_t> read_pos;     // Read position
    uint8_t ring_buffer[65536];         // 64KB ring buffer (~370ms at 44.1kHz stereo)
};
```

**Ring Buffer Protocol**:
- Emulator writes samples, advances `write_pos`
- Server reads samples, advances `read_pos`
- Available data: `(write_pos - read_pos) % buffer_size`
- Lock-free with memory barriers

### Input/Control: Unix Domain Socket

**Why**: Input is low-bandwidth, bidirectional, and event-driven.

**Location**: `/tmp/macemu-control.sock`

**Protocol**: Newline-delimited JSON messages

#### Server → Emulator (Input Events)

```json
{"type": "mouse_move", "x": 100, "y": 200}
{"type": "mouse_button", "x": 100, "y": 200, "button": 0, "pressed": true}
{"type": "key", "code": 65, "pressed": true, "ctrl": false, "alt": false, "shift": false, "meta": false}
{"type": "get_config"}
{"type": "set_config", "config": {"rom": "Quadra.ROM", "ramsize": 16, ...}}
{"type": "restart"}
{"type": "shutdown"}
```

#### Emulator → Server (Responses)

```json
{"type": "config", "data": {"rom": "Quadra.ROM", "ramsize": 16, ...}}
{"type": "storage", "roms": ["Quadra.ROM"], "disks": ["System7.img"]}
{"type": "status", "running": true, "fps": 30}
{"type": "error", "message": "Failed to save config"}
{"type": "ack"}
```

## File Structure

```
web-streaming/
├── libdatachannel/           # WebRTC library (submodule)
├── server/
│   ├── datachannel_webrtc.cpp  # Current monolithic implementation
│   ├── datachannel_webrtc.h
│   ├── ipc_protocol.h          # NEW: Shared memory structures
│   ├── standalone_server.cpp   # NEW: Standalone WebRTC server
│   └── main.cpp                # NEW: Server entry point
├── client/
│   └── ...                     # Unchanged
└── Makefile

BasiliskII/src/SDL/
├── video_sdl2.cpp              # SDL video driver
├── video_headless.cpp          # Current headless driver
└── video_ipc.cpp               # NEW: IPC video driver
```

## Emulator-Side Implementation

### video_ipc.cpp

```cpp
// Shared memory setup
static SharedVideoBuffer* g_video_shm = nullptr;
static SharedAudioBuffer* g_audio_shm = nullptr;
static int g_control_socket = -1;

bool VideoIPC_Init(int width, int height) {
    // Create/open shared memory for video
    int fd = shm_open("/macemu-video", O_CREAT | O_RDWR, 0666);
    ftruncate(fd, sizeof(SharedVideoBuffer));
    g_video_shm = mmap(...);

    // Initialize header
    g_video_shm->magic = 0x4D454D55;
    g_video_shm->version = 1;
    g_video_shm->width = width;
    g_video_shm->height = height;
    g_video_shm->stride = width * 4;

    // Connect to control socket
    g_control_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    connect(g_control_socket, "/tmp/macemu-control.sock");

    // Start input listener thread
    pthread_create(&input_thread, nullptr, input_listener, nullptr);

    return true;
}

void VideoIPC_PushFrame(const uint8_t* rgba, int width, int height) {
    uint32_t next = (g_video_shm->write_index.load() + 1) % 3;
    memcpy(g_video_shm->frames[next], rgba, width * height * 4);
    g_video_shm->frame_count++;
    g_video_shm->timestamp_us = get_timestamp_us();
    g_video_shm->write_index.store(next);
}
```

## Server-Side Implementation

### standalone_server.cpp

```cpp
class StandaloneServer {
    SharedVideoBuffer* video_shm;
    SharedAudioBuffer* audio_shm;
    int control_listen_socket;
    int control_client_socket;

    // WebRTC components (from existing datachannel_webrtc.cpp)
    rtc::WebSocket* signaling_ws;
    std::map<std::string, std::shared_ptr<Peer>> peers;
    VpxEncoder encoder;

public:
    void run() {
        // Open shared memory (read-only for video/audio)
        open_shared_memory();

        // Create control socket (server)
        create_control_socket();

        // Start HTTP server for client files
        start_http_server();

        // Main loop
        while (running) {
            // Check for new video frame
            if (video_shm->write_index != last_frame) {
                encode_and_send_frame();
            }

            // Check for audio data
            if (audio_available()) {
                encode_and_send_audio();
            }

            // Process WebRTC events
            process_webrtc();

            // Forward input to emulator via control socket
            process_input_events();
        }
    }
};
```

## Startup Sequence

1. **Server starts first** (or in parallel):
   ```bash
   macemu-webrtc --port 8000 --signaling-port 8090
   ```
   - Creates shared memory segments
   - Creates control socket (listens)
   - Starts HTTP server
   - Waits for emulator connection

2. **Emulator starts**:
   ```bash
   BasiliskII --ipc-video
   ```
   - Opens shared memory (created by server)
   - Connects to control socket
   - Starts sending frames

3. **Browser connects**:
   - HTTP request → client files
   - WebSocket → signaling
   - WebRTC → video stream

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MACEMU_VIDEO_SHM` | `/macemu-video` | Shared memory name for video |
| `MACEMU_AUDIO_SHM` | `/macemu-audio` | Shared memory name for audio |
| `MACEMU_CONTROL_SOCK` | `/tmp/macemu-control.sock` | Control socket path |
| `BASILISK_ROMS` | `./storage/roms` | ROM directory |
| `BASILISK_IMAGES` | `./storage/images` | Disk image directory |

## Benefits

1. **Process isolation**: WebRTC server can restart without affecting emulator
2. **Shared codebase**: Same server works with BasiliskII and SheepShaver
3. **Resource management**: Server handles encoding load separately
4. **Debugging**: Can run emulator with different video drivers
5. **Testing**: Can test server with synthetic frame generator

## Migration Path

### Phase 1: Add IPC Protocol Header
- Create `ipc_protocol.h` with shared structures
- No functional changes yet

### Phase 2: Create video_ipc.cpp
- New video driver that writes to shared memory
- Control socket client for input
- Test with existing embedded server

### Phase 3: Create Standalone Server
- Extract WebRTC/encoding from datachannel_webrtc.cpp
- Add shared memory reader
- Add control socket server
- Build as separate executable

### Phase 4: Integration
- Add configure option `--enable-ipc-video`
- Update build system
- Documentation
