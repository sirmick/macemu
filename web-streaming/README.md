# Basilisk II Web Streaming

Browser-based access to Basilisk II running in headless mode using WebRTC.

## Architecture

Uses libdatachannel for WebRTC and libvpx for VP8 video encoding:
- **VP8 encoding** at ~2 Mbps (vs ~300 Mbps for raw RGBA)
- **WebRTC DataChannel** for low-latency keyboard/mouse input
- **Embedded HTTP server** serves the client (no external web server needed)
- **Self-contained** - all dependencies built locally

## Quick Start

```bash
# Install system dependencies
sudo apt install cmake pkg-config libvpx-dev libssl-dev

# Build libdatachannel and streaming library
cd web-streaming
make

# Build Basilisk II with web streaming
cd ../BasiliskII/src/Unix
./configure --enable-webstreaming
make

# Run Basilisk II
./BasiliskII

# Open http://localhost:8000 in your browser
```

## How It Works

### Video Pipeline

1. **Frame Capture**: Mac OS renders to memory buffer (1/2/4/8/16/32-bit color)
2. **RGBA Conversion**: Any depth converted to standard RGBA
3. **VP8 Encoding**: libvpx encodes at 30fps, 2Mbps with realtime settings
4. **RTP Packetization**: Frames split into ~1200 byte packets with RTP headers
5. **WebRTC Delivery**: libdatachannel handles DTLS/SRTP/ICE

### Input Pipeline

1. **Browser Events**: Mouse/keyboard captured on video element
2. **DataChannel**: JSON messages sent via WebRTC DataChannel
3. **ADB Translation**: Browser keycodes → Mac ADB keycodes
4. **Emulator Input**: Injected into Mac OS via ADBMouseMoved/ADBKeyDown

## Directory Structure

```
web-streaming/
├── libdatachannel/     # WebRTC library (git submodule)
├── server/
│   ├── datachannel_webrtc.cpp  # WebRTC + VP8 + HTTP server
│   └── datachannel_webrtc.h    # C API header
├── client/
│   ├── index_datachannel.html  # Browser client HTML
│   └── datachannel_client.js   # Browser client JS
├── build/              # Build output
└── Makefile
```

## Build Targets

| Target | Description |
|--------|-------------|
| `all` | Build everything (default) |
| `libdatachannel` | Build libdatachannel library only |
| `clean` | Remove build files |
| `distclean` | Remove all build files including libdatachannel |
| `deps` | Install system dependencies |
| `deps-check` | Verify dependencies are installed |

## API Reference

```c
// Initialize streaming (starts HTTP on 8000, WebSocket on signaling_port)
bool dc_webrtc_init(int signaling_port);

// Cleanup
void dc_webrtc_exit(void);

// Check if streaming is active
bool dc_webrtc_enabled(void);

// Push a video frame (RGBA format)
void dc_webrtc_push_frame(const uint8_t* rgba_data,
                          int width, int height, int stride);

// Get connected peer count
int dc_webrtc_peer_count(void);

// Set input callbacks
void dc_webrtc_set_input_callbacks(
    dc_mouse_move_cb mouse_move,
    dc_mouse_button_cb mouse_button,
    dc_key_cb key
);
```

## Dependencies

- **libdatachannel** - WebRTC library (built locally as submodule)
- **libvpx** - VP8 video encoder (system package)
- **OpenSSL** - TLS/crypto for DTLS (system package)
- **CMake** - Build system for libdatachannel

## Ports Used

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | HTTP | Client web page |
| 8090 | WebSocket | WebRTC signaling |
| Dynamic | UDP | WebRTC media (ICE negotiated) |
