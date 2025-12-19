# WebRTC Streaming for Basilisk II

This document describes the WebRTC streaming feature that allows running Basilisk II in headless mode and accessing it through a web browser.

## Overview

Basilisk II supports browser-based access via WebRTC streaming. The implementation uses:

- **libdatachannel** - Lightweight C++ WebRTC library for signaling and media transport
- **libvpx** - VP8 video encoding (~2 Mbps vs ~300 Mbps for raw RGBA)
- **WebRTC DataChannel** - Low-latency mouse/keyboard input
- **Embedded HTTP server** - No external web server needed

## Architecture

```
+------------------------------------------------------------------+
|                        Basilisk II                                |
|  +------------------+     +------------------------------------+  |
|  | video_headless   |---->| datachannel_webrtc.cpp             |  |
|  | (frame buffer)   |     | +--------------------------------+ |  |
|  +------------------+     | | VP8 Encoder (libvpx)           | |  |
|                           | | - RGBA to I420 conversion      | |  |
|                           | | - 2 Mbps realtime encoding     | |  |
|                           | +--------------------------------+ |  |
|                           | +--------------------------------+ |  |
|                           | | WebRTC (libdatachannel)        | |  |
|                           | | - RTP packetization            | |  |
|                           | | - DTLS/SRTP encryption         | |  |
|                           | | - ICE connectivity             | |  |
|                           | +--------------------------------+ |  |
|                           | +--------------------------------+ |  |
|                           | | Signaling Server (port 8090)   | |  |
|                           | | HTTP Server (port 8000)        | |  |
|                           | +--------------------------------+ |  |
|                           +------------------------------------+  |
+------------------------------------------------------------------+
                                    |
                           WebRTC + DataChannel
                                    v
+------------------------------------------------------------------+
|                         Web Browser                               |
|  +------------------------+     +------------------------------+  |
|  | datachannel_client.js  |---->| <video> element              |  |
|  | - WebSocket signaling  |     | - VP8 decode (browser)       |  |
|  | - RTCPeerConnection    |     | - Hardware accelerated       |  |
|  | - Input capture        |     +------------------------------+  |
|  +------------------------+                                       |
+------------------------------------------------------------------+
```

## Quick Start

### 1. Install Dependencies

```bash
sudo apt install cmake pkg-config libvpx-dev libssl-dev
```

### 2. Build

```bash
# Build web-streaming library (includes libdatachannel)
cd web-streaming
make

# Build Basilisk II with streaming
cd ../BasiliskII/src/Unix
./configure --enable-webstreaming
make
```

### 3. Run

```bash
./BasiliskII
# Open http://localhost:8000 in your browser
```

The emulator serves the web client automatically on port 8000.

## Ports Used

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | HTTP | Embedded web server (client files) |
| 8090 | WebSocket | WebRTC signaling |
| Dynamic | UDP | WebRTC media (ICE negotiated) |

## HTTPS/WSS Support

When accessing the emulator through an HTTPS proxy, the browser requires WSS (WebSocket Secure) for the signaling connection.

### Option 1: Use HTTP

Access via plain HTTP which doesn't require WSS:
```
http://your-server:8000/
```

### Option 2: Enable TLS

Set environment variables pointing to your TLS certificate before running:

```bash
export BASILISK_WSS_CERT=/path/to/fullchain.pem
export BASILISK_WSS_KEY=/path/to/privkey.pem
./BasiliskII
```

This enables WSS on port 8090 for HTTPS compatibility.

### Option 3: Reverse Proxy

Configure nginx/Apache to proxy WebSocket connections through HTTPS.

## Input Handling

Mouse and keyboard events are sent via WebRTC DataChannel:

- **Mouse movement** - Coordinates scaled to video dimensions, throttled to ~30/sec
- **Mouse buttons** - Left (0), Middle (1), Right (2)
- **Keyboard** - JavaScript keyCodes mapped to Mac ADB scancodes

### Supported Keys

- Letters A-Z
- Numbers 0-9
- Arrow keys
- Enter, Tab, Escape, Backspace, Delete, Space
- Modifier keys (Shift, Ctrl->Command, Alt->Option, Meta->Command)
- Common punctuation

## Configuration

### Basilisk II Preferences

Add to your config file:
```
webstreamingport 8090
screen win/800/600
```

### Video Quality

Default VP8 settings in `datachannel_webrtc.cpp`:
- Target bitrate: 2 Mbps
- Keyframe interval: 15 frames (~2 per second)
- CPU preset: 8 (fastest/realtime)

## Troubleshooting

### Black screen / No video

- Check browser console (F12) for WebRTC errors
- Verify the emulator is running and rendering frames
- Check `[VP8]` stats in emulator console - should show fps > 0

### Connection fails

- Ensure ports 8000 and 8090 are not blocked
- Check for WebSocket errors in browser console
- For HTTPS, ensure WSS is configured (see above)

### Input lag

- DataChannel uses unreliable mode for low latency
- Mouse moves are throttled to prevent congestion
- Check `[Input]` stats in browser console

### High CPU usage

- VP8 encoding is CPU-intensive at high resolutions
- Consider reducing resolution in preferences
- Check `[VP8] enc=` time in console (should be < 30ms)

## Development

### Directory Structure

```
web-streaming/
+-- libdatachannel/     # WebRTC library (git submodule)
+-- server/
|   +-- datachannel_webrtc.cpp  # Main implementation
|   +-- datachannel_webrtc.h    # C API header
+-- client/
|   +-- index_datachannel.html  # Embedded in binary
|   +-- datachannel_client.js   # Embedded in binary
+-- build/              # Build output
+-- Makefile
```

### Build Targets

| Target | Description |
|--------|-------------|
| `all` | Build everything |
| `libdatachannel` | Build libdatachannel only |
| `clean` | Remove build files |
| `distclean` | Remove all including libdatachannel build |
| `deps` | Install system dependencies |
| `deps-check` | Verify dependencies |

### API Reference

```c
// Initialize (starts HTTP on 8000, signaling on port)
bool dc_webrtc_init(int signaling_port);

// Shutdown
void dc_webrtc_exit(void);

// Check if active
bool dc_webrtc_enabled(void);

// Push video frame (RGBA format)
void dc_webrtc_push_frame(const uint8_t* rgba, int w, int h, int stride);

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

- **libdatachannel** - Built locally as git submodule
- **libvpx** - System package (`libvpx-dev`)
- **OpenSSL** - System package (`libssl-dev`)
- **CMake** - Build system for libdatachannel

## See Also

- [libdatachannel](https://github.com/paullouisageneau/libdatachannel)
- [libvpx](https://www.webmproject.org/code/)
- [WebRTC API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API)
