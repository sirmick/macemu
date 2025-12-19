# WebRTC Streaming for Basilisk II

This document describes the WebRTC streaming feature that allows running Basilisk II in headless mode and accessing it through a web browser.

## Overview

Basilisk II supports two streaming backends for headless operation:

1. **WebRTC (Recommended)** - Uses GStreamer's webrtcsink for hardware-accelerated VP9 encoding with WebRTC delivery
2. **WebSocket (Legacy)** - Direct raw RGBA frame streaming over WebSocket

WebRTC is preferred because it provides:
- Hardware-accelerated video encoding (VP9)
- Adaptive bitrate control
- Lower bandwidth usage (~1-2 Mbps vs ~300+ Mbps for raw RGBA)
- Standard browser APIs (no custom JavaScript needed for decoding)
- DataChannel for low-latency input

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Basilisk II                               │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │ video_headless.cpp│────▶│ gstreamer_webrtc.cpp              │  │
│  │  (frame buffer)  │     │ ┌──────────────────────────────┐ │  │
│  └──────────────────┘     │ │ GStreamer Pipeline           │ │  │
│                           │ │ appsrc → videoconvert →      │ │  │
│                           │ │ vp9enc → webrtcsink          │ │  │
│                           │ └──────────────────────────────┘ │  │
│                           │ ┌──────────────────────────────┐ │  │
│                           │ │ Built-in Signaling Server    │ │  │
│                           │ │ (WebSocket on port 8090)     │ │  │
│                           │ └──────────────────────────────┘ │  │
│                           └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                    │
                           WebRTC + DataChannel
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Web Browser                              │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │ webrtc_client.js │────▶│ <video> element                   │  │
│  │ (signaling +     │     │ (VP9 decode + display)            │  │
│  │  input handling) │     └──────────────────────────────────┘  │
│  └──────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### System Packages (Ubuntu/Debian)

```bash
# Core GStreamer packages
sudo apt install \
    gstreamer1.0-tools \
    gstreamer1.0-plugins-base \
    gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad \
    libgstreamer1.0-dev \
    libgstreamer-plugins-base1.0-dev \
    libgstreamer-plugins-bad1.0-dev

# WebRTC sink plugin (Ubuntu 24.04+)
sudo apt install gstreamer1.0-plugins-rs
```

### Building webrtcsink from Source

If `gstreamer1.0-plugins-rs` is not available in your distribution:

```bash
# Install Rust if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs.git
cd gst-plugins-rs
cargo build --release -p gst-plugin-webrtc

# Install the plugin
sudo cp target/release/libgstrswebrtc.so /usr/lib/x86_64-linux-gnu/gstreamer-1.0/
```

### Verify Installation

```bash
# Check if webrtcsink is available
gst-inspect-1.0 webrtcsink

# Should show element details, not "No such element or plugin"
```

## Building Basilisk II with WebRTC

```bash
cd BasiliskII/src/Unix
./autogen.sh
./configure --enable-webrtc
make
```

The configure script will check for:
- GStreamer 1.0+ with app and webrtc libraries
- Note: webrtcsink plugin availability is only checked at runtime

## Running

```bash
# Start the emulator in headless mode
./BasiliskII --config ~/.basilisk_headless.cfg

# Default streaming port is 8090
# Override with: --webstreamingport 9000
```

### Accessing from Browser

1. Serve the web client files:
   ```bash
   cd web-streaming/client
   python3 -m http.server 8000
   ```

2. Open in browser: `http://localhost:8000/index_webrtc.html`

3. Click "Connect" to establish the WebRTC connection

### URL Parameters

- `?server=ws://host:port` - Custom signaling server URL
- `?port=8090` - Signaling server port
- `?autoconnect` - Connect automatically on page load

## Input Handling

Mouse and keyboard events are sent from the browser to Basilisk II via WebRTC DataChannel:

- **Mouse movement** - Sent as relative coordinates scaled to video dimensions
- **Mouse buttons** - Left (0), Middle (1), Right (2)
- **Keyboard** - JavaScript keyCodes mapped to Mac ADB scancodes

### Supported Keys

- Letters A-Z
- Numbers 0-9
- Arrow keys
- Enter, Tab, Escape, Backspace, Delete, Space
- Modifier keys (Shift, Ctrl→Command, Alt→Option, Meta→Command)
- Common punctuation

## Hardware Acceleration

The streaming backend automatically detects and uses hardware VP9 encoders:

1. **VA-API (vavp9enc)** - Intel/AMD (newer API)
2. **VAAPI (vaapivp9enc)** - Intel/AMD (older API)
3. **Software (vp9enc)** - Fallback, works everywhere

Check which encoder is being used in the console output:
```
GStreamer WebRTC: Using VA-API VP9 encoder (vavp9enc)
```

## Configuration

### Basilisk II Preferences

Add to your config file:
```
webstreamingport 8090
screen win/800/600
```

### Adjusting Quality

The default VP9 settings prioritize low latency:
- Target bitrate: 2 Mbps
- Keyframe interval: 30 frames
- CPU usage preset: 4 (balanced)

These are configured in `gstreamer_webrtc.cpp` and can be adjusted for different network conditions.

## Troubleshooting

### "webrtcsink not found"

The GStreamer Rust plugins package is missing. Install `gstreamer1.0-plugins-rs` or build from source.

### Video stuttering

- Check network bandwidth (WebRTC target is ~2 Mbps)
- Try a wired connection instead of WiFi
- Reduce resolution in Basilisk II preferences

### Input lag

- DataChannel is configured for low latency (unreliable mode)
- Ensure you're connecting to localhost or low-latency network

### Black screen after connect

- Check console for GStreamer errors
- Verify the emulator has started and is rendering
- Try refreshing the browser page

### Connection fails immediately

- Ensure port 8090 (or custom port) is not blocked by firewall
- Check that no other application is using the port

## Development

### Testing the GStreamer Pipeline

A standalone test harness is provided:

```bash
cd web-streaming
make deps-webrtc
make check-webrtc  # Verify dependencies
make test_gstreamer
./build/test_gstreamer -p 8090
```

This generates an animated test pattern without needing the full emulator.

### Modifying the Pipeline

The GStreamer pipeline is constructed in `gstreamer_webrtc.cpp`:

```cpp
"appsrc name=src format=time is-live=true do-timestamp=true "
"caps=video/x-raw,format=RGBA,width=640,height=480,framerate=30/1 ! "
"queue max-size-buffers=2 leaky=downstream ! "
"videoconvert ! "
"video/x-raw,format=I420 ! "
"vp9enc deadline=1 cpu-used=4 target-bitrate=2000000 keyframe-max-dist=30 ! "
"webrtcsink name=sink run-signalling-server=true ..."
```

## See Also

- [GStreamer webrtcsink documentation](https://gstreamer.freedesktop.org/documentation/rswebrtc/webrtcsink.html)
- [gst-plugins-rs repository](https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs)
- [WebRTC API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API)
