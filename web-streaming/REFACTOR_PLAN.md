# Server.cpp Refactoring Plan

## Executive Summary

The current `server.cpp` is **3,023 lines** and contains multiple responsibilities that make it difficult for LLMs to process and humans to maintain. This plan breaks it into **15-20 focused modules** with clear separation of concerns.

## Goals

1. **LLM-Friendly**: Each file under 500 lines, focused on single responsibility
2. **Maintainable**: Clear module boundaries, minimal coupling
3. **Testable**: Pure functions and classes that can be unit tested
4. **Compatible**: Maintain GPL licensing, use compatible dependencies
5. **Functional**: Zero behavior changes, drop-in replacement

## Current State Analysis

### File Statistics
- **Total Lines**: 3,023
- **Classes**: 3 (WebRTCServer, HTTPServer, PeerConnection)
- **Global Variables**: 69+
- **Functions**: 40+
- **Complexity**: Very High (nested loops, mixed responsibilities)

### Major Issues
1. **Global State Pollution**: 69+ global variables make testing impossible
2. **Monolithic Classes**: WebRTCServer (872 lines), HTTPServer (379 lines)
3. **Mixed Responsibilities**: IPC, HTTP, WebRTC, encoding all interleaved
4. **Deep Nesting**: Video loop has 5+ levels of nesting
5. **Tight Coupling**: Everything depends on everything via globals

## New Dependencies

### 1. JSON Library: nlohmann/json (Already Available!)
- **Location**: `libdatachannel/deps/json/include/nlohmann/json.hpp`
- **License**: MIT (GPL-compatible)
- **Features**: Modern C++ API, header-only, widely used
- **Usage**: Replace hand-written JSON parsing with proper library

### 2. HTTP Framework: cpp-httplib (Lightweight, Header-Only)
- **License**: MIT (GPL-compatible)
- **Size**: Single header file (~10k lines)
- **Features**:
  - HTTP/HTTPS server
  - WebSocket support
  - Route handlers
  - Static file serving
  - Thread pool
- **Why**: Current HTTP server is 379 lines of manual socket handling
- **Alternative**: Keep custom HTTP (it's simple enough), focus on refactoring structure

**Decision**: For Phase 1, keep custom HTTP but extract into focused modules. Consider cpp-httplib for Phase 2 if needed.

## Module Structure

```
web-streaming/server/
├── main.cpp                          # Entry point (~150 lines)
├── config/
│   ├── server_config.h/cpp          # Configuration management
│   └── debug_flags.h                # Debug flag definitions
├── utils/
│   ├── json_utils.h/cpp             # JSON helpers (using nlohmann)
│   └── keyboard_map.h/cpp           # Browser to Mac keycode mapping
├── ipc/
│   ├── connection_manager.h/cpp     # Unified IPC connection
│   ├── shm_connection.h/cpp         # Shared memory management
│   ├── socket_connection.h/cpp      # Unix socket management
│   ├── input_protocol.h/cpp         # Input message sending
│   └── emulator_scanner.h/cpp       # Emulator discovery
├── emulator/
│   ├── process_manager.h/cpp        # Lifecycle management
│   └── status_monitor.h/cpp         # Status checking
├── storage/
│   ├── file_scanner.h/cpp           # Directory scanning
│   └── prefs_manager.h/cpp          # Prefs file I/O
├── http/
│   ├── http_server.h/cpp            # HTTP infrastructure
│   ├── api_handlers.h/cpp           # API endpoint implementations
│   └── static_files.h/cpp           # Static file serving
├── webrtc/
│   ├── signaling_server.h/cpp       # WebSocket signaling
│   ├── peer_manager.h/cpp           # Peer connection lifecycle
│   ├── track_factory.h/cpp          # RTP track setup
│   ├── frame_sender.h/cpp           # Frame encoding and sending
│   └── input_handler.h/cpp          # Binary/text input protocol
├── processing/
│   ├── video_loop.h/cpp             # Video processing thread
│   └── audio_loop.h/cpp             # Audio processing thread
└── encoders/                         # Already extracted!
    ├── codec.h
    ├── h264_encoder.h/cpp
    ├── av1_encoder.h/cpp
    ├── png_encoder.h/cpp
    └── opus_encoder.h/cpp
```

## Phased Refactoring Plan

### Phase 1: Extract Pure Utilities (Low Risk)
**Goal**: Extract self-contained functions with no dependencies

#### 1.1 JSON Utilities (`utils/json_utils.h/cpp`)
- Replace hand-written JSON parsing with nlohmann/json
- Create wrapper functions for common operations
- **Lines**: ~100 lines

```cpp
// Example API
namespace json_utils {
    nlohmann::json parse(const std::string& str);
    std::string get_string(const nlohmann::json& j, const std::string& key, const std::string& default_val = "");
    int get_int(const nlohmann::json& j, const std::string& key, int default_val = 0);
    std::string to_string(const nlohmann::json& j);
}
```

#### 1.2 Keyboard Mapping (`utils/keyboard_map.h/cpp`)
- Extract `browser_to_mac_keycode()` function
- **Lines**: ~80 lines

```cpp
namespace keyboard_map {
    int browser_to_mac_keycode(int browser_keycode);
}
```

**Testing**: Unit tests for each utility

---

### Phase 2: Extract Configuration (Low Risk)
**Goal**: Centralize configuration and eliminate global config variables

#### 2.1 Server Configuration (`config/server_config.h/cpp`)
- **Lines**: ~150 lines

```cpp
struct ServerConfig {
    // Network
    int http_port = 8000;
    int signaling_port = 8090;
    bool enable_stun = false;
    std::string stun_server = "stun:stun.l.google.com:19302";

    // Paths
    std::string roms_path = "storage/roms";
    std::string images_path = "storage/images";
    std::string prefs_path = "basilisk_ii.prefs";
    std::string emulator_path;

    // Behavior
    bool auto_start_emulator = true;
    pid_t target_emulator_pid = 0;
    CodecType server_codec = CodecType::PNG;

    // Debug flags
    bool debug_connection = false;
    bool debug_mode_switch = false;
    bool debug_perf = false;
    bool debug_frames = false;
    bool debug_audio = false;

    // Methods
    void parse_command_line(int argc, char* argv[]);
    void load_from_env();
    void print_summary() const;
};
```

#### 2.2 Debug Flags (`config/debug_flags.h`)
- Header-only debug flag definitions
- **Lines**: ~30 lines

---

### Phase 3: Extract IPC Layer (Medium Risk)
**Goal**: Encapsulate all emulator communication in one module

#### 3.1 IPC Connection Manager (`ipc/connection_manager.h/cpp`)
- **Lines**: ~300 lines
- **Responsibilities**:
  - Unified interface for SHM + socket + eventfds
  - Connection lifecycle (connect, disconnect, reconnect)
  - Status queries

```cpp
class IPCConnectionManager {
public:
    bool connect_to_emulator(pid_t pid);
    void disconnect();
    bool is_connected() const;

    // Access
    MacEmuIPCBuffer* get_shm();
    int get_frame_eventfd() const;
    int get_audio_eventfd() const;

    // Input sending
    bool send_key_input(uint8_t flags, uint8_t mac_keycode, uint8_t modifiers);
    bool send_mouse_input(uint8_t flags, int16_t x, int16_t y, uint8_t buttons, uint32_t timestamp_ms);
    bool send_command(uint8_t command);
    bool send_ping(uint32_t browser_timestamp_ms);

private:
    // Split into sub-components
    SHMConnection shm_;
    SocketConnection socket_;
    int frame_eventfd_ = -1;
    int audio_eventfd_ = -1;
};
```

#### 3.2 Emulator Scanner (`ipc/emulator_scanner.h/cpp`)
- **Lines**: ~150 lines
- Scan /dev/shm for running emulators
- Validate and connect to emulator

```cpp
class EmulatorScanner {
public:
    struct EmulatorInfo {
        pid_t pid;
        std::string shm_name;
        std::string socket_path;
        uint32_t width, height;
        bool is_valid;
    };

    std::vector<EmulatorInfo> scan_for_emulators();
    bool try_connect(pid_t pid, IPCConnectionManager& conn);
};
```

---

### Phase 4: Extract Emulator Lifecycle (Medium Risk)
**Goal**: Separate process management from server logic

#### 4.1 Process Manager (`emulator/process_manager.h/cpp`)
- **Lines**: ~250 lines

```cpp
class EmulatorProcessManager {
public:
    EmulatorProcessManager(const ServerConfig& config);

    bool start();
    bool stop(bool force = false);
    bool restart();

    int check_status();  // Returns: 0=running, -1=not running, >0=exit code
    pid_t get_pid() const;

private:
    const ServerConfig& config_;
    pid_t pid_ = -1;

    std::string find_emulator_executable();
};
```

---

### Phase 5: Extract Storage & Prefs (Medium Risk)
**Goal**: File I/O and configuration management

#### 5.1 File Scanner (`storage/file_scanner.h/cpp`)
- **Lines**: ~200 lines

```cpp
class FileScanner {
public:
    FileScanner(const std::string& base_path);

    nlohmann::json scan_roms(bool recursive = true);
    nlohmann::json scan_disk_images(bool recursive = true);
    nlohmann::json get_storage_json();

private:
    std::string base_path_;
    std::vector<FileInfo> scan_directory(const std::string& path, bool recursive);
};
```

#### 5.2 Prefs Manager (`storage/prefs_manager.h/cpp`)
- **Lines**: ~150 lines

```cpp
class PrefsManager {
public:
    PrefsManager(const std::string& prefs_path);

    std::string read();
    bool write(const std::string& content);
    bool create_minimal_if_needed();
    CodecType read_webcodec_pref();

private:
    std::string prefs_path_;
};
```

---

### Phase 6: Split HTTP Server (High Risk)
**Goal**: Separate routing, API, and static files

#### 6.1 HTTP Server Infrastructure (`http/http_server.h/cpp`)
- **Lines**: ~250 lines
- Socket handling, request parsing, routing

```cpp
class HTTPServer {
public:
    HTTPServer(int port, APIHandlers& api, StaticFileServer& files);

    bool start();
    void stop();
    void run();  // Accept loop

private:
    int port_;
    int server_fd_ = -1;
    APIHandlers& api_;
    StaticFileServer& files_;

    void handle_client(int client_fd);
    void route_request(const std::string& method, const std::string& path,
                       const std::string& body, int client_fd);
};
```

#### 6.2 API Handlers (`http/api_handlers.h/cpp`)
- **Lines**: ~300 lines
- All `/api/*` endpoint implementations

```cpp
class APIHandlers {
public:
    APIHandlers(ServerConfig& config,
                IPCConnectionManager& ipc,
                EmulatorProcessManager& emulator,
                FileScanner& storage,
                PrefsManager& prefs);

    std::string handle_status();
    std::string handle_config();
    std::string handle_storage();
    std::string handle_prefs_get();
    std::string handle_prefs_post(const std::string& body);
    std::string handle_emulator_start();
    std::string handle_emulator_stop();
    std::string handle_emulator_restart();
    std::string handle_log(const std::string& body);
    std::string handle_error(const std::string& body);

private:
    ServerConfig& config_;
    IPCConnectionManager& ipc_;
    EmulatorProcessManager& emulator_;
    FileScanner& storage_;
    PrefsManager& prefs_;
};
```

#### 6.3 Static File Server (`http/static_files.h/cpp`)
- **Lines**: ~150 lines

```cpp
class StaticFileServer {
public:
    StaticFileServer(const std::string& root_dir);

    bool serve_file(const std::string& path, int client_fd);

private:
    std::string root_dir_;
    std::string get_mime_type(const std::string& path);
};
```

---

### Phase 7: Split WebRTC Server (Very High Risk)
**Goal**: Break 872-line monster into focused components

#### 7.1 Signaling Server (`webrtc/signaling_server.h/cpp`)
- **Lines**: ~300 lines
- WebSocket server for signaling
- Protocol parsing and validation

```cpp
class SignalingServer {
public:
    using OnConnectCallback = std::function<void(const std::string& peer_id, const nlohmann::json& params)>;
    using OnAnswerCallback = std::function<void(const std::string& peer_id, const std::string& sdp)>;
    using OnCandidateCallback = std::function<void(const std::string& peer_id, const std::string& candidate, const std::string& mid)>;

    bool init(int port);
    void shutdown();

    void set_on_connect(OnConnectCallback cb);
    void set_on_answer(OnAnswerCallback cb);
    void set_on_candidate(OnCandidateCallback cb);

    void send_offer(const std::string& peer_id, const std::string& sdp);

private:
    int port_;
    std::shared_ptr<rtc::WebSocketServer> ws_server_;

    OnConnectCallback on_connect_;
    OnAnswerCallback on_answer_;
    OnCandidateCallback on_candidate_;

    void handle_message(const std::string& peer_id, const std::string& message);
};
```

#### 7.2 Peer Manager (`webrtc/peer_manager.h/cpp`)
- **Lines**: ~250 lines
- Manage peer lifecycle
- Track active connections by codec

```cpp
struct PeerConnection {
    std::string id;
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::Track> video_track;
    std::shared_ptr<rtc::Track> audio_track;
    std::shared_ptr<rtc::DataChannel> data_channel;
    CodecType codec;
    bool needs_first_frame = true;
    bool ice_connected = false;
    std::chrono::steady_clock::time_point created_at;
};

class PeerManager {
public:
    void add_peer(const std::string& id, std::shared_ptr<PeerConnection> peer);
    void remove_peer(const std::string& id);
    void disconnect_all();

    std::shared_ptr<PeerConnection> get_peer(const std::string& id);
    std::vector<std::shared_ptr<PeerConnection>> get_peers_by_codec(CodecType codec);

    size_t count() const;
    size_t count_by_codec(CodecType codec) const;
    bool has_codec_peer(CodecType codec) const;

private:
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<PeerConnection>> peers_;
};
```

#### 7.3 Track Factory (`webrtc/track_factory.h/cpp`)
- **Lines**: ~200 lines
- Create and configure RTP tracks

```cpp
class TrackFactory {
public:
    std::shared_ptr<rtc::Track> create_h264_track(std::shared_ptr<rtc::PeerConnection> pc, int width, int height);
    std::shared_ptr<rtc::Track> create_av1_track(std::shared_ptr<rtc::PeerConnection> pc, int width, int height);
    std::shared_ptr<rtc::Track> create_opus_track(std::shared_ptr<rtc::PeerConnection> pc);

private:
    void setup_h264_packetizer(rtc::Description::Video& video);
    void setup_av1_packetizer(rtc::Description::Video& video);
    void setup_opus_packetizer(rtc::Description::Audio& audio);
};
```

#### 7.4 Frame Sender (`webrtc/frame_sender.h/cpp`)
- **Lines**: ~300 lines
- Encode and send frames to peers

```cpp
class FrameSender {
public:
    FrameSender(PeerManager& peers, const ServerConfig& config);

    void send_h264_frame(const EncodedFrame& frame);
    void send_av1_frame(const EncodedFrame& frame);
    void send_png_frame(const EncodedFrame& frame, uint64_t timestamp_us, const std::vector<DirtyRect>& dirty_rects);
    void send_audio_frame(const std::vector<uint8_t>& opus_data, uint32_t timestamp);

private:
    PeerManager& peers_;
    const ServerConfig& config_;
};
```

#### 7.5 Input Handler (`webrtc/input_handler.h/cpp`)
- **Lines**: ~200 lines
- Parse binary/text input from DataChannel

```cpp
class InputHandler {
public:
    InputHandler(IPCConnectionManager& ipc);

    void handle_binary(const std::byte* data, size_t size);
    void handle_text(const std::string& message);

private:
    IPCConnectionManager& ipc_;

    void handle_mouse_move(const uint8_t* data);
    void handle_mouse_button(const uint8_t* data);
    void handle_keyboard(const uint8_t* data);
    void handle_ping(const uint8_t* data);
};
```

---

### Phase 8: Extract Processing Loops (Highest Risk)
**Goal**: Isolate video/audio threads

#### 8.1 Video Loop (`processing/video_loop.h/cpp`)
- **Lines**: ~400 lines
- Encapsulate video processing state machine

```cpp
class VideoProcessingLoop {
public:
    VideoProcessingLoop(ServerConfig& config,
                        IPCConnectionManager& ipc,
                        EmulatorProcessManager& emulator,
                        EmulatorScanner& scanner,
                        FrameSender& sender);

    void run();  // Thread entry point
    void request_stop();

private:
    ServerConfig& config_;
    IPCConnectionManager& ipc_;
    EmulatorProcessManager& emulator_;
    EmulatorScanner& scanner_;
    FrameSender& sender_;

    std::atomic<bool> running_{true};

    // Encoders
    std::unique_ptr<H264VideoEncoder> h264_encoder_;
    std::unique_ptr<AV1VideoEncoder> av1_encoder_;
    std::unique_ptr<PNGEncoder> png_encoder_;

    void process_frame();
    void handle_reconnection();
};
```

#### 8.2 Audio Loop (`processing/audio_loop.h/cpp`)
- **Lines**: ~200 lines

```cpp
class AudioProcessingLoop {
public:
    AudioProcessingLoop(IPCConnectionManager& ipc, FrameSender& sender);

    void run();  // Thread entry point
    void request_stop();

private:
    IPCConnectionManager& ipc_;
    FrameSender& sender_;
    std::atomic<bool> running_{true};

    std::unique_ptr<OpusAudioEncoder> encoder_;

    void process_audio();
};
```

---

### Phase 9: New Main Entry Point
**Goal**: Wire everything together, eliminate globals

#### 9.1 Main (`main.cpp`)
- **Lines**: ~250 lines

```cpp
int main(int argc, char* argv[]) {
    // 1. Configuration
    ServerConfig config;
    config.parse_command_line(argc, argv);
    config.load_from_env();

    // 2. Signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // 3. Create components
    IPCConnectionManager ipc;
    EmulatorScanner scanner;
    EmulatorProcessManager emulator(config);
    FileScanner storage(config.roms_path);
    PrefsManager prefs(config.prefs_path);

    // 4. HTTP server
    APIHandlers api(config, ipc, emulator, storage, prefs);
    StaticFileServer static_files("client");
    HTTPServer http_server(config.http_port, api, static_files);

    // 5. WebRTC server
    PeerManager peer_manager;
    TrackFactory track_factory;
    FrameSender frame_sender(peer_manager, config);
    InputHandler input_handler(ipc);
    SignalingServer signaling;

    // Wire up signaling callbacks
    signaling.set_on_connect([&](const std::string& peer_id, const nlohmann::json& params) {
        // Create peer, add tracks, etc.
    });

    // 6. Processing loops
    VideoProcessingLoop video_loop(config, ipc, emulator, scanner, frame_sender);
    AudioProcessingLoop audio_loop(ipc, frame_sender);

    // 7. Start threads
    std::thread http_thread([&]() { http_server.run(); });
    std::thread video_thread([&]() { video_loop.run(); });
    std::thread audio_thread([&]() { audio_loop.run(); });

    // 8. Wait for shutdown
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 9. Cleanup
    video_loop.request_stop();
    audio_loop.request_stop();
    http_server.stop();

    video_thread.join();
    audio_thread.join();
    http_thread.join();

    return 0;
}
```

---

## Migration Strategy

### Step 1: Create Skeleton
1. Create all header files with class definitions
2. Add empty implementations
3. Update Makefile to compile new files
4. Ensure it builds (linking to old server.cpp for now)

### Step 2: Extract Phase by Phase
1. Implement one phase at a time
2. Move code from server.cpp to new modules
3. Update server.cpp to use new modules
4. Test after each phase

### Step 3: Eliminate Globals
1. Pass dependencies through constructors
2. Remove global variables one by one
3. Use references/pointers for shared state

### Step 4: Final Cutover
1. Rename old server.cpp to server_old.cpp.bak
2. Ensure new main.cpp has all functionality
3. Remove backup after testing

---

## Testing Strategy

### Unit Tests (New)
- Each utility module (json_utils, keyboard_map)
- Configuration parsing
- Prefs file I/O
- File scanning

### Integration Tests
- IPC connection lifecycle
- Emulator process management
- HTTP API endpoints
- WebRTC signaling flow

### System Tests
- Full end-to-end streaming
- Browser client connection
- Frame encoding/decoding
- Input latency measurement

### Regression Tests
- Compare behavior with old server.cpp
- Verify all API endpoints work
- Check performance metrics

---

## Makefile Updates

```makefile
# New source structure
SERVER_SRCS = server/main.cpp \
              server/config/server_config.cpp \
              server/utils/json_utils.cpp \
              server/utils/keyboard_map.cpp \
              server/ipc/connection_manager.cpp \
              server/ipc/shm_connection.cpp \
              server/ipc/socket_connection.cpp \
              server/ipc/input_protocol.cpp \
              server/ipc/emulator_scanner.cpp \
              server/emulator/process_manager.cpp \
              server/storage/file_scanner.cpp \
              server/storage/prefs_manager.cpp \
              server/http/http_server.cpp \
              server/http/api_handlers.cpp \
              server/http/static_files.cpp \
              server/webrtc/signaling_server.cpp \
              server/webrtc/peer_manager.cpp \
              server/webrtc/track_factory.cpp \
              server/webrtc/frame_sender.cpp \
              server/webrtc/input_handler.cpp \
              server/processing/video_loop.cpp \
              server/processing/audio_loop.cpp \
              server/h264_encoder.cpp \
              server/av1_encoder.cpp \
              server/opus_encoder.cpp \
              server/png_encoder.cpp \
              server/fpng.cpp

# Add nlohmann/json include path
SERVER_CFLAGS = -I../BasiliskII/src/IPC \
                -Ilibdatachannel/include \
                -Ilibdatachannel/deps/json/include \
                -msse4.1 -mpclmul \
                -I/usr/include/svt-av1 -DEB_DLL
```

---

## Benefits Summary

### For LLMs
- **Focused Context**: Each file under 500 lines
- **Clear Purpose**: Single responsibility per module
- **Self-Contained**: Minimal cross-file dependencies

### For Humans
- **Navigability**: Easy to find relevant code
- **Understandability**: Clear module boundaries
- **Maintainability**: Changes localized to modules

### For Testing
- **Unit Testable**: Pure functions and isolated classes
- **Mockable**: Dependency injection enables mocking
- **Verifiable**: Each module can be tested independently

### For Build System
- **Parallel Builds**: More object files = better parallelism
- **Incremental Builds**: Changes only rebuild affected modules
- **Link-Time Optimization**: Better optimization opportunities

---

## Risks and Mitigations

### Risk: Introducing Bugs
- **Mitigation**: Phase-by-phase migration with testing after each phase
- **Mitigation**: Keep old server.cpp as backup
- **Mitigation**: Extensive regression testing

### Risk: Performance Degradation
- **Mitigation**: Use references/pointers, not copies
- **Mitigation**: Benchmark before/after
- **Mitigation**: Profile and optimize hot paths

### Risk: Increased Complexity
- **Mitigation**: Clear documentation for each module
- **Mitigation**: Dependency diagram
- **Mitigation**: Consistent coding style

### Risk: Breaking Build
- **Mitigation**: Keep Makefile updated
- **Mitigation**: CI/CD pipeline
- **Mitigation**: Build after each phase

---

## Timeline Estimate

| Phase | Complexity | Estimated Time | Dependencies |
|-------|------------|----------------|--------------|
| Phase 1: Utilities | Low | 2-4 hours | None |
| Phase 2: Config | Low | 2-3 hours | Phase 1 |
| Phase 3: IPC | Medium | 6-8 hours | Phase 1, 2 |
| Phase 4: Emulator | Medium | 4-6 hours | Phase 2, 3 |
| Phase 5: Storage | Medium | 4-6 hours | Phase 1, 2 |
| Phase 6: HTTP | High | 8-12 hours | Phase 1, 2, 4, 5 |
| Phase 7: WebRTC | Very High | 12-16 hours | Phase 1, 2, 3, 6 |
| Phase 8: Processing | Highest | 10-14 hours | Phase 3, 7 |
| Phase 9: Main | Medium | 4-6 hours | All phases |
| Testing | High | 8-12 hours | All phases |

**Total**: 60-87 hours (1.5 to 2 weeks for one developer)

---

## Next Steps

1. **Review this plan** - Get feedback on approach
2. **Create skeleton** - All headers and empty implementations
3. **Start Phase 1** - Extract utilities (low risk, quick wins)
4. **Iterate** - Complete phases in order
5. **Test continuously** - Don't let bugs accumulate

---

## Questions for Review

1. Should we use cpp-httplib or keep custom HTTP server?
2. Should we introduce a testing framework (Google Test, Catch2)?
3. Should we add a logging library (spdlog) or keep fprintf?
4. What's the priority: speed of refactor vs. code quality?
5. Should we refactor or rewrite certain sections?

---

## Appendix: Code Size Estimates

| Module | Estimated Lines | Notes |
|--------|----------------|-------|
| main.cpp | 250 | Entry point and wiring |
| server_config | 150 | Configuration management |
| json_utils | 100 | Thin wrapper over nlohmann |
| keyboard_map | 80 | Lookup tables |
| connection_manager | 300 | IPC orchestration |
| shm_connection | 100 | SHM management |
| socket_connection | 150 | Socket + eventfd |
| input_protocol | 150 | Send functions |
| emulator_scanner | 150 | Discovery logic |
| process_manager | 250 | Lifecycle management |
| file_scanner | 200 | Directory traversal |
| prefs_manager | 150 | File I/O |
| http_server | 250 | Socket + routing |
| api_handlers | 300 | Endpoint logic |
| static_files | 150 | File serving |
| signaling_server | 300 | WebSocket protocol |
| peer_manager | 250 | Peer tracking |
| track_factory | 200 | RTP setup |
| frame_sender | 300 | Encoding + sending |
| input_handler | 200 | Protocol parsing |
| video_loop | 400 | State machine |
| audio_loop | 200 | Audio processing |

**Total**: ~4,230 lines (40% increase due to better structure and comments)

**Average**: ~200 lines per file (vs. 3,023 in monolith)
