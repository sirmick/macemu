/*
 * Standalone WebRTC Server for macemu (BasiliskII / SheepShaver)
 *
 * Reads video frames from shared memory and streams to browsers via WebRTC.
 * Receives input via DataChannel and forwards to emulator via Unix socket.
 * Can run independently of the emulator process.
 */

#include "ipc_protocol.h"

#include <rtc/rtc.hpp>
#include <rtc/h264rtppacketizer.hpp>
#include <rtc/rtppacketizationconfig.hpp>

#include <wels/codec_api.h>
#include <libyuv.h>

#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <functional>
#include <sstream>
#include <fstream>
#include <csignal>

// POSIX IPC and process management
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>

// Configuration
static int g_http_port = 8000;
static int g_signaling_port = 8090;
static std::string g_video_shm_name;   // Set at startup with PID
static std::string g_audio_shm_name;   // Set at startup with PID
static std::string g_control_sock_path; // Set at startup with PID
static std::string g_roms_path = "storage/roms";
static std::string g_images_path = "storage/images";
static std::string g_prefs_path = "basilisk_ii.prefs";
static std::string g_emulator_path;    // Path to BasiliskII/SheepShaver executable
static bool g_auto_start_emulator = true;

// Generate default IPC names with server PID
static void init_ipc_names() {
    pid_t pid = getpid();
    g_video_shm_name = "/macemu-video-" + std::to_string(pid);
    g_audio_shm_name = "/macemu-audio-" + std::to_string(pid);
    g_control_sock_path = "/tmp/macemu-" + std::to_string(pid) + ".sock";
}

// Global state
static std::atomic<bool> g_running(true);
static std::atomic<bool> g_emulator_connected(false);
static std::atomic<bool> g_restart_emulator_requested(false);
static pid_t g_emulator_pid = -1;

// IPC handles
static MacEmuVideoBuffer* g_video_shm = nullptr;
static MacEmuAudioBuffer* g_audio_shm = nullptr;
static int g_video_shm_fd = -1;
static int g_audio_shm_fd = -1;
static int g_control_socket = -1;

// Input event counters (for stats)
static std::atomic<uint64_t> g_mouse_move_count(0);
static std::atomic<uint64_t> g_mouse_click_count(0);
static std::atomic<uint64_t> g_key_count(0);

// Global flag to request keyframe (set when new peer connects)
static std::atomic<bool> g_request_keyframe(false);

// Signal handler
static void signal_handler(int sig) {
    fprintf(stderr, "\nServer: Received signal %d, shutting down...\n", sig);
    g_running = false;
}


/*
 * JSON helpers
 */

static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";

    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    pos++;

    // Parse the JSON string with proper unescaping
    std::string result;
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                default: result += json[pos]; break;
            }
        } else {
            result += json[pos];
        }
        pos++;
    }

    return result;
}

static int json_get_int(const std::string& json, const std::string& key, int def = 0) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return def;

    pos = json.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    return std::atoi(json.c_str() + pos);
}

static bool json_get_bool(const std::string& json, const std::string& key, bool def = false) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return def;

    pos = json.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (json.substr(pos, 4) == "true") return true;
    if (json.substr(pos, 5) == "false") return false;
    return def;
}


/*
 * IPC: Shared Memory (Server creates and owns)
 */

static int g_listen_socket = -1;  // Listening socket for emulator connections

static bool create_video_shm(int width = 800, int height = 600) {
    // Remove any stale shm
    shm_unlink(g_video_shm_name.c_str());

    g_video_shm_fd = shm_open(g_video_shm_name.c_str(), O_CREAT | O_RDWR, 0666);
    if (g_video_shm_fd < 0) {
        fprintf(stderr, "IPC: Failed to create video shm '%s': %s\n",
                g_video_shm_name.c_str(), strerror(errno));
        return false;
    }

    size_t shm_size = macemu_video_buffer_size();
    if (ftruncate(g_video_shm_fd, shm_size) < 0) {
        fprintf(stderr, "IPC: Failed to size video shm: %s\n", strerror(errno));
        close(g_video_shm_fd);
        shm_unlink(g_video_shm_name.c_str());
        g_video_shm_fd = -1;
        return false;
    }

    g_video_shm = (MacEmuVideoBuffer*)mmap(nullptr, shm_size,
                                            PROT_READ | PROT_WRITE, MAP_SHARED,
                                            g_video_shm_fd, 0);
    if (g_video_shm == MAP_FAILED) {
        fprintf(stderr, "IPC: Failed to map video shm: %s\n", strerror(errno));
        close(g_video_shm_fd);
        shm_unlink(g_video_shm_name.c_str());
        g_video_shm_fd = -1;
        g_video_shm = nullptr;
        return false;
    }

    // Initialize header
    memset(g_video_shm, 0, sizeof(MacEmuVideoBuffer));
    g_video_shm->magic = MACEMU_VIDEO_MAGIC;
    g_video_shm->version = MACEMU_IPC_VERSION;
    g_video_shm->width = width;
    g_video_shm->height = height;
    g_video_shm->stride = width * 4;
    g_video_shm->format = 0;  // RGBA
    ATOMIC_STORE(g_video_shm->write_index, 0);
    ATOMIC_STORE(g_video_shm->read_index, 0);
    ATOMIC_STORE(g_video_shm->frame_count, 0);
    ATOMIC_STORE(g_video_shm->timestamp_us, 0);

    fprintf(stderr, "IPC: Created video shared memory '%s' (%dx%d)\n",
            g_video_shm_name.c_str(), width, height);
    return true;
}

static void destroy_video_shm() {
    if (g_video_shm && g_video_shm != MAP_FAILED) {
        munmap(g_video_shm, macemu_video_buffer_size());
        g_video_shm = nullptr;
    }
    if (g_video_shm_fd >= 0) {
        close(g_video_shm_fd);
        shm_unlink(g_video_shm_name.c_str());
        g_video_shm_fd = -1;
    }
}


/*
 * IPC: Control Socket (Server listens, emulator connects)
 */

static bool create_control_socket() {
    // Remove any stale socket
    unlink(g_control_sock_path.c_str());

    g_listen_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_listen_socket < 0) {
        fprintf(stderr, "IPC: Failed to create socket: %s\n", strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_control_sock_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(g_listen_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "IPC: Failed to bind socket: %s\n", strerror(errno));
        close(g_listen_socket);
        g_listen_socket = -1;
        return false;
    }

    if (listen(g_listen_socket, 1) < 0) {
        fprintf(stderr, "IPC: Failed to listen: %s\n", strerror(errno));
        close(g_listen_socket);
        unlink(g_control_sock_path.c_str());
        g_listen_socket = -1;
        return false;
    }

    // Set non-blocking for accept
    int flags = fcntl(g_listen_socket, F_GETFL, 0);
    fcntl(g_listen_socket, F_SETFL, flags | O_NONBLOCK);

    fprintf(stderr, "IPC: Listening for emulator on '%s'\n", g_control_sock_path.c_str());
    return true;
}

static bool accept_emulator_connection() {
    if (g_listen_socket < 0) return false;
    if (g_control_socket >= 0) return true;  // Already connected

    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    int fd = accept(g_listen_socket, (struct sockaddr*)&addr, &len);
    if (fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;  // No connection pending
        }
        fprintf(stderr, "IPC: Accept failed: %s\n", strerror(errno));
        return false;
    }

    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    g_control_socket = fd;
    g_emulator_connected = true;

    // Send handshake with shm names
    std::string handshake = "{\"type\":\"hello\",\"version\":1,\"video_shm\":\"" +
                            g_video_shm_name + "\",\"audio_shm\":\"" +
                            g_audio_shm_name + "\"}\n";
    send(g_control_socket, handshake.c_str(), handshake.size(), MSG_NOSIGNAL);

    fprintf(stderr, "IPC: Emulator connected\n");
    return true;
}

static void close_emulator_connection() {
    if (g_control_socket >= 0) {
        close(g_control_socket);
        g_control_socket = -1;
    }
    g_emulator_connected = false;
}

static void destroy_control_socket() {
    close_emulator_connection();
    if (g_listen_socket >= 0) {
        close(g_listen_socket);
        g_listen_socket = -1;
    }
    unlink(g_control_sock_path.c_str());
}

static bool send_to_emulator(const std::string& msg) {
    if (g_control_socket < 0) return false;

    std::string line = msg + "\n";
    ssize_t n = send(g_control_socket, line.c_str(), line.size(), MSG_NOSIGNAL);
    return n == (ssize_t)line.size();
}


/*
 * Emulator Process Management
 */

static std::string find_emulator() {
    // If path explicitly set, use it
    if (!g_emulator_path.empty()) {
        if (access(g_emulator_path.c_str(), X_OK) == 0) {
            return g_emulator_path;
        }
        fprintf(stderr, "Emulator: Specified path not executable: %s\n", g_emulator_path.c_str());
        return "";
    }

    // Look for emulator in current directory or relative paths
    const char* candidates[] = {
        "./BasiliskII",
        "./SheepShaver",
        "../BasiliskII/src/Unix/BasiliskII",
        "../SheepShaver/src/Unix/SheepShaver",
        nullptr
    };

    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            char* resolved = realpath(candidates[i], nullptr);
            if (resolved) {
                std::string path(resolved);
                free(resolved);
                return path;
            }
        }
    }

    return "";
}

static bool start_emulator() {
    if (g_emulator_pid > 0) {
        // Already running, check if still alive
        int status;
        pid_t result = waitpid(g_emulator_pid, &status, WNOHANG);
        if (result == 0) {
            // Still running
            return true;
        }
        // Exited
        g_emulator_pid = -1;
    }

    std::string emu_path = find_emulator();
    if (emu_path.empty()) {
        fprintf(stderr, "Emulator: No emulator found. Place BasiliskII or SheepShaver in current directory.\n");
        return false;
    }

    fprintf(stderr, "Emulator: Starting %s --config %s\n", emu_path.c_str(), g_prefs_path.c_str());

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Emulator: Fork failed: %s\n", strerror(errno));
        return false;
    }

    if (pid == 0) {
        // Child process

        // Set environment for IPC
        setenv("MACEMU_CONTROL_SOCK", g_control_sock_path.c_str(), 1);

        // Close server's file descriptors
        for (int fd = 3; fd < 1024; fd++) {
            close(fd);
        }

        // Execute emulator with prefs file
        // BasiliskII uses --config, SheepShaver uses --prefs
        if (emu_path.find("SheepShaver") != std::string::npos) {
            execl(emu_path.c_str(), emu_path.c_str(),
                  "--prefs", g_prefs_path.c_str(), nullptr);
        } else {
            execl(emu_path.c_str(), emu_path.c_str(),
                  "--config", g_prefs_path.c_str(), nullptr);
        }

        // If exec fails
        fprintf(stderr, "Emulator: Exec failed: %s\n", strerror(errno));
        _exit(1);
    }

    // Parent process
    g_emulator_pid = pid;
    fprintf(stderr, "Emulator: Started with PID %d\n", pid);
    return true;
}

static void stop_emulator() {
    if (g_emulator_pid <= 0) return;

    fprintf(stderr, "Emulator: Stopping PID %d\n", g_emulator_pid);

    // Try graceful shutdown first
    kill(g_emulator_pid, SIGTERM);

    // Wait up to 3 seconds
    for (int i = 0; i < 30; i++) {
        int status;
        pid_t result = waitpid(g_emulator_pid, &status, WNOHANG);
        if (result != 0) {
            g_emulator_pid = -1;
            fprintf(stderr, "Emulator: Stopped\n");
            return;
        }
        usleep(100000);  // 100ms
    }

    // Force kill
    fprintf(stderr, "Emulator: Force killing\n");
    kill(g_emulator_pid, SIGKILL);
    waitpid(g_emulator_pid, nullptr, 0);
    g_emulator_pid = -1;
}

// Returns: 0 if still running, -1 if not running/error, positive if exited with code
static int check_emulator_status() {
    if (g_emulator_pid <= 0) return -1;

    int status;
    pid_t result = waitpid(g_emulator_pid, &status, WNOHANG);
    if (result > 0) {
        // Emulator exited
        int exit_code = -1;
        if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            fprintf(stderr, "Emulator: Exited with code %d\n", exit_code);
            if (exit_code == 75) {
                fprintf(stderr, "Emulator: Restart requested (exit code 75)\n");
            }
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Emulator: Killed by signal %d\n", WTERMSIG(status));
        }
        g_emulator_pid = -1;
        g_emulator_connected = false;
        close_emulator_connection();
        return exit_code >= 0 ? exit_code : -1;
    } else if (result == 0) {
        return 0;  // Still running
    }
    return -1;  // Error
}


/*
 * H.264 Encoder using OpenH264 with screen content optimization
 */

class H264Encoder {
public:
    H264Encoder() = default;
    ~H264Encoder() { cleanup(); }

    bool init(int width, int height, int fps = 30, int bitrate_kbps = 2000) {
        cleanup();

        if (WelsCreateSVCEncoder(&encoder_) != 0 || !encoder_) {
            fprintf(stderr, "H264: Failed to create encoder\n");
            return false;
        }

        // Use extended parameters for proper configuration
        SEncParamExt param;
        encoder_->GetDefaultParams(&param);

        param.iUsageType = SCREEN_CONTENT_REAL_TIME;  // Optimized for desktop/text
        param.fMaxFrameRate = static_cast<float>(fps);
        param.iPicWidth = width;
        param.iPicHeight = height;
        param.iTargetBitrate = bitrate_kbps * 1000;
        param.iRCMode = RC_BITRATE_MODE;
        param.bEnableFrameSkip = false;  // Don't skip frames
        param.bEnableDenoise = false;
        param.iSpatialLayerNum = 1;
        param.iTemporalLayerNum = 1;
        param.iMultipleThreadIdc = 0;  // Auto-detect threads
        param.uiIntraPeriod = fps * 2;  // Keyframe every 2 seconds
        param.eSpsPpsIdStrategy = SPS_LISTING;  // Include SPS/PPS with each IDR

        // Configure the single spatial layer
        param.sSpatialLayers[0].iVideoWidth = width;
        param.sSpatialLayers[0].iVideoHeight = height;
        param.sSpatialLayers[0].fFrameRate = static_cast<float>(fps);
        param.sSpatialLayers[0].iSpatialBitrate = bitrate_kbps * 1000;
        param.sSpatialLayers[0].iMaxSpatialBitrate = bitrate_kbps * 1500;
        param.sSpatialLayers[0].sSliceArgument.uiSliceMode = SM_SINGLE_SLICE;

        if (encoder_->InitializeExt(&param) != 0) {
            fprintf(stderr, "H264: Failed to initialize encoder\n");
            cleanup();
            return false;
        }

        // Set video format (required after InitializeExt)
        int videoFormat = videoFormatI420;
        encoder_->SetOption(ENCODER_OPTION_DATAFORMAT, &videoFormat);

        // Allocate YUV buffer for libyuv conversion
        yuv_size_ = width * height * 3 / 2;
        yuv_buffer_ = new uint8_t[yuv_size_];

        width_ = width;
        height_ = height;
        fps_ = fps;

        fprintf(stderr, "H264: Encoder initialized %dx%d @ %d kbps (screen content mode)\n",
                width, height, bitrate_kbps);
        return true;
    }

    void cleanup() {
        if (encoder_) {
            encoder_->Uninitialize();
            WelsDestroySVCEncoder(encoder_);
            encoder_ = nullptr;
        }
        delete[] yuv_buffer_;
        yuv_buffer_ = nullptr;
    }

    std::vector<uint8_t> encode(const uint8_t* rgba, int width, int height, int stride) {
        std::vector<uint8_t> result;

        if (!encoder_ || width != width_ || height != height_) {
            if (!init(width, height)) {
                return result;
            }
            force_keyframe_ = true;  // Force IDR on first frame after init
        }

        // Force keyframe if requested
        if (force_keyframe_) {
            fprintf(stderr, "H264: Forcing IDR frame\n");
            int ret = encoder_->ForceIntraFrame(true);
            fprintf(stderr, "H264: ForceIntraFrame returned %d\n", ret);
            force_keyframe_ = false;
        }

        // Use libyuv for fast RGBA to I420 conversion
        uint8_t* y = yuv_buffer_;
        uint8_t* u = yuv_buffer_ + width_ * height_;
        uint8_t* v = yuv_buffer_ + width_ * height_ * 5 / 4;
        int y_stride = width_;
        int uv_stride = width_ / 2;

        // libyuv uses ARGB (which is actually BGRA in memory on little-endian)
        // Our input is RGBA, so we use ABGRToI420
        libyuv::ABGRToI420(
            rgba, stride,
            y, y_stride,
            u, uv_stride,
            v, uv_stride,
            width_, height_
        );

        SSourcePicture pic = {};
        pic.iPicWidth = width_;
        pic.iPicHeight = height_;
        pic.iColorFormat = videoFormatI420;
        pic.iStride[0] = y_stride;
        pic.iStride[1] = uv_stride;
        pic.iStride[2] = uv_stride;
        pic.pData[0] = y;
        pic.pData[1] = u;
        pic.pData[2] = v;

        SFrameBSInfo info = {};
        int rv = encoder_->EncodeFrame(&pic, &info);
        if (rv != 0) {
            fprintf(stderr, "H264: EncodeFrame returned %d\n", rv);
            return result;
        }

        // Debug: log frame type and layer info
        static int debug_count = 0;
        bool is_idr = (info.eFrameType == videoFrameTypeIDR);
        if (debug_count++ < 10 || debug_count % 100 == 0 || is_idr) {
            fprintf(stderr, "H264: eFrameType=%d iLayerNum=%d%s\n",
                    info.eFrameType, info.iLayerNum, is_idr ? " [IDR KEYFRAME]" : "");
        }

        if (info.eFrameType == videoFrameTypeSkip) {
            return result;
        }

        // Collect all NAL units with start codes
        for (int layer = 0; layer < info.iLayerNum; layer++) {
            const SLayerBSInfo& layerInfo = info.sLayerInfo[layer];
            uint8_t* data = layerInfo.pBsBuf;
            if (debug_count < 10) {
                fprintf(stderr, "H264: Layer %d: iNalCount=%d pBsBuf=%p\n",
                        layer, layerInfo.iNalCount, (void*)data);
            }
            for (int nal = 0; nal < layerInfo.iNalCount; nal++) {
                int nalSize = layerInfo.pNalLengthInByte[nal];
                if (debug_count < 10) {
                    fprintf(stderr, "H264: NAL %d size=%d\n", nal, nalSize);
                }
                result.insert(result.end(), data, data + nalSize);
                data += nalSize;
            }
        }

        return result;
    }

    bool is_keyframe(const std::vector<uint8_t>& data) {
        // Look for IDR NAL unit (type 5) after start code
        for (size_t i = 0; i + 4 < data.size(); i++) {
            if (data[i] == 0 && data[i+1] == 0 && data[i+2] == 0 && data[i+3] == 1) {
                uint8_t nal_type = data[i+4] & 0x1F;
                if (nal_type == 5) return true;  // IDR frame
            }
        }
        return false;
    }

    // Request a keyframe on next encode (call when new peer connects)
    void request_keyframe() {
        force_keyframe_ = true;
    }

private:
    ISVCEncoder* encoder_ = nullptr;
    uint8_t* yuv_buffer_ = nullptr;
    size_t yuv_size_ = 0;
    int width_ = 0;
    int height_ = 0;
    int fps_ = 30;
    bool force_keyframe_ = true;  // Start true to force first frame as IDR
};


/*
 * Storage scanning and config (similar to datachannel_webrtc.cpp)
 */

static bool has_extension(const std::string& filename, const std::vector<std::string>& extensions) {
    size_t dot = filename.rfind('.');
    if (dot == std::string::npos) return false;
    std::string ext = filename.substr(dot);
    for (auto& c : ext) c = tolower(c);
    for (const auto& e : extensions) {
        if (ext == e) return true;
    }
    return false;
}

struct FileInfo {
    std::string name;
    int64_t size;
    uint32_t checksum;
    bool has_checksum;
};

static uint32_t read_rom_checksum(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return 0;
    uint8_t buf[4];
    if (fread(buf, 1, 4, f) != 4) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

static void scan_directory_recursive(const std::string& base_dir, const std::string& relative_path,
                                     const std::vector<std::string>& extensions, bool read_checksums,
                                     std::vector<FileInfo>& files) {
    std::string current_dir = relative_path.empty() ? base_dir : base_dir + "/" + relative_path;

    DIR* dir = opendir(current_dir.c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        std::string name = entry->d_name;
        std::string full_path = current_dir + "/" + name;
        std::string rel_name = relative_path.empty() ? name : relative_path + "/" + name;

        struct stat st;
        if (stat(full_path.c_str(), &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_directory_recursive(base_dir, rel_name, extensions, read_checksums, files);
        } else if (S_ISREG(st.st_mode)) {
            if (has_extension(name, extensions)) {
                FileInfo info;
                info.name = rel_name;
                info.size = st.st_size;
                info.checksum = 0;
                info.has_checksum = false;

                if (read_checksums) {
                    info.checksum = read_rom_checksum(full_path);
                    info.has_checksum = true;
                }

                files.push_back(info);
            }
        }
    }
    closedir(dir);
}

static std::vector<FileInfo> scan_directory(const std::string& directory,
                                            const std::vector<std::string>& extensions,
                                            bool read_checksums = false, bool recursive = false) {
    std::vector<FileInfo> files;

    if (recursive) {
        scan_directory_recursive(directory, "", extensions, read_checksums, files);
    } else {
        DIR* dir = opendir(directory.c_str());
        if (!dir) return files;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            std::string name = entry->d_name;
            if (has_extension(name, extensions)) {
                FileInfo info;
                info.name = name;
                info.size = 0;
                info.checksum = 0;
                info.has_checksum = false;

                std::string full_path = directory + "/" + name;
                struct stat st;
                if (stat(full_path.c_str(), &st) == 0) {
                    info.size = st.st_size;
                }

                if (read_checksums) {
                    info.checksum = read_rom_checksum(full_path);
                    info.has_checksum = true;
                }

                files.push_back(info);
            }
        }
        closedir(dir);
    }

    std::sort(files.begin(), files.end(), [](const FileInfo& a, const FileInfo& b) {
        return a.name < b.name;
    });
    return files;
}

static std::string get_storage_json() {
    auto roms = scan_directory(g_roms_path, {".rom"}, true, true);
    auto disks = scan_directory(g_images_path, {".img", ".dsk", ".hfv", ".iso", ".toast"});

    std::ostringstream json;
    json << "{\n";
    json << "  \"romsPath\": \"" << json_escape(g_roms_path) << "\",\n";
    json << "  \"imagesPath\": \"" << json_escape(g_images_path) << "\",\n";
    json << "  \"roms\": [";
    for (size_t i = 0; i < roms.size(); i++) {
        if (i > 0) json << ", ";
        json << "{\"name\": \"" << json_escape(roms[i].name) << "\", \"size\": " << roms[i].size;
        char checksum_hex[16];
        snprintf(checksum_hex, sizeof(checksum_hex), "%08x", roms[i].checksum);
        json << ", \"checksum\": \"" << checksum_hex << "\"}";
    }
    json << "],\n";
    json << "  \"disks\": [";
    for (size_t i = 0; i < disks.size(); i++) {
        if (i > 0) json << ", ";
        json << "{\"name\": \"" << json_escape(disks[i].name) << "\", \"size\": " << disks[i].size << "}";
    }
    json << "]\n";
    json << "}";

    return json.str();
}

// Parse JSON array of strings (simple parser for disk list)
static std::vector<std::string> json_get_string_array(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return result;

    pos = json.find('[', pos);
    if (pos == std::string::npos) return result;
    pos++;

    size_t end = json.find(']', pos);
    if (end == std::string::npos) return result;

    std::string array_content = json.substr(pos, end - pos);

    // Extract each quoted string
    size_t start = 0;
    while ((start = array_content.find('"', start)) != std::string::npos) {
        start++;
        size_t str_end = start;
        while (str_end < array_content.size() && array_content[str_end] != '"') {
            if (array_content[str_end] == '\\' && str_end + 1 < array_content.size()) str_end++;
            str_end++;
        }
        result.push_back(array_content.substr(start, str_end - start));
        start = str_end + 1;
    }

    return result;
}

// Write configuration to prefs file
static bool write_config_prefs(const std::string& json) {
    std::string rom = json_get_string(json, "rom");
    std::vector<std::string> disks = json_get_string_array(json, "disks");
    int ramsize = json_get_int(json, "ram", 32);
    std::string screen = json_get_string(json, "screen");
    int cpu = json_get_int(json, "cpu", 4);
    int modelid = json_get_int(json, "model", 14);
    bool fpu = json_get_bool(json, "fpu", true);
    bool jit = json_get_bool(json, "jit", true);
    bool sound = json_get_bool(json, "sound", true);

    // Debug: log what we received
    fprintf(stderr, "Config: rom=%s, disks=%zu, ram=%d, screen=%s, cpu=%d, model=%d\n",
            rom.c_str(), disks.size(), ramsize, screen.c_str(), cpu, modelid);

    // Parse screen resolution
    int screen_w = 800, screen_h = 600;
    if (!screen.empty()) {
        size_t x_pos = screen.find('x');
        if (x_pos != std::string::npos) {
            screen_w = std::atoi(screen.substr(0, x_pos).c_str());
            screen_h = std::atoi(screen.substr(x_pos + 1).c_str());
        }
    }

    // Get absolute paths for ROM and disk files
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        strcpy(cwd, ".");
    }

    std::ostringstream prefs;
    prefs << "# Basilisk II preferences - generated by web UI\n\n";

    // ROM (use absolute path)
    if (!rom.empty()) {
        prefs << "rom " << cwd << "/" << g_roms_path << "/" << rom << "\n";
    }

    // Disk images (use absolute paths)
    if (disks.empty()) {
        fprintf(stderr, "Config: WARNING - no disk images specified!\n");
    }
    for (const auto& disk : disks) {
        fprintf(stderr, "Config: Adding disk: %s\n", disk.c_str());
        prefs << "disk " << cwd << "/" << g_images_path << "/" << disk << "\n";
    }

    prefs << "\n# Hardware settings\n";
    prefs << "ramsize " << (ramsize * 1024 * 1024) << "\n";
    // Use IPC screen mode for web streaming, with configured resolution
    prefs << "screen ipc/" << screen_w << "/" << screen_h << "\n";
    prefs << "cpu " << cpu << "\n";
    prefs << "modelid " << modelid << "\n";
    prefs << "fpu " << (fpu ? "true" : "false") << "\n";
    prefs << "jit " << (jit ? "true" : "false") << "\n";
    prefs << "nosound " << (sound ? "false" : "true") << "\n";

    prefs << "\n# JIT settings\n";
    prefs << "jitfpu true\n";
    prefs << "jitcachesize 8192\n";
    prefs << "jitlazyflush true\n";
    prefs << "jitinline true\n";
    prefs << "jitdebug false\n";

    prefs << "\n# Display settings\n";
    prefs << "displaycolordepth 0\n";
    prefs << "frameskip 0\n";
    prefs << "scale_nearest false\n";
    prefs << "scale_integer false\n";

    prefs << "\n# Input settings\n";
    prefs << "keyboardtype 5\n";
    prefs << "keycodes false\n";
    prefs << "mousewheelmode 1\n";
    prefs << "mousewheellines 3\n";
    prefs << "swap_opt_cmd true\n";
    prefs << "hotkey 0\n";

    prefs << "\n# Serial/Network\n";
    prefs << "seriala /dev/null\n";
    prefs << "serialb /dev/null\n";
    prefs << "udptunnel false\n";
    prefs << "udpport 6066\n";
    prefs << "etherpermanentaddress true\n";
    prefs << "ethermulticastmode 0\n";
    prefs << "routerenabled false\n";
    prefs << "ftp_port_list 21\n";

    prefs << "\n# Boot settings\n";
    prefs << "bootdrive 0\n";
    prefs << "bootdriver 0\n";
    prefs << "nocdrom false\n";

    prefs << "\n# System settings\n";
    prefs << "ignoresegv true\n";
    prefs << "idlewait true\n";
    prefs << "noclipconversion false\n";
    prefs << "nogui true\n";
    prefs << "sound_buffer 0\n";
    prefs << "name_encoding 0\n";
    prefs << "delay 0\n";
    prefs << "init_grab false\n";
    prefs << "yearofs 0\n";
    prefs << "dayofs 0\n";
    prefs << "reservewindowskey false\n";

    prefs << "\n# SDL settings\n";
    prefs << "sdlrender software\n";
    prefs << "sdl_vsync true\n";

    prefs << "\n# ExtFS settings\n";
    prefs << "enableextfs false\n";
    prefs << "debugextfs false\n";
    prefs << "extfs \n";
    prefs << "extdrives CDEFGHIJKLMNOPQRSTUVWXYZ\n";
    prefs << "pollmedia true\n";

    // Write to file
    std::ofstream file(g_prefs_path);
    if (!file) {
        fprintf(stderr, "Config: Failed to open prefs file for writing: %s\n", g_prefs_path.c_str());
        return false;
    }

    file << prefs.str();
    file.close();

    fprintf(stderr, "Config: Wrote prefs file: %s\n", g_prefs_path.c_str());
    return true;
}

// Read current config from prefs file and return as JSON
static std::string read_config_json() {
    std::ifstream file(g_prefs_path);
    if (!file) {
        return "{\"error\": \"No config file found\"}";
    }

    std::string rom;
    std::vector<std::string> disks;
    int ramsize = 32;
    int screen_w = 800, screen_h = 600;
    int cpu = 4;
    int modelid = 14;
    bool fpu = true;
    bool jit = true;
    bool sound = true;

    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string key, value;
        iss >> key;
        std::getline(iss >> std::ws, value);

        if (key == "rom") {
            // Extract just the filename
            size_t slash = value.rfind('/');
            rom = (slash != std::string::npos) ? value.substr(slash + 1) : value;
        } else if (key == "disk") {
            size_t slash = value.rfind('/');
            std::string disk_name = (slash != std::string::npos) ? value.substr(slash + 1) : value;
            disks.push_back(disk_name);
        } else if (key == "ramsize") {
            ramsize = std::atoi(value.c_str()) / (1024 * 1024);
        } else if (key == "screen") {
            // Parse "win/800/600" or "ipc/800/600" format
            size_t first_slash = value.find('/');
            if (first_slash != std::string::npos) {
                std::string dims = value.substr(first_slash + 1);
                size_t second_slash = dims.find('/');
                if (second_slash != std::string::npos) {
                    screen_w = std::atoi(dims.substr(0, second_slash).c_str());
                    screen_h = std::atoi(dims.substr(second_slash + 1).c_str());
                }
            }
        } else if (key == "cpu") {
            cpu = std::atoi(value.c_str());
        } else if (key == "modelid") {
            modelid = std::atoi(value.c_str());
        } else if (key == "fpu") {
            fpu = (value == "true");
        } else if (key == "jit") {
            jit = (value == "true");
        } else if (key == "nosound") {
            sound = (value != "true");
        }
    }

    std::ostringstream json;
    json << "{";
    json << "\"rom\": \"" << json_escape(rom) << "\", ";
    json << "\"disks\": [";
    for (size_t i = 0; i < disks.size(); i++) {
        if (i > 0) json << ", ";
        json << "\"" << json_escape(disks[i]) << "\"";
    }
    json << "], ";
    json << "\"ram\": " << ramsize << ", ";
    json << "\"screen\": \"" << screen_w << "x" << screen_h << "\", ";
    json << "\"cpu\": " << cpu << ", ";
    json << "\"model\": " << modelid << ", ";
    json << "\"fpu\": " << (fpu ? "true" : "false") << ", ";
    json << "\"jit\": " << (jit ? "true" : "false") << ", ";
    json << "\"sound\": " << (sound ? "true" : "false");
    json << "}";

    return json.str();
}


/*
 * HTTP Server
 */

class HTTPServer {
public:
    bool start(int port) {
        port_ = port;

        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            fprintf(stderr, "HTTP: Failed to create socket\n");
            return false;
        }

        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        int flags = fcntl(server_fd_, F_GETFL, 0);
        fcntl(server_fd_, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "HTTP: Failed to bind port %d\n", port);
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        if (listen(server_fd_, 10) < 0) {
            fprintf(stderr, "HTTP: Failed to listen\n");
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        running_ = true;
        thread_ = std::thread(&HTTPServer::run, this);

        fprintf(stderr, "HTTP: Server on port %d\n", port);
        return true;
    }

    void stop() {
        running_ = false;
        if (server_fd_ >= 0) {
            close(server_fd_);
            server_fd_ = -1;
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

private:
    void run() {
        while (running_ && g_running) {
            struct pollfd pfd;
            pfd.fd = server_fd_;
            pfd.events = POLLIN;

            int ret = poll(&pfd, 1, 100);
            if (ret <= 0) continue;

            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) continue;

            handle_client(client_fd);
            close(client_fd);
        }
    }

    void handle_client(int fd) {
        char buffer[8192];
        ssize_t n = recv(fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) return;
        buffer[n] = '\0';

        std::string request(buffer);
        std::string method;
        std::string path = "/";

        size_t method_end = request.find(' ');
        if (method_end != std::string::npos) {
            method = request.substr(0, method_end);
            size_t path_end = request.find(' ', method_end + 1);
            if (path_end != std::string::npos) {
                path = request.substr(method_end + 1, path_end - method_end - 1);
            }
        }

        // Strip query string from path
        size_t query_pos = path.find('?');
        if (query_pos != std::string::npos) {
            path = path.substr(0, query_pos);
        }

        // Debug: log requests
        // fprintf(stderr, "HTTP: %s %s\n", method.c_str(), path.c_str());

        // Extract request body for POST requests
        std::string body;
        size_t content_length = 0;
        size_t cl_pos = request.find("Content-Length:");
        if (cl_pos != std::string::npos) {
            content_length = std::atoi(request.c_str() + cl_pos + 15);
        }
        size_t body_start = request.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            body = request.substr(body_start + 4);
        }

        // API endpoints
        if (path == "/api/storage" && method == "GET") {
            std::string json_body = get_storage_json();
            send_json_response(fd, json_body);
            return;
        }

        if (path == "/api/config" && method == "GET") {
            std::string json_body = read_config_json();
            send_json_response(fd, json_body);
            return;
        }

        if (path == "/api/config" && method == "POST") {
            if (write_config_prefs(body)) {
                send_json_response(fd, "{\"success\": true}");
            } else {
                send_json_response(fd, "{\"success\": false, \"error\": \"Failed to write config\"}");
            }
            return;
        }

        if (path == "/api/restart" && method == "POST") {
            fprintf(stderr, "Server: Restart requested via API\n");
            send_to_emulator("{\"type\":\"restart\"}");
            std::string json_body = "{\"success\": true, \"message\": \"Restart sent to emulator\"}";
            send_json_response(fd, json_body);
            return;
        }

        if (path == "/api/status" && method == "GET") {
            std::ostringstream json;
            json << "{";
            json << "\"emulator_connected\": " << (g_emulator_connected ? "true" : "false");
            json << ", \"emulator_running\": " << (g_emulator_pid > 0 ? "true" : "false");
            json << ", \"emulator_pid\": " << g_emulator_pid;
            if (g_video_shm) {
                json << ", \"video\": {\"width\": " << g_video_shm->width;
                json << ", \"height\": " << g_video_shm->height;
                json << ", \"frame_count\": " << ATOMIC_LOAD(g_video_shm->frame_count) << "}";
            }
            json << "}";
            send_json_response(fd, json.str());
            return;
        }

        if (path == "/api/emulator/start" && method == "POST") {
            std::string json_body;
            if (g_emulator_pid > 0) {
                json_body = "{\"success\": false, \"message\": \"Emulator already running\", \"pid\": " + std::to_string(g_emulator_pid) + "}";
            } else if (start_emulator()) {
                json_body = "{\"success\": true, \"message\": \"Emulator started\", \"pid\": " + std::to_string(g_emulator_pid) + "}";
            } else {
                json_body = "{\"success\": false, \"message\": \"Failed to start emulator\"}";
            }
            send_json_response(fd, json_body);
            return;
        }

        if (path == "/api/emulator/stop" && method == "POST") {
            std::string json_body;
            if (g_emulator_pid <= 0) {
                json_body = "{\"success\": false, \"message\": \"Emulator not running\"}";
            } else {
                stop_emulator();
                json_body = "{\"success\": true, \"message\": \"Emulator stopped\"}";
            }
            send_json_response(fd, json_body);
            return;
        }

        if (path == "/api/emulator/restart" && method == "POST") {
            g_restart_emulator_requested = true;
            std::string json_body = "{\"success\": true, \"message\": \"Restart requested\"}";
            send_json_response(fd, json_body);
            return;
        }

        // Static files
        std::string content_type = "text/html";
        std::string disk_path;

        // Map paths to files and content types
        if (path == "/" || path == "/index.html") {
            disk_path = client_dir_ + "/index.html";
            content_type = "text/html";
        } else if (path == "/client.js") {
            disk_path = client_dir_ + "/client.js";
            content_type = "application/javascript";
        } else if (path == "/styles.css") {
            disk_path = client_dir_ + "/styles.css";
            content_type = "text/css";
        }

        // Read file from disk
        std::string file_content;
        if (!disk_path.empty()) {
            std::ifstream file(disk_path);
            if (file.is_open()) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                file_content = buffer.str();
            }
        }

        if (!file_content.empty()) {
            size_t content_len = file_content.size();

            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: " + content_type + "\r\n";
            response += "Content-Length: " + std::to_string(content_len) + "\r\n";
            response += "Connection: close\r\n";
            response += "\r\n";
            send(fd, response.c_str(), response.size(), 0);
            send(fd, file_content.c_str(), content_len, 0);
        } else {
            std::string response = "HTTP/1.1 404 Not Found\r\n";
            response += "Content-Type: text/plain\r\n";
            response += "Content-Length: 9\r\n";
            response += "Connection: close\r\n";
            response += "\r\n";
            response += "Not Found";
            send(fd, response.c_str(), response.size(), 0);
        }
    }

    void send_json_response(int fd, const std::string& json_body) {
        std::string response = "HTTP/1.1 200 OK\r\n";
        response += "Content-Type: application/json\r\n";
        response += "Content-Length: " + std::to_string(json_body.size()) + "\r\n";
        response += "Connection: close\r\n";
        response += "\r\n";
        response += json_body;
        send(fd, response.c_str(), response.size(), 0);
    }

    int port_ = 8000;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::string client_dir_ = "client";  // Directory for client files
};


/*
 * WebRTC Peer Connection
 */

struct PeerConnection {
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::Track> video_track;
    std::shared_ptr<rtc::DataChannel> data_channel;
    std::string id;
    bool ready = false;
    bool has_remote_description = false;
    std::vector<std::pair<std::string, std::string>> pending_candidates;  // candidate, mid
};


/*
 * WebRTC Server
 */

class WebRTCServer {
public:
    bool init(int signaling_port) {
        port_ = signaling_port;

        rtc::InitLogger(rtc::LogLevel::Error);
        rtc::Preload();

        try {
            rtc::WebSocketServer::Configuration config;
            config.port = signaling_port;
            config.enableTls = false;

            ws_server_ = std::make_unique<rtc::WebSocketServer>(config);

            ws_server_->onClient([this](std::shared_ptr<rtc::WebSocket> ws) {
                ws->onOpen([ws]() {
                    std::string welcome = "{\"type\":\"welcome\",\"peerId\":\"server\"}";
                    ws->send(welcome);
                });

                ws->onMessage([this, ws](auto data) {
                    if (std::holds_alternative<std::string>(data)) {
                        process_signaling(ws, std::get<std::string>(data));
                    }
                });

                ws->onClosed([this, ws]() {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    auto it = ws_to_peer_id_.find(ws.get());
                    if (it != ws_to_peer_id_.end()) {
                        peers_.erase(it->second);
                        ws_to_peer_id_.erase(it);
                        peer_count_--;
                    }
                });
            });

            initialized_ = true;
            fprintf(stderr, "WebRTC: Signaling server on port %d\n", signaling_port);

        } catch (const std::exception& e) {
            fprintf(stderr, "WebRTC: Failed to start server: %s\n", e.what());
            return false;
        }

        return true;
    }

    void shutdown() {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peers_.clear();
        ws_to_peer_id_.clear();
        ws_server_.reset();
        initialized_ = false;
    }

    void send_frame(const std::vector<uint8_t>& data, bool is_keyframe) {
        if (data.empty() || peer_count_ == 0) return;

        std::lock_guard<std::mutex> lock(peers_mutex_);

        static int frame_count = 0;
        static int sent_count = 0;
        frame_count++;

        for (auto& [id, peer] : peers_) {
            if (peer->ready && peer->video_track && peer->video_track->isOpen()) {
                try {
                    // H264RtpPacketizer handles NAL unit fragmentation automatically
                    peer->video_track->send(
                        reinterpret_cast<const std::byte*>(data.data()),
                        data.size());
                    sent_count++;
                } catch (const std::exception& e) {
                    fprintf(stderr, "[WebRTC] Send error: %s\n", e.what());
                }
            } else if (frame_count % 30 == 0) {
                // Log why we're not sending
                fprintf(stderr, "[WebRTC] Not sending to %s: ready=%d track=%p isOpen=%d\n",
                        id.c_str(), peer->ready,
                        (void*)peer->video_track.get(),
                        peer->video_track ? peer->video_track->isOpen() : 0);
            }
        }

        // Log first few frames and then periodically
        if (frame_count <= 5 || frame_count % 100 == 0) {
            fprintf(stderr, "[WebRTC] Frame %d: %zu bytes, keyframe=%d, sent_to=%d peers\n",
                    frame_count, data.size(), is_keyframe, sent_count);
            sent_count = 0;
        }
    }

    int peer_count() { return peer_count_.load(); }
    bool is_enabled() { return initialized_.load(); }

private:
    void process_signaling(std::shared_ptr<rtc::WebSocket> ws, const std::string& msg) {
        std::string type = json_get_string(msg, "type");

        if (type == "connect") {
            std::string peer_id = "peer_" + std::to_string(rand());
            auto peer = std::make_shared<PeerConnection>();
            peer->id = peer_id;

            rtc::Configuration config;
            config.iceServers.emplace_back("stun:stun.l.google.com:19302");

            peer->pc = std::make_shared<rtc::PeerConnection>(config);

            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                ws_to_peer_id_[ws.get()] = peer_id;
                peers_[peer_id] = peer;
                peer_count_++;
            }

            std::weak_ptr<rtc::PeerConnection> wpc = peer->pc;
            peer->pc->onGatheringStateChange([ws, peer_id, wpc](rtc::PeerConnection::GatheringState state) {
                if (state == rtc::PeerConnection::GatheringState::Complete) {
                    if (auto pc = wpc.lock()) {
                        auto description = pc->localDescription();
                        if (description) {
                            std::string sdp = std::string(description.value());
                            std::string type_str = description->typeString();
                            std::string response = "{\"type\":\"" + type_str + "\",\"sdp\":\"" + json_escape(sdp) + "\"}";
                            ws->send(response);
                        }
                    }
                }
            });

            // Add video track with H.264 codec
            rtc::Description::Video media("video-stream", rtc::Description::Direction::SendOnly);
            media.addH264Codec(96);
            media.addSSRC(ssrc_, "video-stream", "stream1", "video-stream");
            peer->video_track = peer->pc->addTrack(media);

            // Set up H.264 RTP packetizer (handles NAL unit fragmentation)
            auto rtpConfig = std::make_shared<rtc::RtpPacketizationConfig>(
                ssrc_, "video-stream", 96, rtc::H264RtpPacketizer::ClockRate
            );
            auto packetizer = std::make_shared<rtc::H264RtpPacketizer>(
                rtc::H264RtpPacketizer::Separator::LongStartSequence,
                rtpConfig
            );
            peer->video_track->setMediaHandler(packetizer);

            peer->video_track->onOpen([peer]() {
                fprintf(stderr, "[WebRTC] Video track OPEN for %s - ready to send frames!\n", peer->id.c_str());
                peer->ready = true;
                // Request keyframe so new peer gets a complete picture
                g_request_keyframe.store(true);
            });

            peer->video_track->onClosed([peer]() {
                fprintf(stderr, "[WebRTC] Video track CLOSED for %s\n", peer->id.c_str());
                peer->ready = false;
            });

            peer->video_track->onError([peer](std::string error) {
                fprintf(stderr, "[WebRTC] Video track ERROR for %s: %s\n", peer->id.c_str(), error.c_str());
            });

            peer->pc->onStateChange([peer](rtc::PeerConnection::State state) {
                const char* state_str = "unknown";
                switch (state) {
                    case rtc::PeerConnection::State::New: state_str = "New"; break;
                    case rtc::PeerConnection::State::Connecting: state_str = "Connecting"; break;
                    case rtc::PeerConnection::State::Connected: state_str = "Connected"; break;
                    case rtc::PeerConnection::State::Disconnected: state_str = "Disconnected"; break;
                    case rtc::PeerConnection::State::Failed: state_str = "Failed"; break;
                    case rtc::PeerConnection::State::Closed: state_str = "Closed"; break;
                }
                fprintf(stderr, "[WebRTC] Peer %s state: %s\n", peer->id.c_str(), state_str);
            });

            peer->pc->onIceStateChange([peer](rtc::PeerConnection::IceState state) {
                const char* state_str = "unknown";
                switch (state) {
                    case rtc::PeerConnection::IceState::New: state_str = "New"; break;
                    case rtc::PeerConnection::IceState::Checking: state_str = "Checking"; break;
                    case rtc::PeerConnection::IceState::Connected: state_str = "Connected"; break;
                    case rtc::PeerConnection::IceState::Completed: state_str = "Completed"; break;
                    case rtc::PeerConnection::IceState::Disconnected: state_str = "Disconnected"; break;
                    case rtc::PeerConnection::IceState::Failed: state_str = "Failed"; break;
                    case rtc::PeerConnection::IceState::Closed: state_str = "Closed"; break;
                }
                fprintf(stderr, "[WebRTC] Peer %s ICE state: %s\n", peer->id.c_str(), state_str);
            });

            // Add data channel for input
            peer->data_channel = peer->pc->createDataChannel("input");
            peer->data_channel->onOpen([peer_id = peer->id]() {
                fprintf(stderr, "[WebRTC] DataChannel OPEN for %s\n", peer_id.c_str());
            });
            peer->data_channel->onMessage([this](auto data) {
                if (std::holds_alternative<std::string>(data)) {
                    const std::string& msg = std::get<std::string>(data);
                    static int msg_count = 0;
                    if (msg_count++ < 5) {
                        fprintf(stderr, "[WebRTC] DataChannel message: '%s'\n", msg.c_str());
                    }
                    handle_input(msg);
                } else {
                    fprintf(stderr, "[WebRTC] DataChannel received binary data\n");
                }
            });

            // Also handle incoming data channels from browser
            peer->pc->onDataChannel([this, peer_id = peer->id](std::shared_ptr<rtc::DataChannel> dc) {
                fprintf(stderr, "[WebRTC] Incoming DataChannel '%s' from %s\n",
                        dc->label().c_str(), peer_id.c_str());
                dc->onOpen([label = dc->label(), peer_id]() {
                    fprintf(stderr, "[WebRTC] Incoming DataChannel '%s' OPEN for %s\n",
                            label.c_str(), peer_id.c_str());
                });
                dc->onMessage([this](auto data) {
                    if (std::holds_alternative<std::string>(data)) {
                        handle_input(std::get<std::string>(data));
                    }
                });
            });

            peer->pc->setLocalDescription();
        }
        else if (type == "answer") {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = ws_to_peer_id_.find(ws.get());
            if (it != ws_to_peer_id_.end()) {
                auto peer = peers_[it->second];
                std::string sdp = json_get_string(msg, "sdp");
                fprintf(stderr, "[WebRTC] Received answer from %s (sdp length=%zu)\n",
                        peer->id.c_str(), sdp.size());

                // Debug: Always print SDP for debugging
                fprintf(stderr, "[WebRTC] Answer SDP:\n---\n%s\n---\n", sdp.c_str());

                // Debug: Check for ICE credentials in SDP
                if (sdp.find("a=ice-ufrag:") == std::string::npos) {
                    fprintf(stderr, "[WebRTC] WARNING: Answer SDP missing ice-ufrag after parsing!\n");
                }

                // Set remote description
                try {
                    peer->pc->setRemoteDescription(rtc::Description(sdp, "answer"));
                    peer->has_remote_description = true;
                    fprintf(stderr, "[WebRTC] Remote description set for %s\n", peer->id.c_str());
                } catch (const std::exception& e) {
                    fprintf(stderr, "[WebRTC] ERROR setting remote description for %s: %s\n",
                            peer->id.c_str(), e.what());
                    return;
                }

                // Now add any pending ICE candidates
                if (!peer->pending_candidates.empty()) {
                    fprintf(stderr, "[WebRTC] Adding %zu pending ICE candidates\n",
                            peer->pending_candidates.size());
                    for (const auto& [candidate, mid] : peer->pending_candidates) {
                        try {
                            peer->pc->addRemoteCandidate(rtc::Candidate(candidate, mid));
                            fprintf(stderr, "[WebRTC] Added pending candidate: %s\n", mid.c_str());
                        } catch (const std::exception& e) {
                            fprintf(stderr, "[WebRTC] Failed to add pending candidate: %s\n", e.what());
                        }
                    }
                    peer->pending_candidates.clear();
                }
            }
        }
        else if (type == "candidate") {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = ws_to_peer_id_.find(ws.get());
            if (it != ws_to_peer_id_.end()) {
                auto peer = peers_[it->second];
                std::string candidate = json_get_string(msg, "candidate");
                std::string mid = json_get_string(msg, "mid");
                if (!candidate.empty()) {
                    if (peer->has_remote_description) {
                        // Remote description is set, add candidate immediately
                        fprintf(stderr, "[WebRTC] Adding ICE candidate from %s (mid=%s)\n",
                                peer->id.c_str(), mid.c_str());
                        try {
                            peer->pc->addRemoteCandidate(rtc::Candidate(candidate, mid));
                        } catch (const std::exception& e) {
                            fprintf(stderr, "[WebRTC] Failed to add candidate: %s\n", e.what());
                        }
                    } else {
                        // Queue candidate - remote description not set yet
                        fprintf(stderr, "[WebRTC] Queuing ICE candidate from %s (mid=%s)\n",
                                peer->id.c_str(), mid.c_str());
                        peer->pending_candidates.emplace_back(candidate, mid);
                    }
                }
            }
        }
    }

    void handle_input(const std::string& msg) {
        // Simple text protocol: M dx,dy | D btn | U btn | K code | k code
        if (msg.empty()) return;

        char cmd = msg[0];
        switch (cmd) {
            case 'M': g_mouse_move_count++; break;
            case 'D':
            case 'U': g_mouse_click_count++; break;
            case 'K':
            case 'k': g_key_count++; break;
        }

        // Forward input to emulator via control socket
        if (g_control_socket >= 0) {
            send_to_emulator(msg);
        }
    }

    std::atomic<bool> initialized_{false};
    std::atomic<int> peer_count_{0};

    int port_ = 8090;
    std::unique_ptr<rtc::WebSocketServer> ws_server_;

    std::mutex peers_mutex_;
    std::map<std::string, std::shared_ptr<PeerConnection>> peers_;
    std::map<rtc::WebSocket*, std::string> ws_to_peer_id_;

    uint32_t ssrc_ = 1;
};


/*
 * Main video processing loop
 */

static void video_loop(WebRTCServer& webrtc, H264Encoder& encoder) {
    uint64_t last_frame_count = 0;
    auto last_stats_time = std::chrono::steady_clock::now();
    auto last_emu_check = std::chrono::steady_clock::now();
    int frames_encoded = 0;

    // Track input counts between stats intervals
    uint64_t last_mouse_move = 0;
    uint64_t last_mouse_click = 0;
    uint64_t last_key = 0;

    fprintf(stderr, "Video: Starting frame processing loop\n");

    while (g_running) {
        // Check emulator process status periodically
        auto now = std::chrono::steady_clock::now();
        auto emu_check_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_emu_check);
        if (emu_check_elapsed.count() >= 500) {
            last_emu_check = now;

            // Check if emulator process exited
            int exit_code = check_emulator_status();
            if (exit_code > 0 && g_auto_start_emulator) {
                // Emulator exited - check if restart requested (exit code 75)
                if (exit_code == 75) {
                    fprintf(stderr, "Video: Auto-restarting emulator...\n");
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    start_emulator();
                }
            }

            // Handle restart request from web UI
            if (g_restart_emulator_requested.exchange(false)) {
                fprintf(stderr, "Video: Restart requested from web UI\n");
                stop_emulator();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                start_emulator();
            }
        }

        // Accept emulator connection if not connected
        if (!g_emulator_connected) {
            if (accept_emulator_connection()) {
                fprintf(stderr, "Video: Emulator connected\n");
            }
        }

        // Check if emulator disconnected (detect by checking socket)
        if (g_emulator_connected && g_control_socket >= 0) {
            char buf;
            ssize_t n = recv(g_control_socket, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
            if (n == 0) {
                // Connection closed
                fprintf(stderr, "Video: Emulator disconnected\n");
                close_emulator_connection();
                last_frame_count = 0;  // Reset frame tracking
            }
        }

        // Wait for frames
        if (!g_video_shm) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Check for new frame
        uint64_t current_count = ATOMIC_LOAD(g_video_shm->frame_count);
        if (current_count == last_frame_count) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        last_frame_count = current_count;

        // Read frame from shared memory
        uint32_t idx = ATOMIC_LOAD(g_video_shm->write_index);
        uint32_t width = g_video_shm->width;
        uint32_t height = g_video_shm->height;
        uint32_t stride = g_video_shm->stride;

        if (width == 0 || height == 0) continue;

        const uint8_t* frame_data = g_video_shm->frames[idx];

        // Check if keyframe requested (new peer connected)
        if (g_request_keyframe.exchange(false)) {
            encoder.request_keyframe();
        }

        // Encode frame
        auto encoded = encoder.encode(frame_data, width, height, stride);
        if (!encoded.empty()) {
            bool is_keyframe = encoder.is_keyframe(encoded);
            webrtc.send_frame(encoded, is_keyframe);
            frames_encoded++;
        }

        // Print stats every 3 seconds
        auto stats_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time);
        if (stats_elapsed.count() >= 3000) {
            float fps = frames_encoded * 1000.0f / stats_elapsed.count();

            // Calculate input rates
            uint64_t cur_mouse_move = g_mouse_move_count.load();
            uint64_t cur_mouse_click = g_mouse_click_count.load();
            uint64_t cur_key = g_key_count.load();

            uint64_t mouse_moves = cur_mouse_move - last_mouse_move;
            uint64_t mouse_clicks = cur_mouse_click - last_mouse_click;
            uint64_t keys = cur_key - last_key;

            float mouse_rate = mouse_moves * 1000.0f / stats_elapsed.count();

            fprintf(stderr, "[Server] fps=%.1f peers=%d emu=%s | input: mouse=%.0f/s clicks=%lu keys=%lu\n",
                    fps, webrtc.peer_count(),
                    g_emulator_pid > 0 ? "running" : "stopped",
                    mouse_rate, mouse_clicks, keys);

            last_mouse_move = cur_mouse_move;
            last_mouse_click = cur_mouse_click;
            last_key = cur_key;
            frames_encoded = 0;
            last_stats_time = now;
        }
    }

    fprintf(stderr, "Video: Exiting frame processing loop\n");
}


/*
 * Print usage
 */

static void print_usage(const char* program) {
    fprintf(stderr, "Usage: %s [options]\n", program);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -h, --help              Show this help\n");
    fprintf(stderr, "  -p, --http-port PORT    HTTP server port (default: 8000)\n");
    fprintf(stderr, "  -s, --signaling PORT    WebSocket signaling port (default: 8090)\n");
    fprintf(stderr, "  -e, --emulator PATH     Path to BasiliskII/SheepShaver executable\n");
    fprintf(stderr, "  -P, --prefs FILE        Emulator prefs file (default: basilisk_ii.prefs)\n");
    fprintf(stderr, "  -n, --no-auto-start     Don't auto-start emulator (wait for web UI)\n");
    fprintf(stderr, "  --video-shm NAME        Video shared memory name (default: PID-based)\n");
    fprintf(stderr, "  --control-sock PATH     Control socket path (default: PID-based)\n");
    fprintf(stderr, "  --roms PATH             ROMs directory (default: storage/roms)\n");
    fprintf(stderr, "  --images PATH           Disk images directory (default: storage/images)\n");
    fprintf(stderr, "\nEnvironment variables:\n");
    fprintf(stderr, "  MACEMU_VIDEO_SHM        Override video shared memory name\n");
    fprintf(stderr, "  MACEMU_CONTROL_SOCK     Override control socket path\n");
    fprintf(stderr, "  BASILISK_ROMS           Override ROMs directory\n");
    fprintf(stderr, "  BASILISK_IMAGES         Override disk images directory\n");
    fprintf(stderr, "\nThe server will look for emulators in this order:\n");
    fprintf(stderr, "  1. Path specified by --emulator\n");
    fprintf(stderr, "  2. ./BasiliskII or ./SheepShaver in current directory\n");
    fprintf(stderr, "  3. ../BasiliskII/src/Unix/BasiliskII\n");
}


/*
 * Main entry point
 */

int main(int argc, char* argv[]) {
    // Initialize IPC names with server PID (can be overridden by CLI/env)
    init_ipc_names();

    // Parse command line
    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"http-port",    required_argument, 0, 'p'},
        {"signaling",    required_argument, 0, 's'},
        {"video-shm",    required_argument, 0, 'v'},
        {"control-sock", required_argument, 0, 'c'},
        {"roms",         required_argument, 0, 'r'},
        {"images",       required_argument, 0, 'i'},
        {"emulator",     required_argument, 0, 'e'},
        {"prefs",        required_argument, 0, 'P'},
        {"no-auto-start", no_argument,      0, 'n'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hp:s:e:nP:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'p':
                g_http_port = atoi(optarg);
                break;
            case 's':
                g_signaling_port = atoi(optarg);
                break;
            case 'v':
                g_video_shm_name = optarg;
                break;
            case 'c':
                g_control_sock_path = optarg;
                break;
            case 'r':
                g_roms_path = optarg;
                break;
            case 'i':
                g_images_path = optarg;
                break;
            case 'e':
                g_emulator_path = optarg;
                break;
            case 'P':
                g_prefs_path = optarg;
                break;
            case 'n':
                g_auto_start_emulator = false;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Check environment variables
    if (const char* env = getenv("MACEMU_VIDEO_SHM")) g_video_shm_name = env;
    if (const char* env = getenv("MACEMU_CONTROL_SOCK")) g_control_sock_path = env;
    if (const char* env = getenv("BASILISK_ROMS")) g_roms_path = env;
    if (const char* env = getenv("BASILISK_IMAGES")) g_images_path = env;

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr, "=== macemu WebRTC Server ===\n");
    fprintf(stderr, "HTTP port:      %d\n", g_http_port);
    fprintf(stderr, "Signaling port: %d\n", g_signaling_port);
    fprintf(stderr, "Video SHM:      %s\n", g_video_shm_name.c_str());
    fprintf(stderr, "Control socket: %s\n", g_control_sock_path.c_str());
    fprintf(stderr, "Prefs file:     %s\n", g_prefs_path.c_str());
    fprintf(stderr, "ROMs path:      %s\n", g_roms_path.c_str());
    fprintf(stderr, "Images path:    %s\n", g_images_path.c_str());
    fprintf(stderr, "\n");

    // Create IPC resources (server owns these)
    if (!create_video_shm()) {
        fprintf(stderr, "Failed to create video shared memory\n");
        return 1;
    }

    if (!create_control_socket()) {
        fprintf(stderr, "Failed to create control socket\n");
        destroy_video_shm();
        return 1;
    }

    // Start HTTP server
    HTTPServer http_server;
    if (!http_server.start(g_http_port)) {
        fprintf(stderr, "Failed to start HTTP server\n");
        destroy_control_socket();
        destroy_video_shm();
        return 1;
    }

    // Start WebRTC server
    WebRTCServer webrtc;
    if (!webrtc.init(g_signaling_port)) {
        fprintf(stderr, "Failed to start WebRTC server\n");
        http_server.stop();
        destroy_control_socket();
        destroy_video_shm();
        return 1;
    }

    fprintf(stderr, "\nOpen http://localhost:%d in your browser\n", g_http_port);

    // Auto-start emulator if enabled
    if (g_auto_start_emulator) {
        std::string emu = find_emulator();
        if (!emu.empty()) {
            fprintf(stderr, "Found emulator: %s\n", emu.c_str());
            if (start_emulator()) {
                fprintf(stderr, "Emulator started, waiting for connection...\n\n");
            }
        } else {
            fprintf(stderr, "No emulator found. Use --emulator PATH or place BasiliskII in current directory.\n");
            fprintf(stderr, "Waiting for emulator to connect manually...\n\n");
        }
    } else {
        fprintf(stderr, "Auto-start disabled, waiting for emulator to connect...\n\n");
    }

    // Main video processing loop
    H264Encoder encoder;
    video_loop(webrtc, encoder);

    // Stop emulator if we started it
    stop_emulator();

    // Cleanup
    webrtc.shutdown();
    http_server.stop();
    destroy_control_socket();
    destroy_video_shm();

    fprintf(stderr, "Server: Shutdown complete\n");
    return 0;
}
