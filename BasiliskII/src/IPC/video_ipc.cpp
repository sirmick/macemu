/*
 *  video_ipc.cpp - IPC-based video driver for standalone WebRTC server
 *
 *  Basilisk II (C) 1997-2008 Christian Bauer
 *  IPC mode (C) 2024
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 *  NOTES:
 *    This video driver writes frames to POSIX shared memory and receives
 *    input via a Unix domain socket. A standalone WebRTC server reads the
 *    frames and handles browser connections.
 *
 *    This allows the WebRTC server to run independently and be shared
 *    between BasiliskII and SheepShaver.
 */

#include "sysdeps.h"

#ifdef ENABLE_IPC_VIDEO

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

// POSIX IPC
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include "cpu_emulation.h"
#include "main.h"
#include "adb.h"
#include "macos_util.h"
#include "prefs.h"
#include "user_strings.h"
#include "video.h"
#include "video_defs.h"
#include "video_blit.h"
#include "vm_alloc.h"

// IPC protocol definitions
#include "ipc_protocol.h"

#define DEBUG 0
#include "debug.h"

// Forward declarations
static bool IPC_VideoInit(bool classic);
static void IPC_VideoExit(void);
static void IPC_VideoQuitFullScreen(void);
static void IPC_VideoInterrupt(void);
static void IPC_VideoRefresh(void);

// Supported video modes
using std::vector;
static vector<VIDEO_MODE> VideoModes;

// Mac Screen Width and Height
#ifdef USE_SDL_VIDEO
extern uint32 MacScreenWidth;
extern uint32 MacScreenHeight;
#else
uint32 MacScreenWidth;
uint32 MacScreenHeight;
#endif

// Global variables
static uint32 frame_skip;
static uint8 *the_buffer = NULL;           // Mac frame buffer
static uint32 the_buffer_size;             // Size of allocated buffer
static bool classic_mode = false;          // Classic Mac video mode

// Frame buffer properties
static int frame_width = 640;
static int frame_height = 480;
static int frame_depth = 32;               // Bits per pixel
static int frame_bytes_per_row;

// Threading
static std::thread video_thread;
static std::atomic<bool> video_thread_running(false);
static std::mutex frame_mutex;

// Pending mouse input (from control socket)
static std::atomic<int> pending_mouse_x(-1);
static std::atomic<int> pending_mouse_y(-1);
static std::atomic<bool> pending_mouse_update(false);

// Palette for indexed color modes
static uint8 ipc_palette[256 * 3];

// IPC handles
static int video_shm_fd = -1;
static int audio_shm_fd = -1;
static int control_socket = -1;
static MacEmuVideoBuffer* video_shm = nullptr;
static MacEmuAudioBuffer* audio_shm = nullptr;

// Control socket thread
static std::thread control_thread;
static std::atomic<bool> control_thread_running(false);

// Persistent buffer
static uint8 *persistent_buffer = NULL;
static uint32 persistent_buffer_size = 0;


/*
 *  IPC path configuration
 *  Server provides shm name via handshake; control socket path from env/prefs
 */

static std::string g_control_sock_path;  // Set from env or prefs
static std::string g_video_shm_name;     // Received from server handshake

static std::string get_control_sock_path() {
    if (!g_control_sock_path.empty()) return g_control_sock_path;
    const char* env = getenv("MACEMU_CONTROL_SOCK");
    return env ? env : MACEMU_CONTROL_SOCK_DEFAULT;
}


/*
 *  Open shared memory for video (created by server)
 */

static bool open_video_shm(const std::string& shm_name, int width, int height) {
    // Open existing shared memory created by server
    video_shm_fd = shm_open(shm_name.c_str(), O_RDWR, 0);
    if (video_shm_fd < 0) {
        fprintf(stderr, "IPC: Failed to open video shared memory '%s': %s\n",
                shm_name.c_str(), strerror(errno));
        return false;
    }

    size_t shm_size = macemu_video_buffer_size();

    // Map shared memory
    video_shm = (MacEmuVideoBuffer*)mmap(nullptr, shm_size,
                                          PROT_READ | PROT_WRITE, MAP_SHARED,
                                          video_shm_fd, 0);
    if (video_shm == MAP_FAILED) {
        fprintf(stderr, "IPC: Failed to map video shared memory: %s\n", strerror(errno));
        close(video_shm_fd);
        video_shm_fd = -1;
        video_shm = nullptr;
        return false;
    }

    // Validate magic
    if (video_shm->magic != MACEMU_VIDEO_MAGIC) {
        fprintf(stderr, "IPC: Invalid video shm magic (got 0x%08X, expected 0x%08X)\n",
                video_shm->magic, MACEMU_VIDEO_MAGIC);
        munmap(video_shm, shm_size);
        close(video_shm_fd);
        video_shm_fd = -1;
        video_shm = nullptr;
        return false;
    }

    // Update dimensions in shm (server initializes with defaults)
    video_shm->width = width;
    video_shm->height = height;
    video_shm->stride = width * 4;
    video_shm->format = 0;  // RGBA

    g_video_shm_name = shm_name;
    fprintf(stderr, "IPC: Opened video shared memory '%s' (%dx%d)\n",
            shm_name.c_str(), width, height);

    return true;
}

static void cleanup_video_shm() {
    if (video_shm && video_shm != MAP_FAILED) {
        munmap(video_shm, macemu_video_buffer_size());
        video_shm = nullptr;
    }
    if (video_shm_fd >= 0) {
        close(video_shm_fd);
        // Don't unlink - server owns the shm
        video_shm_fd = -1;
    }
}


/*
 *  Open shared memory for audio (optional, created by server)
 */

static std::string g_audio_shm_name;  // Received from server handshake

static bool open_audio_shm(const std::string& shm_name) {
    audio_shm_fd = shm_open(shm_name.c_str(), O_RDWR, 0);
    if (audio_shm_fd < 0) {
        // Audio is optional, don't warn loudly
        return false;
    }

    size_t shm_size = macemu_audio_buffer_size();
    audio_shm = (MacEmuAudioBuffer*)mmap(nullptr, shm_size,
                                          PROT_READ | PROT_WRITE, MAP_SHARED,
                                          audio_shm_fd, 0);
    if (audio_shm == MAP_FAILED) {
        close(audio_shm_fd);
        audio_shm_fd = -1;
        audio_shm = nullptr;
        return false;
    }

    // Validate magic
    if (audio_shm->magic != MACEMU_AUDIO_MAGIC) {
        munmap(audio_shm, shm_size);
        close(audio_shm_fd);
        audio_shm_fd = -1;
        audio_shm = nullptr;
        return false;
    }

    g_audio_shm_name = shm_name;
    fprintf(stderr, "IPC: Opened audio shared memory '%s'\n", shm_name.c_str());
    return true;
}

static void cleanup_audio_shm() {
    if (audio_shm && audio_shm != MAP_FAILED) {
        munmap(audio_shm, macemu_audio_buffer_size());
        audio_shm = nullptr;
    }
    if (audio_shm_fd >= 0) {
        close(audio_shm_fd);
        // Don't unlink - server owns the shm
        audio_shm_fd = -1;
    }
}


/*
 *  Control socket - handles input from WebRTC server
 */

// Convert browser keycode to Mac ADB keycode
static int browser_to_mac_keycode(int keycode) {
    if (keycode >= 65 && keycode <= 90) {
        static const int letter_map[] = {
            0x00, 0x0B, 0x08, 0x02, 0x0E, 0x03, 0x05, 0x04,
            0x22, 0x26, 0x28, 0x25, 0x2E, 0x2D, 0x1F, 0x23,
            0x0C, 0x0F, 0x01, 0x11, 0x20, 0x09, 0x0D, 0x07,
            0x10, 0x06
        };
        return letter_map[keycode - 65];
    } else if (keycode >= 48 && keycode <= 57) {
        static const int number_map[] = {
            0x1D, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1A, 0x1C, 0x19
        };
        return number_map[keycode - 48];
    } else {
        switch (keycode) {
            case 8: return 0x33;   // Backspace
            case 9: return 0x30;   // Tab
            case 13: return 0x24;  // Enter
            case 16: return 0x38;  // Shift
            case 17: return 0x36;  // Ctrl -> Command
            case 18: return 0x3A;  // Alt -> Option
            case 27: return 0x35;  // Escape
            case 32: return 0x31;  // Space
            case 37: return 0x3B;  // Left
            case 38: return 0x3E;  // Up
            case 39: return 0x3C;  // Right
            case 40: return 0x3D;  // Down
            case 46: return 0x75;  // Delete
            case 91: return 0x37;  // Meta -> Command
            case 186: return 0x29; // ;
            case 187: return 0x18; // =
            case 188: return 0x2B; // ,
            case 189: return 0x1B; // -
            case 190: return 0x2F; // .
            case 191: return 0x2C; // /
            case 192: return 0x32; // `
            case 219: return 0x21; // [
            case 220: return 0x2A; // backslash
            case 221: return 0x1E; // ]
            case 222: return 0x27; // '
            default: return -1;
        }
    }
}

// Accumulated mouse deltas (for relative mouse mode)
static std::atomic<int> mouse_delta_x(0);
static std::atomic<int> mouse_delta_y(0);

static void process_control_message(const char* msg) {
    // Simple text protocol: M dx,dy | D btn | U btn | K code | k code
    // Also supports JSON for restart/shutdown commands

    if (!msg || !msg[0]) return;

    char cmd = msg[0];
    const char* args = msg + 1;

    switch (cmd) {
        case 'M': {
            // Mouse move: M dx,dy
            int dx = 0, dy = 0;
            if (sscanf(args, "%d,%d", &dx, &dy) == 2) {
                mouse_delta_x.fetch_add(dx);
                mouse_delta_y.fetch_add(dy);
                pending_mouse_update.store(true);
            }
            break;
        }
        case 'D': {
            // Mouse down: D button
            int button = atoi(args);
            ADBMouseDown(button);
            break;
        }
        case 'U': {
            // Mouse up: U button
            int button = atoi(args);
            ADBMouseUp(button);
            break;
        }
        case 'K': {
            // Key down: K keycode
            int keycode = atoi(args);
            int mac_code = browser_to_mac_keycode(keycode);
            if (mac_code >= 0) {
                ADBKeyDown(mac_code);
            }
            break;
        }
        case 'k': {
            // Key up: k keycode
            int keycode = atoi(args);
            int mac_code = browser_to_mac_keycode(keycode);
            if (mac_code >= 0) {
                ADBKeyUp(mac_code);
            }
            break;
        }
        case '{': {
            // JSON command (restart, shutdown)
            const char* type_start = strstr(msg, "\"type\":\"");
            if (type_start) {
                type_start += 8;
                if (strncmp(type_start, "restart", 7) == 0) {
                    fprintf(stderr, "IPC: Restart requested via control socket\n");
                    exit(75);
                } else if (strncmp(type_start, "shutdown", 8) == 0) {
                    fprintf(stderr, "IPC: Shutdown requested via control socket\n");
                    exit(0);
                }
            }
            break;
        }
    }
}

static void control_socket_thread() {
    char buffer[4096];
    std::string partial;

    while (control_thread_running && control_socket >= 0) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(control_socket, &readfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  // 100ms timeout

        int ret = select(control_socket + 1, &readfds, nullptr, nullptr, &tv);
        if (ret <= 0) continue;

        ssize_t n = recv(control_socket, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
            // Connection closed or error
            fprintf(stderr, "IPC: Control socket disconnected\n");
            break;
        }

        buffer[n] = '\0';
        partial += buffer;

        // Process newline-delimited messages
        size_t pos;
        while ((pos = partial.find('\n')) != std::string::npos) {
            std::string msg = partial.substr(0, pos);
            partial.erase(0, pos + 1);
            if (!msg.empty()) {
                process_control_message(msg.c_str());
            }
        }
    }
}

// Simple JSON string extractor
static std::string json_get_string(const char* json, const char* key) {
    std::string search = std::string("\"") + key + "\":\"";
    const char* start = strstr(json, search.c_str());
    if (!start) return "";
    start += search.length();
    const char* end = strchr(start, '"');
    if (!end) return "";
    return std::string(start, end - start);
}

static bool connect_to_server(std::string& video_shm_out, std::string& audio_shm_out) {
    std::string sock_path = get_control_sock_path();

    fprintf(stderr, "IPC: Connecting to server at '%s'...\n", sock_path.c_str());

    // Create socket
    control_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (control_socket < 0) {
        fprintf(stderr, "IPC: Failed to create socket: %s\n", strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    // Try connecting with retries
    int retries = 10;
    while (retries > 0) {
        if (connect(control_socket, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            break;
        }
        if (errno == ENOENT || errno == ECONNREFUSED) {
            fprintf(stderr, "IPC: Server not ready, retrying... (%d)\n", retries);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            retries--;
        } else {
            fprintf(stderr, "IPC: Connect failed: %s\n", strerror(errno));
            close(control_socket);
            control_socket = -1;
            return false;
        }
    }

    if (retries == 0) {
        fprintf(stderr, "IPC: Could not connect to server (not running?)\n");
        close(control_socket);
        control_socket = -1;
        return false;
    }

    fprintf(stderr, "IPC: Connected to server\n");

    // Wait for handshake from server
    char buf[1024];
    ssize_t n = recv(control_socket, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        fprintf(stderr, "IPC: Failed to receive handshake: %s\n",
                n == 0 ? "connection closed" : strerror(errno));
        close(control_socket);
        control_socket = -1;
        return false;
    }
    buf[n] = '\0';

    // Parse handshake: {"type":"hello","version":1,"video_shm":"/macemu-video-1234"}
    std::string type = json_get_string(buf, "type");
    if (type != "hello") {
        fprintf(stderr, "IPC: Unexpected handshake type: %s\n", type.c_str());
        close(control_socket);
        control_socket = -1;
        return false;
    }

    video_shm_out = json_get_string(buf, "video_shm");
    audio_shm_out = json_get_string(buf, "audio_shm");

    if (video_shm_out.empty()) {
        fprintf(stderr, "IPC: No video_shm in handshake\n");
        close(control_socket);
        control_socket = -1;
        return false;
    }

    fprintf(stderr, "IPC: Server handshake OK (video_shm=%s)\n", video_shm_out.c_str());

    // Start control socket reader thread
    control_thread_running = true;
    control_thread = std::thread(control_socket_thread);

    return true;
}

static void cleanup_control_socket() {
    control_thread_running = false;

    if (control_socket >= 0) {
        shutdown(control_socket, SHUT_RDWR);
        close(control_socket);
        control_socket = -1;
    }

    if (control_thread.joinable()) {
        control_thread.join();
    }
    // Don't unlink - server owns the socket
}


/*
 *  Framebuffer allocation
 */

static bool allocate_framebuffer(uint32 width, uint32 height, video_depth depth, uint32 mode_bytes_per_row = 0)
{
    uint32 trivial_bpr = TrivialBytesPerRow(width, depth);
    if (mode_bytes_per_row > 0) {
        frame_bytes_per_row = mode_bytes_per_row;
    } else {
        frame_bytes_per_row = trivial_bpr;
    }

    uint32 needed_size = frame_bytes_per_row * height;

    if (persistent_buffer != NULL && persistent_buffer_size >= needed_size) {
        the_buffer = persistent_buffer;
        the_buffer_size = needed_size;
    } else {
        if (persistent_buffer != NULL) {
            vm_release(persistent_buffer, persistent_buffer_size);
            persistent_buffer = NULL;
        }

        uint32 max_size = 1024 * 768 * 4;
        if (needed_size > max_size) max_size = needed_size;

        persistent_buffer = (uint8 *)vm_acquire(max_size, VM_MAP_DEFAULT | VM_MAP_32BIT);
        if (persistent_buffer == VM_MAP_FAILED || persistent_buffer == NULL) {
            fprintf(stderr, "IPC: Failed to allocate frame buffer\n");
            return false;
        }
        persistent_buffer_size = max_size;

        the_buffer = persistent_buffer;
        the_buffer_size = needed_size;
    }

    memset(the_buffer, 0x80, the_buffer_size);

    frame_width = width;
    frame_height = height;

    switch (depth) {
        case VDEPTH_1BIT:  frame_depth = 1; break;
        case VDEPTH_2BIT:  frame_depth = 2; break;
        case VDEPTH_4BIT:  frame_depth = 4; break;
        case VDEPTH_8BIT:  frame_depth = 8; break;
        case VDEPTH_16BIT: frame_depth = 16; break;
        case VDEPTH_32BIT: frame_depth = 32; break;
        default:           frame_depth = 8; break;
    }

    // Update shared memory dimensions
    if (video_shm) {
        video_shm->width = width;
        video_shm->height = height;
        video_shm->stride = width * 4;
    }

    return true;
}

static void free_framebuffer()
{
    the_buffer = NULL;
    the_buffer_size = 0;
}

static void free_persistent_buffer()
{
    if (persistent_buffer && persistent_buffer != VM_MAP_FAILED) {
        vm_release(persistent_buffer, persistent_buffer_size);
        persistent_buffer = NULL;
        persistent_buffer_size = 0;
    }
}


/*
 *  Convert frame buffer to RGBA and write to shared memory
 */

static void push_frame_to_shm()
{
    if (!the_buffer || !video_shm) return;

    std::lock_guard<std::mutex> lock(frame_mutex);

    // Calculate next buffer index (triple buffering)
    uint32_t current = atomic_load(&video_shm->write_index);
    uint32_t next = (current + 1) % 3;

    uint8_t* dst = video_shm->frames[next];
    uint8_t* src = the_buffer;

    size_t frame_size = (size_t)frame_width * frame_height * 4;
    if (frame_size > MACEMU_MAX_FRAME_SIZE) {
        fprintf(stderr, "IPC: Frame too large for shared memory\n");
        return;
    }

    switch (frame_depth) {
        case 32:
            // Mac stores 32-bit pixels as big-endian ARGB
            for (int y = 0; y < frame_height; y++) {
                uint8_t *src_row = src + y * frame_bytes_per_row;
                uint8_t *dst_row = dst + y * frame_width * 4;
                for (int x = 0; x < frame_width; x++) {
                    uint8_t *pixel = src_row + x * 4;
                    dst_row[x * 4 + 0] = pixel[1];  // R
                    dst_row[x * 4 + 1] = pixel[2];  // G
                    dst_row[x * 4 + 2] = pixel[3];  // B
                    dst_row[x * 4 + 3] = 0xFF;      // A
                }
            }
            break;

        case 16:
            // Mac stores 16-bit pixels as big-endian RGB555
            for (int y = 0; y < frame_height; y++) {
                uint8_t *src_row = src + y * frame_bytes_per_row;
                uint8_t *dst_row = dst + y * frame_width * 4;
                for (int x = 0; x < frame_width; x++) {
                    uint8_t *pb = src_row + x * 2;
                    uint16_t pixel = (pb[0] << 8) | pb[1];
                    dst_row[x * 4 + 0] = ((pixel >> 10) & 0x1F) << 3;  // R
                    dst_row[x * 4 + 1] = ((pixel >> 5) & 0x1F) << 3;   // G
                    dst_row[x * 4 + 2] = (pixel & 0x1F) << 3;          // B
                    dst_row[x * 4 + 3] = 0xFF;                          // A
                }
            }
            break;

        case 8:
            for (int y = 0; y < frame_height; y++) {
                uint8_t *src_row = src + y * frame_bytes_per_row;
                uint8_t *dst_row = dst + y * frame_width * 4;
                for (int x = 0; x < frame_width; x++) {
                    uint8_t idx = src_row[x];
                    dst_row[x * 4 + 0] = ipc_palette[idx * 3];
                    dst_row[x * 4 + 1] = ipc_palette[idx * 3 + 1];
                    dst_row[x * 4 + 2] = ipc_palette[idx * 3 + 2];
                    dst_row[x * 4 + 3] = 0xFF;
                }
            }
            break;

        case 4:
            for (int y = 0; y < frame_height; y++) {
                uint8_t *src_row = src + y * frame_bytes_per_row;
                uint8_t *dst_row = dst + y * frame_width * 4;
                for (int x = 0; x < frame_width; x++) {
                    int byte_idx = x / 2;
                    int nibble = (x & 1) ? (src_row[byte_idx] & 0x0F) : ((src_row[byte_idx] >> 4) & 0x0F);
                    dst_row[x * 4 + 0] = ipc_palette[nibble * 3];
                    dst_row[x * 4 + 1] = ipc_palette[nibble * 3 + 1];
                    dst_row[x * 4 + 2] = ipc_palette[nibble * 3 + 2];
                    dst_row[x * 4 + 3] = 0xFF;
                }
            }
            break;

        case 2:
            for (int y = 0; y < frame_height; y++) {
                uint8_t *src_row = src + y * frame_bytes_per_row;
                uint8_t *dst_row = dst + y * frame_width * 4;
                for (int x = 0; x < frame_width; x++) {
                    int byte_idx = x / 4;
                    int shift = 6 - (x & 3) * 2;
                    int idx = (src_row[byte_idx] >> shift) & 0x03;
                    dst_row[x * 4 + 0] = ipc_palette[idx * 3];
                    dst_row[x * 4 + 1] = ipc_palette[idx * 3 + 1];
                    dst_row[x * 4 + 2] = ipc_palette[idx * 3 + 2];
                    dst_row[x * 4 + 3] = 0xFF;
                }
            }
            break;

        case 1:
            for (int y = 0; y < frame_height; y++) {
                uint8_t *src_row = src + y * frame_bytes_per_row;
                uint8_t *dst_row = dst + y * frame_width * 4;
                for (int x = 0; x < frame_width; x++) {
                    int byte_idx = x / 8;
                    int bit = 7 - (x & 7);
                    int idx = (src_row[byte_idx] >> bit) & 0x01;
                    dst_row[x * 4 + 0] = ipc_palette[idx * 3];
                    dst_row[x * 4 + 1] = ipc_palette[idx * 3 + 1];
                    dst_row[x * 4 + 2] = ipc_palette[idx * 3 + 2];
                    dst_row[x * 4 + 3] = 0xFF;
                }
            }
            break;

        default:
            // Fill with magenta to indicate error
            for (size_t i = 0; i < frame_width * frame_height; i++) {
                dst[i * 4 + 0] = 0xFF;
                dst[i * 4 + 1] = 0x00;
                dst[i * 4 + 2] = 0xFF;
                dst[i * 4 + 3] = 0xFF;
            }
            break;
    }

    // Update timestamp and atomically publish the frame
    auto now = std::chrono::steady_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    atomic_store(&video_shm->timestamp_us, (uint64_t)us);
    atomic_fetch_add(&video_shm->frame_count, 1);
    atomic_store(&video_shm->write_index, next);
}


/*
 *  Video refresh thread
 */

static void video_refresh_thread()
{
    auto last_frame_time = std::chrono::steady_clock::now();
    auto last_stats_time = std::chrono::steady_clock::now();
    int target_fps = 30;
    int frames_sent = 0;
    int mouse_updates = 0;

    // Use relative mouse mode since browser uses pointer lock
    ADBSetRelMouseMode(true);

    while (video_thread_running) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_frame_time);

        // Process pending mouse delta updates (relative mode)
        if (pending_mouse_update.exchange(false)) {
            int dx = mouse_delta_x.exchange(0);
            int dy = mouse_delta_y.exchange(0);
            if (dx != 0 || dy != 0) {
                ADBMouseMoved(dx, dy);
                mouse_updates++;
            }
        }

        // Print stats every 3 seconds
        auto stats_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time);
        if (stats_elapsed.count() >= 3000) {
            float fps = frames_sent * 1000.0f / stats_elapsed.count();
            fprintf(stderr, "[IPC] fps=%.1f frames=%d mouse=%d\n", fps, frames_sent, mouse_updates);
            frames_sent = 0;
            mouse_updates = 0;
            last_stats_time = now;
        }

        // Rate limit to target FPS
        int frame_interval = 1000 / target_fps;
        if (elapsed.count() < frame_interval) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        last_frame_time = now;

        // Push frame to shared memory
        push_frame_to_shm();
        frames_sent++;
    }
}


/*
 *  IPC monitor descriptor
 */

class IPC_monitor_desc : public monitor_desc {
public:
    IPC_monitor_desc(const vector<video_mode> &available_modes,
                     video_depth default_depth, uint32 default_id)
        : monitor_desc(available_modes, default_depth, default_id) {}
    ~IPC_monitor_desc() {}

    virtual void switch_to_current_mode(void);
    virtual void set_palette(uint8 *pal, int num);
    virtual void set_gamma(uint8 *gamma, int num);

    void video_close(void);
};

static IPC_monitor_desc *the_monitor = NULL;


void IPC_monitor_desc::switch_to_current_mode(void)
{
    const video_mode &mode = get_current_mode();

    free_framebuffer();

    if (!allocate_framebuffer(mode.x, mode.y, mode.depth, mode.bytes_per_row)) {
        fprintf(stderr, "IPC: Failed to allocate frame buffer for mode %dx%d\n",
                mode.x, mode.y);
        return;
    }

    uint32 mac_addr = (uint32)Host2MacAddr(the_buffer);
    set_mac_frame_base(mac_addr);

    MacScreenWidth = mode.x;
    MacScreenHeight = mode.y;
}


void IPC_monitor_desc::set_palette(uint8 *pal, int num)
{
    std::lock_guard<std::mutex> lock(frame_mutex);

    for (int i = 0; i < num; i++) {
        ipc_palette[i * 3] = pal[i * 3];
        ipc_palette[i * 3 + 1] = pal[i * 3 + 1];
        ipc_palette[i * 3 + 2] = pal[i * 3 + 2];
    }
}


void IPC_monitor_desc::set_gamma(uint8 *gamma, int num)
{
    // Not implemented
}


void IPC_monitor_desc::video_close(void)
{
    video_thread_running = false;
    if (video_thread.joinable()) {
        video_thread.join();
    }

    free_framebuffer();
}


/*
 *  Initialization
 */

static void add_mode(uint32 width, uint32 height, uint32 resolution_id,
                     uint32 bytes_per_row, video_depth depth)
{
    video_mode mode;
    mode.x = width;
    mode.y = height;
    mode.resolution_id = resolution_id;
    mode.bytes_per_row = bytes_per_row;
    mode.depth = depth;
    VideoModes.push_back(mode);
}

static void add_standard_modes(uint32 width, uint32 height, uint32 resolution_id)
{
    add_mode(width, height, resolution_id,
             TrivialBytesPerRow(width, VDEPTH_1BIT), VDEPTH_1BIT);
    add_mode(width, height, resolution_id,
             TrivialBytesPerRow(width, VDEPTH_2BIT), VDEPTH_2BIT);
    add_mode(width, height, resolution_id,
             TrivialBytesPerRow(width, VDEPTH_4BIT), VDEPTH_4BIT);
    add_mode(width, height, resolution_id,
             TrivialBytesPerRow(width, VDEPTH_8BIT), VDEPTH_8BIT);
    add_mode(width, height, resolution_id,
             TrivialBytesPerRow(width, VDEPTH_16BIT), VDEPTH_16BIT);
    add_mode(width, height, resolution_id,
             TrivialBytesPerRow(width, VDEPTH_32BIT), VDEPTH_32BIT);
}


#ifndef USE_SDL_VIDEO

#ifdef SHEEPSHAVER
bool VideoInit(void)
{
    const bool classic = false;
#else
bool VideoInit(bool classic)
{
#endif
    return IPC_VideoInit(classic);
}

#endif // !USE_SDL_VIDEO


static bool IPC_VideoInit(bool classic)
{
    classic_mode = classic;

    frame_skip = PrefsFindInt32("frameskip");

    // Get screen mode from preferences
    int default_width = 640;
    int default_height = 480;
    const char *mode_str = PrefsFindString("screen");

    if (mode_str) {
        if (sscanf(mode_str, "win/%d/%d", &default_width, &default_height) != 2) {
            if (sscanf(mode_str, "dga/%d/%d", &default_width, &default_height) != 2) {
                sscanf(mode_str, "%d/%d", &default_width, &default_height);
            }
        }
    }

    if (default_width < 512) default_width = 512;
    if (default_width > 2560) default_width = 2560;
    if (default_height < 384) default_height = 384;
    if (default_height > 1600) default_height = 1600;

    if (classic) {
        default_width = 512;
        default_height = 342;
    }

    // Initialize palette
    for (int i = 0; i < 256; i++) {
        ipc_palette[i * 3] = 255 - i;
        ipc_palette[i * 3 + 1] = 255 - i;
        ipc_palette[i * 3 + 2] = 255 - i;
    }

    // Initialize IPC - connect to server first
    fprintf(stderr, "IPC: Initializing shared memory video driver\n");

    std::string video_shm_name, audio_shm_name;
    if (!connect_to_server(video_shm_name, audio_shm_name)) {
        fprintf(stderr, "IPC: Failed to connect to WebRTC server\n");
        return false;
    }

    if (!open_video_shm(video_shm_name, default_width, default_height)) {
        cleanup_control_socket();
        return false;
    }

    if (!audio_shm_name.empty()) {
        open_audio_shm(audio_shm_name);  // Optional
    }

    // Build list of video modes
    VideoModes.clear();

    if (classic) {
        add_mode(512, 342, 0x80, 64, VDEPTH_1BIT);
    } else {
        add_standard_modes(default_width, default_height, 0x80);

        if (default_width != 640 || default_height != 480)
            add_standard_modes(640, 480, 0x81);
        if (default_width != 800 || default_height != 600)
            add_standard_modes(800, 600, 0x82);
        if (default_width != 1024 || default_height != 768)
            add_standard_modes(1024, 768, 0x83);
    }

    // Create monitor descriptor
    video_depth default_depth = classic ? VDEPTH_1BIT : VDEPTH_32BIT;
    uint32 default_bytes_per_row = TrivialBytesPerRow(default_width, default_depth);

    the_monitor = new IPC_monitor_desc(VideoModes, default_depth, 0x80);
    VideoMonitors.push_back(the_monitor);

    // Allocate initial frame buffer
    if (!allocate_framebuffer(default_width, default_height, default_depth, default_bytes_per_row)) {
        cleanup_control_socket();
        cleanup_video_shm();
        cleanup_audio_shm();
        return false;
    }

    uint32 mac_frame_base = (uint32)Host2MacAddr(the_buffer);
    the_monitor->set_mac_frame_base(mac_frame_base);

    MacScreenWidth = default_width;
    MacScreenHeight = default_height;

    // Start video refresh thread
    video_thread_running = true;
    video_thread = std::thread(video_refresh_thread);

    fprintf(stderr, "IPC: Video initialized (%dx%d)\n", default_width, default_height);

    return true;
}


/*
 *  Deinitialization
 */

#ifndef USE_SDL_VIDEO
void VideoExit(void)
{
    IPC_VideoExit();
}
#endif

static void IPC_VideoExit(void)
{
    if (the_monitor) {
        the_monitor->video_close();
    }

    cleanup_control_socket();
    cleanup_video_shm();
    cleanup_audio_shm();
    free_persistent_buffer();

    VideoModes.clear();

    fprintf(stderr, "IPC: Video shutdown complete\n");
}


static void IPC_VideoQuitFullScreen(void)
{
    // Nothing to do
}

#ifndef USE_SDL_VIDEO
void VideoQuitFullScreen(void)
{
    IPC_VideoQuitFullScreen();
}
#endif


static void IPC_VideoInterrupt(void)
{
    // Nothing to do - handled by video thread
}

#ifndef USE_SDL_VIDEO
void VideoInterrupt(void)
{
    IPC_VideoInterrupt();
}
#endif


static void IPC_VideoRefresh(void)
{
    // Nothing to do - handled by video thread
}

#ifndef USE_SDL_VIDEO
void VideoRefresh(void)
{
    IPC_VideoRefresh();
}
#endif

#endif // ENABLE_IPC_VIDEO
