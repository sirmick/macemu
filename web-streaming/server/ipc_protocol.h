/*
 * IPC Protocol for macemu WebRTC Streaming - Version 3
 *
 * Architecture:
 * - Emulator OWNS resources (creates SHM and Unix socket)
 * - Server CONNECTS to emulator resources by PID
 * - Emulator converts Mac framebuffer to I420 (via libyuv)
 * - Server reads I420 directly for H.264 encoding (zero-copy)
 *
 * SHM naming: /macemu-video-{PID}
 * Socket naming: /tmp/macemu-{PID}.sock
 *
 * Triple buffering with atomics - no locks, no polling needed.
 */

#ifndef IPC_PROTOCOL_H
#define IPC_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
#include <atomic>
#define ATOMIC_UINT32 std::atomic<uint32_t>
#define ATOMIC_UINT64 std::atomic<uint64_t>
#define ATOMIC_LOAD(ptr) (ptr).load(std::memory_order_acquire)
#define ATOMIC_STORE(ptr, val) (ptr).store(val, std::memory_order_release)
#define ATOMIC_FETCH_ADD(ptr, val) (ptr).fetch_add(val, std::memory_order_acq_rel)
#else
#include <stdatomic.h>
#define ATOMIC_UINT32 _Atomic uint32_t
#define ATOMIC_UINT64 _Atomic uint64_t
#define ATOMIC_LOAD(ptr) atomic_load_explicit(&(ptr), memory_order_acquire)
#define ATOMIC_STORE(ptr, val) atomic_store_explicit(&(ptr), val, memory_order_release)
#define ATOMIC_FETCH_ADD(ptr, val) atomic_fetch_add_explicit(&(ptr), val, memory_order_acq_rel)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resource naming - emulator creates, server connects
 * Format: /macemu-video-{PID} and /tmp/macemu-{PID}.sock
 */
#define MACEMU_VIDEO_SHM_PREFIX "/macemu-video-"
#define MACEMU_CONTROL_SOCK_PREFIX "/tmp/macemu-"
#define MACEMU_CONTROL_SOCK_SUFFIX ".sock"

// Magic number and version
#define MACEMU_VIDEO_MAGIC 0x4D454D33  // "MEM3" (version 3 - I420)
#define MACEMU_IPC_VERSION 3

// Maximum supported resolution (1080p)
#define MACEMU_MAX_WIDTH  1920
#define MACEMU_MAX_HEIGHT 1080

// I420 frame size for max resolution: Y + U + V = w*h + w*h/4 + w*h/4 = w*h*1.5
#define MACEMU_I420_Y_SIZE  (MACEMU_MAX_WIDTH * MACEMU_MAX_HEIGHT)
#define MACEMU_I420_UV_SIZE (MACEMU_MAX_WIDTH * MACEMU_MAX_HEIGHT / 4)
#define MACEMU_I420_FRAME_SIZE (MACEMU_I420_Y_SIZE + 2 * MACEMU_I420_UV_SIZE)

// Number of frame buffers for triple buffering
#define MACEMU_NUM_BUFFERS 3

// Total SHM size: header + 3 I420 frames (~9.4 MB)
#define MACEMU_VIDEO_SHM_SIZE (sizeof(MacEmuVideoBuffer))

// Emulator state flags
#define MACEMU_STATE_STOPPED   0
#define MACEMU_STATE_RUNNING   1
#define MACEMU_STATE_PAUSED    2

/*
 * I420 Frame Layout (within each frame buffer):
 *
 * For a frame of actual size (width x height):
 * - Y plane: width * height bytes at offset 0
 * - U plane: (width/2) * (height/2) bytes at offset MACEMU_I420_Y_SIZE
 * - V plane: (width/2) * (height/2) bytes at offset MACEMU_I420_Y_SIZE + MACEMU_I420_UV_SIZE
 *
 * Strides are based on MAX dimensions for fixed layout:
 * - Y stride: MACEMU_MAX_WIDTH
 * - U/V stride: MACEMU_MAX_WIDTH / 2
 */

/*
 * Shared Video Buffer - Fixed size, emulator-owned
 *
 * Protocol:
 * 1. Emulator creates SHM at startup, initializes header
 * 2. Emulator converts Mac framebuffer to I420, writes to frames[write_index]
 * 3. On frame complete, emulator calls macemu_frame_complete()
 * 4. Server connects, maps SHM, reads from frames[ready_index]
 * 5. Server uses I420 data directly for OpenH264 encoding
 */
typedef struct {
    // Header - validated by server on connect
    uint32_t magic;              // Must be MACEMU_VIDEO_MAGIC
    uint32_t version;            // Protocol version (3)
    uint32_t pid;                // Emulator PID (for validation)
    uint32_t state;              // MACEMU_STATE_* (running/paused/stopped)

    // Current frame dimensions (actual, not max)
    uint32_t width;              // Actual frame width (≤ MACEMU_MAX_WIDTH)
    uint32_t height;             // Actual frame height (≤ MACEMU_MAX_HEIGHT)
    uint32_t _reserved[2];       // Future use, alignment

    // Triple buffer synchronization (lock-free)
    ATOMIC_UINT32 write_index;   // Buffer emulator is writing to (0-2)
    ATOMIC_UINT32 ready_index;   // Buffer ready for server to read (0-2)
    ATOMIC_UINT64 frame_count;   // Total frames completed (monotonic)
    ATOMIC_UINT64 timestamp_us;  // Timestamp of last completed frame (microseconds)

    // I420 frame buffers - fixed size for max resolution
    // Each frame: Y plane + U plane + V plane
    uint8_t frames[MACEMU_NUM_BUFFERS][MACEMU_I420_FRAME_SIZE];
} MacEmuVideoBuffer;

/*
 * Binary Input Protocol - sent over Unix socket from server to emulator
 *
 * Replaces JSON with fixed-size binary messages for efficiency.
 * Server converts browser keycodes to Mac keycodes before sending.
 */

// Input message types
#define MACEMU_INPUT_KEY       1   // Keyboard event
#define MACEMU_INPUT_MOUSE     2   // Mouse move/button
#define MACEMU_INPUT_COMMAND   3   // Emulator command (start/stop/reset)

// Key event flags
#define MACEMU_KEY_DOWN        0x01
#define MACEMU_KEY_UP          0x00

// Mouse button flags
#define MACEMU_MOUSE_LEFT      0x01
#define MACEMU_MOUSE_RIGHT     0x02
#define MACEMU_MOUSE_MIDDLE    0x04

// Command types
#define MACEMU_CMD_START       1
#define MACEMU_CMD_STOP        2
#define MACEMU_CMD_RESET       3
#define MACEMU_CMD_PAUSE       4
#define MACEMU_CMD_RESUME      5

// Input message header (4 bytes)
typedef struct {
    uint8_t type;                // MACEMU_INPUT_*
    uint8_t flags;               // Type-specific flags
    uint16_t _reserved;          // Alignment/future use
} MacEmuInputHeader;

// Keyboard input (8 bytes total)
typedef struct {
    MacEmuInputHeader hdr;       // type = MACEMU_INPUT_KEY
    uint8_t mac_keycode;         // Mac keycode (converted by server)
    uint8_t modifiers;           // Modifier state (shift, ctrl, alt, cmd)
    uint16_t _reserved;
} MacEmuKeyInput;

// Mouse input (12 bytes total)
typedef struct {
    MacEmuInputHeader hdr;       // type = MACEMU_INPUT_MOUSE
    int16_t x;                   // X position (absolute)
    int16_t y;                   // Y position (absolute)
    uint8_t buttons;             // Button state (MACEMU_MOUSE_*)
    uint8_t _reserved[3];
} MacEmuMouseInput;

// Command input (8 bytes total)
typedef struct {
    MacEmuInputHeader hdr;       // type = MACEMU_INPUT_COMMAND
    uint8_t command;             // MACEMU_CMD_*
    uint8_t _reserved[3];
} MacEmuCommandInput;

// Union for receiving any input type
typedef union {
    MacEmuInputHeader hdr;
    MacEmuKeyInput key;
    MacEmuMouseInput mouse;
    MacEmuCommandInput cmd;
} MacEmuInput;

/*
 * Helper functions
 */

// Get pointer to a specific frame buffer
static inline uint8_t* macemu_get_frame_ptr(MacEmuVideoBuffer* buf, uint32_t index) {
    return buf->frames[index];
}

// Get I420 plane pointers for a frame
static inline void macemu_get_i420_planes(MacEmuVideoBuffer* buf, uint32_t index,
                                          uint8_t** y, uint8_t** u, uint8_t** v) {
    uint8_t* frame = buf->frames[index];
    *y = frame;
    *u = frame + MACEMU_I420_Y_SIZE;
    *v = frame + MACEMU_I420_Y_SIZE + MACEMU_I420_UV_SIZE;
}

// Get I420 strides (fixed for max resolution)
static inline void macemu_get_i420_strides(int* y_stride, int* uv_stride) {
    *y_stride = MACEMU_MAX_WIDTH;
    *uv_stride = MACEMU_MAX_WIDTH / 2;
}

// Get pointer to the frame currently being written by emulator
static inline uint8_t* macemu_get_write_frame(MacEmuVideoBuffer* buf) {
    uint32_t idx = ATOMIC_LOAD(buf->write_index);
    return macemu_get_frame_ptr(buf, idx);
}

// Get pointer to the most recently completed frame (for server to read)
static inline uint8_t* macemu_get_ready_frame(MacEmuVideoBuffer* buf) {
    uint32_t idx = ATOMIC_LOAD(buf->ready_index);
    return macemu_get_frame_ptr(buf, idx);
}

// Get I420 planes for the ready frame (server use)
static inline void macemu_get_ready_i420(MacEmuVideoBuffer* buf,
                                         uint8_t** y, uint8_t** u, uint8_t** v) {
    uint32_t idx = ATOMIC_LOAD(buf->ready_index);
    macemu_get_i420_planes(buf, idx, y, u, v);
}

// Called by emulator after frame is complete - swaps buffers atomically
static inline void macemu_frame_complete(MacEmuVideoBuffer* buf, uint64_t timestamp_us) {
    uint32_t current = ATOMIC_LOAD(buf->write_index);
    uint32_t next = (current + 1) % MACEMU_NUM_BUFFERS;

    // Update timestamp before making frame visible
    ATOMIC_STORE(buf->timestamp_us, timestamp_us);

    // Mark current buffer as ready for reading
    ATOMIC_STORE(buf->ready_index, current);

    // Move to next buffer for writing
    ATOMIC_STORE(buf->write_index, next);

    // Increment frame count (server can use this to detect new frames)
    ATOMIC_FETCH_ADD(buf->frame_count, 1);
}

// Initialize video buffer (called by emulator)
static inline void macemu_init_video_buffer(MacEmuVideoBuffer* buf, uint32_t pid,
                                            uint32_t width, uint32_t height) {
    buf->magic = MACEMU_VIDEO_MAGIC;
    buf->version = MACEMU_IPC_VERSION;
    buf->pid = pid;
    buf->state = MACEMU_STATE_STOPPED;
    buf->width = width;
    buf->height = height;
    ATOMIC_STORE(buf->write_index, 0);
    ATOMIC_STORE(buf->ready_index, 0);
    ATOMIC_STORE(buf->frame_count, 0);
    ATOMIC_STORE(buf->timestamp_us, 0);
}

// Validate video buffer (called by server on connect)
static inline int macemu_validate_video_buffer(const MacEmuVideoBuffer* buf, uint32_t expected_pid) {
    if (buf->magic != MACEMU_VIDEO_MAGIC) return -1;
    if (buf->version != MACEMU_IPC_VERSION) return -2;
    if (buf->pid != expected_pid) return -3;
    if (buf->width > MACEMU_MAX_WIDTH || buf->height > MACEMU_MAX_HEIGHT) return -4;
    return 0;
}

// Calculate actual I420 frame size for current resolution
static inline size_t macemu_actual_i420_size(uint32_t width, uint32_t height) {
    size_t y_size = (size_t)width * height;
    size_t uv_size = ((size_t)width / 2) * (height / 2);
    return y_size + 2 * uv_size;
}

#ifdef __cplusplus
}
#endif

#endif // IPC_PROTOCOL_H
