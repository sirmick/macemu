/*
 * Video Stream Abstraction
 *
 * Complete abstraction from SHM frame data to network transmission.
 * Each stream handles:
 * - Encoding (via VideoCodec)
 * - Protocol-specific logic (dirty rects, heartbeats, first frame)
 * - Metadata packaging (timestamps, ping echoes)
 * - Transport (WebRTC RTP or DataChannel)
 */

#ifndef VIDEO_STREAM_H
#define VIDEO_STREAM_H

#include "codec.h"
#include "ipc_protocol.h"
#include <cstdint>
#include <chrono>

// Forward declarations
class WebRTCServer;

// Stream statistics for monitoring
struct StreamStats {
    int frames_sent = 0;
    int64_t bytes_sent = 0;
    float avg_encode_ms = 0.0f;
    float avg_size_kb = 0.0f;
    int peers = 0;
};

// Dirty rectangle for partial updates
struct DirtyRect {
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t w = 0;
    uint32_t h = 0;

    bool is_empty() const { return w == 0 || h == 0; }
    bool is_full_frame(int width, int height) const {
        return x == 0 && y == 0 && w == (uint32_t)width && h == (uint32_t)height;
    }
};

// Ping echo data for latency measurement
struct PingEcho {
    uint32_t sequence = 0;
    uint64_t t1_browser_ms = 0;
    uint64_t t2_server_us = 0;
    uint64_t t3_emulator_us = 0;
    uint64_t t4_frame_us = 0;
    uint64_t t5_server_send_us = 0;

    bool has_ping() const { return sequence > 0; }
};

// Abstract base class for video streams
class VideoStream {
public:
    virtual ~VideoStream() = default;

    // Get stream codec type
    virtual CodecType codec() const = 0;

    // Get stream name for logging
    virtual const char* name() const = 0;

    // Initialize stream with resolution
    virtual bool init(int width, int height, int fps = 30) = 0;

    // Cleanup resources
    virtual void cleanup() = 0;

    // Process a frame from SHM and send to peers
    // Returns true if frame was encoded and sent
    virtual bool process_frame(
        const uint8_t* bgra_data,
        int width, int height, int stride,
        const MacEmuIPCBuffer* shm,
        uint64_t server_timestamp_us
    ) = 0;

    // Request keyframe on next encode (e.g., when new peer connects)
    virtual void request_keyframe() = 0;

    // Check if stream has active peers
    virtual bool has_peers() const = 0;

    // Get stream statistics
    virtual StreamStats get_stats() const = 0;

    // Reset statistics
    virtual void reset_stats() = 0;
};

#endif // VIDEO_STREAM_H
