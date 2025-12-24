/*
 * PNG Video Stream
 *
 * Streams PNG encoded video via WebRTC DataChannel.
 * PNG is complex - handles dirty rects, heartbeats, first frame, ping echoes.
 * All logic that was scattered in video_loop now lives here.
 */

#ifndef PNG_STREAM_H
#define PNG_STREAM_H

#include "video_stream.h"
#include "png_encoder.h"
#include <memory>
#include <chrono>

// Forward declaration
class WebRTCServer;

class PNGStream : public VideoStream {
public:
    explicit PNGStream(WebRTCServer* webrtc);
    ~PNGStream() override;

    CodecType codec() const override { return CodecType::PNG; }
    const char* name() const override { return "PNG"; }

    bool init(int width, int height, int fps = 30) override;
    void cleanup() override;

    bool process_frame(
        const uint8_t* bgra_data,
        int width, int height, int stride,
        const MacEmuIPCBuffer* shm,
        uint64_t server_timestamp_us
    ) override;

    void request_keyframe() override;
    bool has_peers() const override;
    StreamStats get_stats() const override;
    void reset_stats() override;

private:
    WebRTCServer* webrtc_;
    PNGEncoder encoder_;
    StreamStats stats_;

    // Timing for stats
    std::chrono::steady_clock::time_point last_encode_start_;
    std::chrono::steady_clock::time_point last_encode_end_;
    std::chrono::steady_clock::time_point last_heartbeat_;

    // Debug logging throttle
    int dirty_log_counter_ = 0;
    int encode_log_counter_ = 0;

    // Helper methods - all the logic that was in video_loop
    DirtyRect extract_dirty_rect(const MacEmuIPCBuffer* shm, int width, int height);
    PingEcho extract_ping_echo(const MacEmuIPCBuffer* shm);
    bool has_pending_ping(const MacEmuIPCBuffer* shm);
    bool should_send_heartbeat();
};

#endif // PNG_STREAM_H
