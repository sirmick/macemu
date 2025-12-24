/*
 * AV1 Video Stream
 *
 * Streams AV1 encoded video via WebRTC RTP video track.
 * AV1 is similar to H.264 - no dirty rects, no heartbeats, just encode and send.
 */

#ifndef AV1_STREAM_H
#define AV1_STREAM_H

#include "video_stream.h"
#include "av1_encoder.h"
#include <memory>
#include <chrono>

// Forward declaration
class WebRTCServer;

class AV1Stream : public VideoStream {
public:
    explicit AV1Stream(WebRTCServer* webrtc);
    ~AV1Stream() override;

    CodecType codec() const override { return CodecType::AV1; }
    const char* name() const override { return "AV1"; }

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
    AV1Encoder encoder_;
    StreamStats stats_;

    // Timing for stats
    std::chrono::steady_clock::time_point last_encode_start_;
    std::chrono::steady_clock::time_point last_encode_end_;
};

#endif // AV1_STREAM_H
