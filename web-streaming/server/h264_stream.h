/*
 * H.264 Video Stream
 *
 * Streams H.264 encoded video via WebRTC RTP video track.
 * H.264 is simple - no dirty rects, no heartbeats, just encode and send.
 */

#ifndef H264_STREAM_H
#define H264_STREAM_H

#include "video_stream.h"
#include "h264_encoder.h"
#include <memory>
#include <chrono>

// Forward declaration
class WebRTCServer;

class H264Stream : public VideoStream {
public:
    explicit H264Stream(WebRTCServer* webrtc);
    ~H264Stream() override;

    CodecType codec() const override { return CodecType::H264; }
    const char* name() const override { return "H264"; }

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
    H264Encoder encoder_;
    StreamStats stats_;

    // Timing for stats
    std::chrono::steady_clock::time_point last_encode_start_;
    std::chrono::steady_clock::time_point last_encode_end_;
};

#endif // H264_STREAM_H
