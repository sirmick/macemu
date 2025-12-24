/*
 * AV1 Encoder using SVT-AV1
 * Note: SVT-AV1 is only available on Linux. On macOS, this provides a stub.
 */

#ifndef AV1_ENCODER_H
#define AV1_ENCODER_H

#include "codec.h"
#include <vector>

#ifdef HAVE_AV1
#include <EbSvtAv1Enc.h>

class AV1Encoder : public VideoCodec {
public:
    AV1Encoder() = default;
    ~AV1Encoder() override { cleanup(); }

    // VideoCodec interface
    CodecType type() const override { return CodecType::AV1; }
    const char* name() const override { return "AV1"; }
    bool init(int width, int height, int fps = 30) override;
    void cleanup() override;
    EncodedFrame encode_i420(const uint8_t* y, const uint8_t* u, const uint8_t* v,
                             int width, int height, int y_stride, int uv_stride) override;
    EncodedFrame encode_bgra(const uint8_t* bgra, int width, int height, int stride) override;
    void request_keyframe() override { force_keyframe_ = true; }

private:
    EbComponentType* encoder_ = nullptr;
    EbSvtAv1EncConfiguration config_ = {};

    int width_ = 0;
    int height_ = 0;
    int fps_ = 30;
    bool force_keyframe_ = false;
    uint64_t frame_count_ = 0;

    // I420 conversion buffer
    std::vector<uint8_t> i420_buffer_;

    // Input buffer (allocated once, reused for all frames)
    EbBufferHeaderType* input_buffer_ = nullptr;
    EbSvtIOFormat* input_picture_ = nullptr;
};

#else
// Stub implementation for platforms without SVT-AV1

class AV1Encoder : public VideoCodec {
public:
    AV1Encoder() = default;
    ~AV1Encoder() override { cleanup(); }

    CodecType type() const override { return CodecType::AV1; }
    const char* name() const override { return "AV1 (unavailable)"; }

    bool init(int, int, int = 30) override {
        fprintf(stderr, "AV1: SVT-AV1 not available on this platform\n");
        return false;
    }

    void cleanup() override {}

    EncodedFrame encode_i420(const uint8_t*, const uint8_t*, const uint8_t*,
                             int, int, int, int) override {
        return EncodedFrame();
    }

    EncodedFrame encode_bgra(const uint8_t*, int, int, int) override {
        return EncodedFrame();
    }

    void request_keyframe() override {}
};

#endif // HAVE_AV1

#endif // AV1_ENCODER_H
