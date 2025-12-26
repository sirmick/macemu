/*
 * Opus Audio Encoder Implementation
 */

#include "opus_encoder.h"
#include <cstdio>
#include <cstring>
#include <cmath>

// External debug flag from server.cpp
extern bool g_debug_mode_switch;

OpusAudioEncoder::OpusAudioEncoder() {}

OpusAudioEncoder::~OpusAudioEncoder() {
    cleanup();
}

bool OpusAudioEncoder::init(int output_sample_rate, int channels, int bitrate) {
    sample_rate_ = output_sample_rate;
    channels_ = channels;
    bitrate_ = bitrate;
    frame_size_ = (sample_rate_ * 20) / 1000;  // 20ms frames

    int error;
    encoder_ = opus_encoder_create(sample_rate_, channels, OPUS_APPLICATION_AUDIO, &error);

    if (error != OPUS_OK) {
        fprintf(stderr, "[Opus] Failed to create encoder: %s\n", opus_strerror(error));
        return false;
    }

    // Configure for low latency and good quality
    opus_encoder_ctl(encoder_, OPUS_SET_BITRATE(bitrate));
    opus_encoder_ctl(encoder_, OPUS_SET_COMPLEXITY(5));  // Medium complexity (0-10)
    opus_encoder_ctl(encoder_, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));  // Optimize for music
    opus_encoder_ctl(encoder_, OPUS_SET_VBR(1));  // Variable bitrate
    opus_encoder_ctl(encoder_, OPUS_SET_VBR_CONSTRAINT(0));  // Unconstrained VBR
    opus_encoder_ctl(encoder_, OPUS_SET_DTX(1));  // Enable DTX (discontinuous transmission) for silence

    fprintf(stderr, "[Opus] Encoder initialized: %dHz, %d ch, %d bps, frame=%d samples\n",
            sample_rate_, channels_, bitrate, frame_size_);

    return true;
}

void OpusAudioEncoder::cleanup() {
    if (encoder_) {
        opus_encoder_destroy(encoder_);
        encoder_ = nullptr;
    }
}

std::vector<uint8_t> OpusAudioEncoder::encode(const int16_t* pcm, int frame_size) {
    if (!encoder_) {
        fprintf(stderr, "[Opus] Encoder not initialized\n");
        return {};
    }

    std::vector<uint8_t> output(4000);  // Max Opus packet size

    int encoded_bytes = opus_encode(encoder_, pcm, frame_size,
                                    output.data(), output.size());

    if (encoded_bytes < 0) {
        fprintf(stderr, "[Opus] Encode error: %s\n", opus_strerror(encoded_bytes));
        return {};
    }

    output.resize(encoded_bytes);
    return output;
}

std::vector<int16_t> OpusAudioEncoder::resample_linear(const int16_t* input,
                                                         int input_samples,
                                                         int input_rate,
                                                         int output_rate,
                                                         int channels) {
    // Calculate output sample count
    int output_samples = (int)((int64_t)input_samples * output_rate / input_rate);
    std::vector<int16_t> output(output_samples * channels);

    double ratio = (double)input_rate / output_rate;

    for (int i = 0; i < output_samples; i++) {
        double src_pos = i * ratio;
        int src_index = (int)src_pos;
        double frac = src_pos - src_index;

        for (int ch = 0; ch < channels; ch++) {
            if (src_index + 1 < input_samples) {
                // Linear interpolation
                int16_t s0 = input[(src_index * channels) + ch];
                int16_t s1 = input[((src_index + 1) * channels) + ch];
                output[(i * channels) + ch] = (int16_t)(s0 + frac * (s1 - s0));
            } else {
                // Last sample, no interpolation
                output[(i * channels) + ch] = input[(src_index * channels) + ch];
            }
        }
    }

    return output;
}

std::vector<uint8_t> OpusAudioEncoder::encode_dynamic(const int16_t* pcm,
                                                        int samples,
                                                        int input_sample_rate,
                                                        int input_channels) {
    // Check for format changes (like video encoders do!)
    bool format_changed = false;

    if (input_sample_rate != last_input_rate_ || input_channels != last_input_channels_) {
        if (last_input_rate_ != 0) {  // Not first call
            if (g_debug_mode_switch) {
                fprintf(stderr, "[Opus] Audio format changed: %dHz %dch -> %dHz %dch\n",
                        last_input_rate_, last_input_channels_,
                        input_sample_rate, input_channels);
            }
        }
        format_changed = true;
        last_input_rate_ = input_sample_rate;
        last_input_channels_ = input_channels;
    }

    // Reinitialize encoder if channels changed
    if (format_changed && input_channels != channels_) {
        fprintf(stderr, "[Opus] Reinitializing encoder for %d channels\n", input_channels);
        cleanup();
        int new_bitrate = (input_channels == 2) ? 128000 : 64000;
        if (!init(48000, input_channels, new_bitrate)) {
            fprintf(stderr, "[Opus] Failed to reinitialize encoder\n");
            return {};
        }
    }

    // Resample if needed
    const int16_t* pcm_to_encode = pcm;
    int samples_to_encode = samples;
    std::vector<int16_t> resampled;

    if (input_sample_rate != sample_rate_) {
        resampled = resample_linear(pcm, samples, input_sample_rate, sample_rate_, input_channels);
        pcm_to_encode = resampled.data();
        samples_to_encode = resampled.size() / input_channels;
    }

    // Encode (may need to handle partial frames if samples don't match frame_size_)
    // For simplicity, we'll encode what we have and pad if needed
    if (samples_to_encode < frame_size_) {
        // Pad with silence
        std::vector<int16_t> padded(frame_size_ * input_channels, 0);
        memcpy(padded.data(), pcm_to_encode, samples_to_encode * input_channels * sizeof(int16_t));
        return encode(padded.data(), frame_size_);
    } else if (samples_to_encode > frame_size_) {
        // Truncate to frame size (shouldn't happen with 20ms frames)
        return encode(pcm_to_encode, frame_size_);
    } else {
        // Perfect match
        return encode(pcm_to_encode, frame_size_);
    }
}

