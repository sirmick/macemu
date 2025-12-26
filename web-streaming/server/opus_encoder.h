/*
 * Opus Audio Encoder for macemu WebRTC Streaming
 *
 * Handles:
 * - Dynamic sample rate changes (11025, 22050, 44100, 48000 Hz)
 * - Dynamic channel changes (mono/stereo)
 * - Resampling to 48kHz for Opus (WebRTC standard)
 * - Low-latency encoding (20ms frames)
 */

#ifndef OPUS_ENCODER_H
#define OPUS_ENCODER_H

#include <opus/opus.h>
#include <vector>
#include <cstdint>

class OpusAudioEncoder {
public:
    OpusAudioEncoder();
    ~OpusAudioEncoder();

    // Initialize encoder
    // output_sample_rate: Always 48000 (WebRTC standard)
    // channels: 1 (mono) or 2 (stereo)
    // bitrate: 64000 for mono, 128000 for stereo
    bool init(int output_sample_rate = 48000, int channels = 2, int bitrate = 128000);

    // Cleanup
    void cleanup();

    // Encode PCM samples with dynamic format handling
    // Automatically resamples if input_sample_rate != 48000
    // Automatically reinitializes if channels change
    std::vector<uint8_t> encode_dynamic(const int16_t* pcm,
                                         int samples,
                                         int input_sample_rate,
                                         int input_channels);

    // Simple encode (assumes 48kHz input matching encoder config)
    std::vector<uint8_t> encode(const int16_t* pcm, int frame_size);

    // Get frame size in samples at 48kHz (typically 960 for 20ms)
    int get_frame_size() const { return frame_size_; }

    // Get encoder sample rate (always 48000)
    int get_sample_rate() const { return sample_rate_; }

    // Get encoder channels
    int get_channels() const { return channels_; }

    // Simple linear resampler for audio (good enough for speech/music)
    // More sophisticated would use libswresample, but adds dependency
    // Made public for use by server audio loop
    std::vector<int16_t> resample_linear(const int16_t* input,
                                          int input_samples,
                                          int input_rate,
                                          int output_rate,
                                          int channels);

private:

    OpusEncoder* encoder_ = nullptr;
    int sample_rate_ = 48000;  // Output rate (fixed for Opus)
    int channels_ = 2;
    int frame_size_ = 960;     // 20ms at 48kHz
    int bitrate_ = 128000;

    // Track last input format for change detection
    int last_input_rate_ = 0;
    int last_input_channels_ = 0;
};

#endif // OPUS_ENCODER_H
