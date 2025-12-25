/*
 *  audio_ipc.cpp - IPC-based audio driver for standalone WebRTC server
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
 *    Audio IPC uses same SHM as video (MacEmuIPCBuffer).
 *
 *    - Audio writes to audio_frames[] in existing video SHM
 *    - Signals via audio_ready_eventfd (separate from video)
 *    - Server processes audio independently from video
 *    - Supports dynamic format changes (sample rate, channels)
 *
 *    Double buffering - audio changes less frequently than video.
 */

#include "sysdeps.h"

#ifdef ENABLE_IPC_AUDIO

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "cpu_emulation.h"
#include "main.h"
#include "prefs.h"
#include "user_strings.h"
#include "audio.h"
#include "audio_defs.h"

// IPC protocol definitions
#include "ipc_protocol.h"

// Get video SHM pointer (managed by video_ipc.cpp)
extern MacEmuIPCBuffer* IPC_GetVideoSHM();

#define DEBUG 0
#include "debug.h"

// Audio buffer for mixing/conversion before writing to SHM
static uint8_t* audio_mix_buffer = nullptr;
static size_t audio_mix_buffer_size = 0;

// Streaming thread (C++11 style, consistent with video_ipc.cpp)
static std::thread audio_thread;
static std::atomic<bool> audio_thread_running(false);
static std::atomic<bool> audio_thread_cancel(false);

// Synchronization for AudioInterrupt
static std::mutex audio_irq_mutex;
static std::condition_variable audio_irq_done_cv;
static bool audio_irq_done = false;

// Wake-up mechanism for audio thread
static std::mutex audio_wakeup_mutex;
static std::condition_variable audio_wakeup_cv;

// Timing for 20ms audio frames
static auto last_audio_frame_time = std::chrono::steady_clock::now();

// Counters for debug
static uint64_t audio_frames_sent = 0;
static uint64_t last_log_frame = 0;

// Debug flag (read once at initialization)
static bool g_debug_audio = false;

// Forward declarations
static void write_audio_to_shm(const uint8_t* data, size_t len);
static void audio_thread_func();


/*
 *  Initialization
 */

void AudioInit(void)
{
	// Read debug flag once at startup
	g_debug_audio = (getenv("MACEMU_DEBUG_AUDIO") != nullptr);

	// Init audio status and feature flags
	AudioStatus.sample_rate = 44100 << 16;  // Default 44.1kHz (Mac format: upper 16 bits = integer part)
	AudioStatus.sample_size = 16;            // 16-bit samples
	AudioStatus.channels = 2;                // Stereo
	AudioStatus.mixer = 0;
	AudioStatus.num_sources = 0;
	audio_component_flags = cmpWantsRegisterMessage | kStereoOut | k16BitOut;

	// Supported audio formats - IPC audio supports multiple sample rates
	// Mac OS will choose from these based on what the application requests
	audio_sample_rates.push_back(11025 << 16);  // 11.025 kHz
	audio_sample_rates.push_back(22050 << 16);  // 22.05 kHz
	audio_sample_rates.push_back(44100 << 16);  // 44.1 kHz
	audio_sample_rates.push_back(48000 << 16);  // 48 kHz

	// Supported sample sizes
	audio_sample_sizes.push_back(8);   // 8-bit (U8)
	audio_sample_sizes.push_back(16);  // 16-bit (S16)

	// Supported channel counts
	audio_channel_counts.push_back(1);  // Mono
	audio_channel_counts.push_back(2);  // Stereo

	// Sound disabled in prefs? Then do nothing
	if (PrefsFindBool("nosound")) {
		fprintf(stderr, "Audio IPC: Disabled by 'nosound' pref\n");
		audio_open = false;
		return;
	}

	// Allocate mixing buffer (max 48kHz stereo 20ms = 3840 bytes)
	audio_mix_buffer_size = MACEMU_AUDIO_MAX_FRAME_SIZE;
	audio_mix_buffer = (uint8_t*)malloc(audio_mix_buffer_size);

	if (!audio_mix_buffer) {
		fprintf(stderr, "Audio IPC: Failed to allocate mix buffer\n");
		audio_open = false;
		return;
	}

	memset(audio_mix_buffer, 0, audio_mix_buffer_size);

	// Set audio frames per block
	// For 44.1kHz @ 20ms: 882 samples
	// For 48kHz @ 20ms: 960 samples
	// Use 4096 like OSS/SDL to match their behavior
	audio_frames_per_block = 4096;

	// Mark audio as available
	audio_open = true;

	// Start streaming thread immediately (runs continuously, checks num_sources each loop)
	// This avoids thread start/stop overhead for brief sounds
	// Using std::thread for consistency with video_ipc.cpp
	audio_thread_cancel = false;
	audio_thread = std::thread(audio_thread_func);
	audio_thread_running = true;

	if (g_debug_audio) {
		fprintf(stderr, "Audio IPC: Streaming thread started\n");
	}

	fprintf(stderr, "Audio IPC: Initialized and READY (buffer size: %zu bytes, frames per block: %d, sample rates: 11025-48000 Hz)\n",
	        audio_mix_buffer_size, audio_frames_per_block);
	D(bug("Audio IPC: Initialized (buffer size: %zu bytes, frames: %d)\n", audio_mix_buffer_size, audio_frames_per_block));
}


/*
 *  Deinitialization
 */

void AudioExit(void)
{
	// Stop streaming thread if active
	if (audio_thread_running) {
		audio_thread_cancel = true;

		// Wake up thread if it's sleeping
		audio_wakeup_cv.notify_one();

		// Wait for thread to finish
		if (audio_thread.joinable()) {
			audio_thread.join();
		}

		audio_thread_running = false;
		if (g_debug_audio) {
			fprintf(stderr, "Audio IPC: Streaming thread stopped\n");
		}
	}

	if (audio_mix_buffer) {
		free(audio_mix_buffer);
		audio_mix_buffer = nullptr;
	}

	D(bug("Audio IPC: Shutdown complete\n"));
}


/*
 *  First source added (num_sources 0→1)
 *  Wake up the audio thread immediately
 */

void audio_enter_stream()
{
	// ALWAYS log this - it's critical for debugging
	fprintf(stderr, "Audio IPC: *** STREAM STARTED *** (num_sources 0→1)\n");
	D(bug("Audio IPC: Stream started\n"));
	last_audio_frame_time = std::chrono::steady_clock::now();

	// Wake up audio thread immediately (instead of waiting for next 20ms timeout)
	audio_wakeup_cv.notify_one();
	fprintf(stderr, "Audio IPC: Woke up audio thread\n");
}


/*
 *  Last source removed (num_sources 1→0)
 *  Thread continues running, just stops processing
 */

void audio_exit_stream()
{
	// ALWAYS log this - it's critical for debugging
	fprintf(stderr, "Audio IPC: *** STREAM STOPPED *** (num_sources 1→0)\n");
	D(bug("Audio IPC: Stream stopped\n"));

	// Thread continues running, will automatically stop processing
	// when it sees num_sources == 0 on next loop iteration

	// Signal audio paused (not disabled)
	MacEmuIPCBuffer* video_shm = IPC_GetVideoSHM();
	if (video_shm) {
		video_shm->audio_format = MACEMU_AUDIO_FORMAT_NONE;
	}
}


/*
 *  MacOS audio interrupt - new buffer is available
 *  This is called from the Mac sound manager interrupt
 */

void AudioInterrupt(void)
{
	D(bug("Audio IPC: Interrupt\n"));

	if (g_debug_audio) {
		static int irq_count = 0;
		irq_count++;
		if (irq_count <= 10 || irq_count % 100 == 0) {
			fprintf(stderr, "Audio IPC: AudioInterrupt called (count=%d, num_sources=%d)\n",
			        irq_count, AudioStatus.num_sources);
		}
	}

	// Call GetSourceData to fill apple_stream_info (like SDL does)
	// This tells the Apple Mixer to prepare audio data for us to read
	if (AudioStatus.mixer) {
		M68kRegisters r;
		r.a[0] = audio_data + adatStreamInfo;
		r.a[1] = AudioStatus.mixer;
		Execute68k(audio_data + adatGetSourceData, &r);
		D(bug(" GetSourceData() returns %08lx\n", r.d[0]));
	} else {
		WriteMacInt32(audio_data + adatStreamInfo, 0);
	}

	// Signal streaming thread that interrupt is complete
	{
		std::lock_guard<std::mutex> lock(audio_irq_mutex);
		audio_irq_done = true;
	}
	audio_irq_done_cv.notify_one();
}


/*
 *  Write audio frame to shared memory
 */

static void write_audio_to_shm(const uint8_t* data, size_t len)
{
	MacEmuIPCBuffer* video_shm = IPC_GetVideoSHM();
	if (!video_shm) {
		return;
	}

	// Check if audio eventfd is available
	if (video_shm->audio_ready_eventfd < 0) {
		return;  // Audio not enabled in server
	}

	// Get current audio format
	uint32_t sample_rate = AudioStatus.sample_rate >> 16;  // Convert from Mac format
	uint32_t channels = AudioStatus.channels;
	uint32_t samples = len / (2 * channels);  // Assuming 16-bit (2 bytes per sample)

	if (samples == 0 || len > MACEMU_AUDIO_MAX_FRAME_SIZE) {
		return;  // Invalid
	}

	// Get write buffer
	uint8_t* audio_frame = macemu_get_write_audio(video_shm);

	// Copy audio data
	memcpy(audio_frame, data, len);

	// Get timestamp
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	uint64_t timestamp_us = (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;

	// Publish frame (atomically updates metadata and signals server)
	macemu_audio_frame_complete(video_shm, sample_rate, channels, samples, timestamp_us);

	audio_frames_sent++;

	// Log every 100 frames (~2 seconds at 50fps) if debug enabled
	if (g_debug_audio && (audio_frames_sent - last_log_frame >= 100)) {
		fprintf(stderr, "Audio IPC: Sent %lu frames (%u samples/frame, %uHz, %uch)\n",
		        audio_frames_sent, samples, sample_rate, channels);
		last_log_frame = audio_frames_sent;
	}

	D(bug("Audio IPC: Sent %u samples (%uHz, %uch)\n", samples, sample_rate, channels));
}


/*
 *  Get/set audio info
 */

bool audio_get_main_mute(void)
{
	return false;  // Not muted
}

uint32 audio_get_main_volume(void)
{
	return 0x0100;  // Max volume
}

bool audio_get_speaker_mute(void)
{
	return false;
}

uint32 audio_get_speaker_volume(void)
{
	return 0x0100;  // Max volume
}

void audio_set_main_mute(bool mute)
{
	// Not implemented for IPC audio
	(void)mute;
}

void audio_set_main_volume(uint32 vol)
{
	// Not implemented for IPC audio
	(void)vol;
}

void audio_set_speaker_mute(bool mute)
{
	// Not implemented for IPC audio
	(void)mute;
}

void audio_set_speaker_volume(uint32 vol)
{
	// Not implemented for IPC audio
	(void)vol;
}

bool audio_set_sample_rate(int index)
{
	// Sample rate changes are handled automatically
	// AudioStatus.sample_rate is updated by audio.cpp
	D(bug("Audio IPC: Sample rate changed to index %d\n", index));
	return true;
}

bool audio_set_sample_size(int index)
{
	// Sample size changes are handled automatically
	D(bug("Audio IPC: Sample size changed to index %d\n", index));
	return true;
}

bool audio_set_channels(int index)
{
	// Channel changes are handled automatically
	D(bug("Audio IPC: Channels changed to index %d\n", index));
	return true;
}


/*
 *  Audio streaming thread
 *  Periodically triggers audio interrupt to get new data from Mac
 *  Uses condition_variable for efficient wake-up (no polling overhead)
 */

static void audio_thread_func()
{
	if (g_debug_audio) {
		fprintf(stderr, "Audio IPC: Streaming thread running\n");
	}

	// Frame timing: 20ms for audio processing
	const auto frame_interval = std::chrono::milliseconds(20);

	int loop_count = 0;
	int zero_sources_count = 0;
	int no_data_count = 0;

	while (!audio_thread_cancel) {
		if (AudioStatus.num_sources) {
			// Trigger audio interrupt to signal Mac we're ready for data
			loop_count++;
			if (g_debug_audio && loop_count == 1) {
				fprintf(stderr, "Audio IPC: Thread FIRST LOOP with num_sources=%d\n", AudioStatus.num_sources);
			}
			if (g_debug_audio && loop_count % 50 == 0) {  // Log every ~1 second
				fprintf(stderr, "Audio IPC: Thread active (num_sources=%d, loop=%d)\n",
				        AudioStatus.num_sources, loop_count);
			}
			D(bug("Audio IPC: Triggering audio interrupt\n"));
			if (g_debug_audio && loop_count <= 10) {
				fprintf(stderr, "Audio IPC: About to trigger interrupt (loop=%d)\n", loop_count);
			}
			SetInterruptFlag(INTFLAG_AUDIO);
			TriggerInterrupt();

			// Wait for AudioInterrupt() to complete
			D(bug("Audio IPC: Waiting for interrupt completion\n"));
			if (g_debug_audio && loop_count <= 10) {
				fprintf(stderr, "Audio IPC: Waiting for AudioInterrupt() to complete...\n");
			}
			{
				std::unique_lock<std::mutex> lock(audio_irq_mutex);
				audio_irq_done_cv.wait(lock, []{ return audio_irq_done; });
				audio_irq_done = false;  // Reset for next iteration
			}
			D(bug("Audio IPC: Interrupt complete\n"));
			if (g_debug_audio && loop_count <= 10) {
				fprintf(stderr, "Audio IPC: AudioInterrupt() completed, now reading data\n");
			}

			// Now read the audio data (like OSS/SDL do)
			MacEmuIPCBuffer* video_shm = IPC_GetVideoSHM();
			if (g_debug_audio && loop_count <= 10) {
				fprintf(stderr, "Audio IPC: video_shm=%p\n", (void*)video_shm);
			}
			if (video_shm) {
				uint32 apple_stream_info = ReadMacInt32(audio_data + adatStreamInfo);

				// Debug: log first time and periodically if debug enabled
				static int read_count = 0;
				read_count++;
				if (g_debug_audio && (read_count <= 20 || read_count % 100 == 0)) {
					fprintf(stderr, "Audio IPC: Reading stream (count=%d, stream_info=0x%x, audio_data=0x%x)\n",
					        read_count, apple_stream_info, audio_data);
				}

				if (apple_stream_info) {
					uint32 sample_count = ReadMacInt32(apple_stream_info + scd_sampleCount);
					uint32 buffer_ptr = ReadMacInt32(apple_stream_info + scd_buffer);
					uint32 num_channels = ReadMacInt16(apple_stream_info + scd_numChannels);
					uint32 sample_size = ReadMacInt16(apple_stream_info + scd_sampleSize);
					uint32 sample_rate = ReadMacInt32(apple_stream_info + scd_sampleRate);

					// Debug: log what we got
					if (g_debug_audio && (read_count <= 20 || read_count % 100 == 0)) {
						fprintf(stderr, "Audio IPC: Got sample_count=%u, buffer_ptr=0x%x, channels=%u, size=%u, rate=%u\n",
						        sample_count, buffer_ptr, num_channels, sample_size, sample_rate >> 16);
					}

					if (sample_count > 0 && buffer_ptr != 0) {
						// We have data! Process it
						uint32 sample_size = AudioStatus.sample_size;
						uint32 channels = AudioStatus.channels;
						uint32 bytes_per_sample = (sample_size >> 3);
						size_t data_len = sample_count * bytes_per_sample * channels;

						if (data_len > audio_mix_buffer_size) {
							data_len = audio_mix_buffer_size;
							sample_count = data_len / (bytes_per_sample * channels);
						}

						// Copy and convert audio data
						uint8_t* src = Mac2HostAddr(buffer_ptr);

						if (sample_size == 8) {
							// Convert U8 to S16
							uint8_t* src_u8 = src;
							int16_t* dst_s16 = (int16_t*)audio_mix_buffer;
							for (uint32 i = 0; i < sample_count * channels; i++) {
								dst_s16[i] = ((int16_t)src_u8[i] - 128) << 8;
							}
							data_len = sample_count * channels * 2;
						} else {
							// S16 data - direct copy like SDL does (Mac provides S16MSB format)
							// SDL uses AUDIO_S16MSB and does direct memcpy - we do the same
							// The server/Opus encoder will handle any needed byte swapping
							memcpy(audio_mix_buffer, src, data_len);
						}

						// Write to SHM
						if (g_debug_audio && read_count <= 20) {
							fprintf(stderr, "Audio IPC: Writing %zu bytes to SHM (%u samples, %u channels)\n",
							        data_len, sample_count, channels);
						}
						write_audio_to_shm(audio_mix_buffer, data_len);
						no_data_count = 0;  // Reset
					} else {
						// No data yet
						no_data_count++;
						if (g_debug_audio && no_data_count % 100 == 0) {
							fprintf(stderr, "Audio IPC: No data available yet (%d checks, sample_count=%u, buffer_ptr=0x%x)\n",
							        no_data_count, sample_count, buffer_ptr);
						}
					}
				} else {
					// No stream info yet
					no_data_count++;
					if (g_debug_audio && no_data_count % 100 == 0) {
						fprintf(stderr, "Audio IPC: No stream info yet (%d checks)\n", no_data_count);
					}
				}
			}
		} else {
			// No sources, reset counters
			zero_sources_count++;
			if (g_debug_audio && zero_sources_count == 1) {
				fprintf(stderr, "Audio IPC: Thread loop with num_sources=0 (audio not active yet)\n");
			}
			loop_count = 0;
			no_data_count = 0;
		}

		// Sleep with timeout - wakes immediately on notify OR after 20ms
		// When audio active: maintains 20ms frame timing
		// When idle: waits for audio_enter_stream() to wake us
		std::unique_lock<std::mutex> lock(audio_wakeup_mutex);
		audio_wakeup_cv.wait_for(lock, frame_interval);
	}

	if (g_debug_audio) {
		fprintf(stderr, "Audio IPC: Streaming thread exiting\n");
	}
}

#endif // ENABLE_IPC_AUDIO
