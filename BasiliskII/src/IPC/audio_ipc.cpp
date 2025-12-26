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
#include <cerrno>
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

// Audio buffer for mixing/conversion before writing to SHM ring buffer
static uint8_t* audio_mix_buffer = nullptr;
static size_t audio_mix_buffer_size = 0;

// Ring buffer is now in SHM (MacEmuIPCBuffer::audio_ring_buffer)
// Indices are atomic fields in SHM (audio_ring_write_pos, audio_ring_read_pos)
// No local copy needed - zero-copy architecture!

// No dedicated audio thread - audio processing happens inline when server requests data
// This matches the autonomous ring buffer model:
// - Mac side: Fills ring buffer with 4096 samples per interrupt (~85 Hz)
// - Server side: Pulls 960 samples when needed (50 Hz)
// - Ring buffer decouples the timing

// Synchronization for AudioInterrupt (Mac emulation thread → control socket thread)
static std::mutex audio_irq_mutex;
static std::condition_variable audio_irq_done_cv;
static bool audio_irq_done = false;

// Timing for 20ms audio frames
static auto last_audio_frame_time = std::chrono::steady_clock::now();

// Counters for debug
static uint64_t audio_frames_sent = 0;
static uint64_t last_log_frame = 0;

// Debug flag (read once at initialization)
static bool g_debug_audio = false;

// Forward declarations
static void ring_buffer_write(const uint8_t* data, size_t len);


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

	fprintf(stderr, "Audio IPC: Initialized and READY (buffer size: %zu bytes, frames per block: %d, sample rates: 11025-48000 Hz)\n",
	        audio_mix_buffer_size, audio_frames_per_block);
	D(bug("Audio IPC: Initialized (buffer size: %zu bytes, frames: %d)\n", audio_mix_buffer_size, audio_frames_per_block));
}


/*
 *  Deinitialization
 */

void AudioExit(void)
{
	// No thread to stop - audio processing is inline now

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
	if (g_debug_audio) {
		fprintf(stderr, "Audio IPC: Stream started (num_sources 0→1)\n");
	}
	D(bug("Audio IPC: Stream started\n"));
	last_audio_frame_time = std::chrono::steady_clock::now();
}

/*
 *  Server requested audio data (pull model)
 *  Called from control socket thread when AUDIO_REQUEST message arrives
 *
 *  This function runs inline in the control socket thread - no dedicated audio thread needed.
 *  The autonomous ring buffer model:
 *  - This function triggers Mac interrupt and gets 4096 samples
 *  - Writes to ring buffer
 *  - Signals server via eventfd
 *  - Returns to epoll_wait
 *  - Server pulls 960 samples as needed from ring buffer
 */

void audio_request_data()
{
	static int request_count = 0;
	request_count++;

	// If no audio sources active, signal server immediately (will send silence via DTX)
	if (!AudioStatus.num_sources) {
		MacEmuIPCBuffer* shm = IPC_GetVideoSHM();
		if (shm && shm->audio_ready_eventfd >= 0) {
			uint64_t val = 1;
			write(shm->audio_ready_eventfd, &val, sizeof(val));
		}
		return;
	}

	// Trigger Mac audio interrupt to get fresh data
	SetInterruptFlag(INTFLAG_AUDIO);
	TriggerInterrupt();

	// Wait for Mac to fill audio data (blocks until AudioInterrupt() completes)
	{
		std::unique_lock<std::mutex> lock(audio_irq_mutex);
		audio_irq_done_cv.wait(lock, []{ return audio_irq_done; });
		audio_irq_done = false;
	}

	// Read Mac's audio data and write to ring buffer
	MacEmuIPCBuffer* shm = IPC_GetVideoSHM();
	if (!shm || !audio_data) {
		// SHM or audio_data invalid - signal anyway so server doesn't timeout
		if (shm && shm->audio_ready_eventfd >= 0) {
			uint64_t val = 1;
			write(shm->audio_ready_eventfd, &val, sizeof(val));
		}
		return;
	}

	uint32 apple_stream_info = ReadMacInt32(audio_data + adatStreamInfo);
	if (!apple_stream_info) {
		// No stream info - signal server anyway
		if (shm->audio_ready_eventfd >= 0) {
			uint64_t val = 1;
			write(shm->audio_ready_eventfd, &val, sizeof(val));
		}
		return;
	}

	uint32 sample_count = ReadMacInt32(apple_stream_info + scd_sampleCount);
	uint32 buffer_ptr = ReadMacInt32(apple_stream_info + scd_buffer);
	uint32 num_channels = ReadMacInt16(apple_stream_info + scd_numChannels);
	uint32 sample_size = ReadMacInt16(apple_stream_info + scd_sampleSize);

	if (g_debug_audio && request_count <= 10) {
		fprintf(stderr, "Audio IPC: Request #%d: Got %u samples from Mac\n",
			request_count, sample_count);
	}

	if (sample_count > 0 && buffer_ptr != 0) {
		// Process audio data
		uint32 bytes_per_sample = (sample_size >> 3);
		size_t data_len = sample_count * bytes_per_sample * num_channels;

		if (data_len > audio_mix_buffer_size) {
			data_len = audio_mix_buffer_size;
			sample_count = data_len / (bytes_per_sample * num_channels);
		}

		uint8_t* src = Mac2HostAddr(buffer_ptr);

		if (sample_size == 8) {
			// Convert U8 to S16
			uint8_t* src_u8 = src;
			int16_t* dst_s16 = (int16_t*)audio_mix_buffer;
			for (uint32 i = 0; i < sample_count * num_channels; i++) {
				dst_s16[i] = ((int16_t)src_u8[i] - 128) << 8;
			}
			data_len = sample_count * num_channels * 2;
		} else {
			// S16 data - direct copy (Mac provides S16MSB format)
			memcpy(audio_mix_buffer, src, data_len);
		}

		// Write to ring buffer
		if (g_debug_audio && request_count <= 10) {
			fprintf(stderr, "Audio IPC: Writing %zu bytes to ring buffer (%u samples)\n",
				data_len, sample_count);
		}
		ring_buffer_write(audio_mix_buffer, data_len);
	}

	// Signal server that data is ready (or that we responded to the request)
	if (shm->audio_ready_eventfd >= 0) {
		uint64_t val = 1;
		ssize_t written = write(shm->audio_ready_eventfd, &val, sizeof(val));
		if (written != sizeof(val) && g_debug_audio) {
			fprintf(stderr, "Audio IPC: Warning - eventfd write failed: %s\n", strerror(errno));
		}
	}
}


/*
 *  Last source removed (num_sources 1→0)
 *  Thread continues running, just stops processing
 */

void audio_exit_stream()
{
	if (g_debug_audio) {
		fprintf(stderr, "Audio IPC: Stream stopped (num_sources 1→0)\n");
	}
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
	if (!audio_data) {
		// Audio component has been closed, audio_data freed
		if (g_debug_audio) {
			fprintf(stderr, "Audio IPC: AudioInterrupt - audio_data is NULL, component closed\n");
		}
	} else if (AudioStatus.mixer) {
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
 *  Ring buffer functions for audio buffering
 */

// Write data to ring buffer in SHM (called by AudioInterrupt with Mac's audio data)
// Zero-copy: writes directly to SHM ring buffer, advances write index
static void ring_buffer_write(const uint8_t* data, size_t len)
{
	MacEmuIPCBuffer* shm = IPC_GetVideoSHM();
	if (!shm) return;

	// Read current positions atomically
	uint32_t write_pos = ATOMIC_LOAD(shm->audio_ring_write_pos);
	uint32_t read_pos = ATOMIC_LOAD(shm->audio_ring_read_pos);
	uint32_t ring_size = shm->audio_ring_size;

	// Calculate available space
	uint32_t available = (read_pos > write_pos) ?
		(read_pos - write_pos - 1) :
		(ring_size - write_pos + read_pos - 1);

	if (len > available) {
		if (g_debug_audio) {
			fprintf(stderr, "Audio IPC: Ring buffer full! Dropping %zu bytes (available %u)\n",
				len - available, available);
		}
		len = available;  // Drop excess data
	}

	// Write data directly to SHM ring buffer (handle wrap-around)
	size_t first_chunk = std::min(len, (size_t)(ring_size - write_pos));
	memcpy(&shm->audio_ring_buffer[write_pos], data, first_chunk);

	if (first_chunk < len) {
		// Wrap around to beginning
		memcpy(&shm->audio_ring_buffer[0], data + first_chunk, len - first_chunk);
	}

	// Advance write position atomically (release semantics - publishes data writes)
	write_pos = (write_pos + len) % ring_size;
	ATOMIC_STORE(shm->audio_ring_write_pos, write_pos);
}

// Get pointer and size for reading from ring buffer (zero-copy)
// Server calls this to get direct pointer into SHM ring buffer
// Returns bytes available (may be less than requested if underrun)
// NOTE: This is for emulator use only - server has its own implementation
static size_t ring_buffer_get_read_info(uint8_t** out_ptr1, size_t* out_size1,
                                         uint8_t** out_ptr2, size_t* out_size2,
                                         size_t requested_len)
{
	MacEmuIPCBuffer* shm = IPC_GetVideoSHM();
	if (!shm) return 0;

	uint32_t write_pos = ATOMIC_LOAD(shm->audio_ring_write_pos);
	uint32_t read_pos = ATOMIC_LOAD(shm->audio_ring_read_pos);
	uint32_t ring_size = shm->audio_ring_size;

	// Calculate available data
	uint32_t available = (write_pos >= read_pos) ?
		(write_pos - read_pos) :
		(ring_size - read_pos + write_pos);

	if (requested_len > available) {
		if (g_debug_audio) {
			static int underrun_count = 0;
			if (++underrun_count <= 10 || underrun_count % 100 == 0) {
				fprintf(stderr, "Audio IPC: Ring buffer underrun! Requested %zu, available %u (count=%d)\n",
					requested_len, available, underrun_count);
			}
		}
		requested_len = available;
	}

	// Return pointers (may need two chunks if wrapping)
	size_t first_chunk = std::min(requested_len, (size_t)(ring_size - read_pos));
	*out_ptr1 = &shm->audio_ring_buffer[read_pos];
	*out_size1 = first_chunk;

	if (first_chunk < requested_len) {
		*out_ptr2 = &shm->audio_ring_buffer[0];
		*out_size2 = requested_len - first_chunk;
	} else {
		*out_ptr2 = nullptr;
		*out_size2 = 0;
	}

	return requested_len;
}

// Advance read position after consuming data (called by emulator audio thread)
static void ring_buffer_advance_read(size_t len)
{
	MacEmuIPCBuffer* shm = IPC_GetVideoSHM();
	if (!shm) return;

	uint32_t read_pos = ATOMIC_LOAD(shm->audio_ring_read_pos);
	read_pos = (read_pos + len) % shm->audio_ring_size;
	ATOMIC_STORE(shm->audio_ring_read_pos, read_pos);
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


// No dedicated audio thread needed - audio processing happens inline in audio_request_data()

#endif // ENABLE_IPC_AUDIO
