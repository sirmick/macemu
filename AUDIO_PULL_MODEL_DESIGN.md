# Audio IPC Pull Model Design

## Problem Statement

Audio quality was terrible with the original push-based IPC model:
- **Emulator pushed** audio every 20ms (autonomous timer)
- **Server consumed** whenever eventfd fired (async)
- **Clock drift**: Two independent clocks caused desynchronization
- **Buffer issues**: Frames overlapped or got dropped
- **Symptoms**: "Parts of audio buffer played over top of itself"

**Root cause**: 20ms was WRONG for 4096 samples @ 44.1kHz (should be ~93ms)

## Why SDL Works

SDL uses a **pull model** that perfectly synchronizes timing:

```cpp
// SDL audio hardware callback (called at hardware rate)
static void stream_func(void *arg, uint8 *stream, int stream_len) {
    // 1. Trigger Mac interrupt
    SetInterruptFlag(INTFLAG_AUDIO);
    TriggerInterrupt();

    // 2. BLOCK waiting for Mac to fill buffer (synchronous!)
    SDL_SemWait(audio_irq_done_sem);

    // 3. Read Mac's buffer
    memcpy(audio_mix_buf, Mac2HostAddr(buffer_ptr), work_size);

    // 4. Mix into SDL output
    SDL_MixAudio(stream, audio_mix_buf, work_size, volume);
}
```

**Key insight**: SDL **blocks** until Mac provides data. Single clock source (hardware).

## Solution: Server-Driven Pull Model

Make IPC mirror SDL's architecture:

```
Before (BROKEN - Push):
┌─────────┐ 20ms timer  ┌─────────┐ async    ┌────────┐
│Emulator │────────────>│   SHM   │────────>│ Server │
└─────────┘  autonomous └─────────┘ epoll   └────────┘
              (wrong timing!)        (desync)

After (FIXED - Pull):
┌─────────┐             ┌─────────┐         ┌────────┐
│Emulator │<────────────│   SHM   │<────────│ Server │
└─────────┘  on request └─────────┘ 20ms    └────────┘
              (reactive)            timer    (drives timing)
                                    (Opus frame rate)
```

Server dictates timing (like SDL hardware), emulator responds (like Mac OS).

## Implementation

### Phase 1: Protocol (✅ DONE)

**File**: `BasiliskII/src/IPC/ipc_protocol.h`

Added new message type:
```c
#define MACEMU_INPUT_AUDIO_REQUEST  5

typedef struct {
    MacEmuInputHeader hdr;       // type = MACEMU_INPUT_AUDIO_REQUEST
    uint32_t requested_samples;  // Usually 960 for 20ms @ 48kHz
} MacEmuAudioRequestInput;
```

### Phase 2: Emulator (✅ DONE)

**Files Modified**:
- `BasiliskII/src/IPC/audio_ipc.cpp`
- `BasiliskII/src/IPC/video_ipc.cpp`
- `BasiliskII/src/include/audio.h`

**Changes**:

1. **Audio thread is now REACTIVE** (was autonomous):
```cpp
static void audio_thread_func() {
    while (!audio_thread_cancel) {
        // BLOCK waiting for server request (was: sleep 20ms)
        {
            std::unique_lock<std::mutex> lock(audio_request_mutex);
            audio_request_cv.wait(lock, []{ return audio_requested || audio_thread_cancel; });
            audio_requested = false;
        }

        // Only run when server asks for data
        if (AudioStatus.num_sources) {
            SetInterruptFlag(INTFLAG_AUDIO);
            TriggerInterrupt();
            wait_for_interrupt_complete();
            read_mac_audio_buffer();
            write_audio_to_shm();
        }
    }
}
```

2. **New function for server requests**:
```cpp
void audio_request_data() {
    std::lock_guard<std::mutex> lock(audio_request_mutex);
    audio_requested = true;
    audio_request_cv.notify_one();
}
```

3. **Control socket thread handles requests**:
```cpp
case MACEMU_INPUT_AUDIO_REQUEST:
    audio_request_data();  // Wake audio thread
    break;
```

### Phase 3: Server (❌ TODO - Next Session)

**File**: `web-streaming/server/server.cpp`

**Function to modify**: `audio_loop_mac_ipc()`

**Current behavior**:
```cpp
while (g_running) {
    epoll_wait(epoll_fd, ...);  // Wait for emulator to push
    read(g_audio_ready_eventfd, ...);
    read_audio_from_shm();
    encode_to_opus();
    send_to_peers();
}
```

**New behavior (PSEUDO-CODE)**:
```cpp
void audio_loop_mac_ipc(WebRTCServer& webrtc) {
    int epoll_fd = epoll_create1(0);
    int current_eventfd = -1;

    // Opus frame timing (20ms @ 48kHz = 960 samples)
    const auto frame_duration = std::chrono::milliseconds(20);

    while (g_running) {
        auto frame_start = std::chrono::steady_clock::now();

        // Step 1: Send AUDIO_REQUEST to emulator
        if (g_control_socket >= 0 && g_video_shm && AudioStatus.num_sources > 0) {
            MacEmuAudioRequestInput req;
            memset(&req, 0, sizeof(req));
            req.hdr.type = MACEMU_INPUT_AUDIO_REQUEST;
            req.hdr.flags = 0;
            req.requested_samples = 960;  // 20ms @ 48kHz

            ssize_t sent = send(g_control_socket, &req, sizeof(req), MSG_NOSIGNAL);
            if (sent != sizeof(req)) {
                fprintf(stderr, "Audio: Failed to send request: %s\n", strerror(errno));
                // Handle disconnection
                std::this_thread::sleep_for(frame_duration);
                continue;
            }
        } else {
            // No connection or no audio sources - sleep and retry
            std::this_thread::sleep_for(frame_duration);
            continue;
        }

        // Step 2: Wait for emulator response (audio_ready_eventfd)
        // Setup epoll for eventfd (same as current code)
        if (g_audio_ready_eventfd >= 0 && g_audio_ready_eventfd != current_eventfd) {
            if (current_eventfd >= 0) {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_eventfd, nullptr);
            }
            struct epoll_event ev;
            ev.events = EPOLLIN;
            ev.data.fd = g_audio_ready_eventfd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, g_audio_ready_eventfd, &ev) == 0) {
                current_eventfd = g_audio_ready_eventfd;
            }
        }

        // Wait for response with timeout (100ms)
        struct epoll_event events[1];
        int nfds = epoll_wait(epoll_fd, events, 1, 100);

        if (nfds <= 0) {
            // Timeout or error - continue loop
            auto elapsed = std::chrono::steady_clock::now() - frame_start;
            auto remaining = frame_duration - elapsed;
            if (remaining > std::chrono::milliseconds(0)) {
                std::this_thread::sleep_for(remaining);
            }
            continue;
        }

        // Step 3: Read eventfd
        uint64_t event_count;
        if (read(g_audio_ready_eventfd, &event_count, sizeof(event_count)) != sizeof(event_count)) {
            continue;
        }

        // Step 4: Read audio from SHM (EXISTING CODE - keep as-is)
        if (!g_video_shm) continue;

        int ready_index = g_video_shm->audio_ready_index;
        if (ready_index < 0 || ready_index >= MACEMU_AUDIO_NUM_BUFFERS) continue;

        int audio_format = g_video_shm->audio_format;
        if (audio_format == MACEMU_AUDIO_FORMAT_NONE) continue;

        int sample_rate = g_video_shm->audio_sample_rate;
        int channels = g_video_shm->audio_channels;
        int samples = g_video_shm->audio_samples_in_frame;

        if (samples <= 0 || samples > MACEMU_AUDIO_MAX_SAMPLES_PER_FRAME) continue;

        const uint8_t* audio_data = macemu_get_ready_audio(g_video_shm);
        int bytes_per_sample = 2 * channels;
        int input_size = samples * bytes_per_sample;

        if (input_size > MACEMU_AUDIO_MAX_FRAME_SIZE) {
            input_size = MACEMU_AUDIO_MAX_FRAME_SIZE;
        }

        // Step 5: Encode to Opus (EXISTING CODE - keep as-is)
        if (g_audio_encoder) {
            std::vector<uint8_t> opus_data = g_audio_encoder->encode_dynamic(
                reinterpret_cast<const int16_t*>(audio_data),
                samples,
                sample_rate,
                channels
            );

            // Step 6: Send to peers (EXISTING CODE - keep as-is)
            if (!opus_data.empty()) {
                webrtc.send_audio_to_all_peers(opus_data);
            }
        }

        // Step 7: Maintain frame timing (sleep remainder of 20ms)
        auto elapsed = std::chrono::steady_clock::now() - frame_start;
        auto remaining = frame_duration - elapsed;
        if (remaining > std::chrono::milliseconds(0)) {
            std::this_thread::sleep_for(remaining);
        }
    }

    if (epoll_fd >= 0) {
        close(epoll_fd);
    }
}
```

**Key server changes**:
1. **Request → Wait → Process** loop (not passive epoll wait)
2. **Fixed 20ms timing** maintained by server (single clock source)
3. **Timeout handling** for robustness (if emulator doesn't respond)
4. **Reuse existing** SHM read, Opus encode, and send code

## Additional Requirements

### Server needs access to:
- `g_control_socket` - to send AUDIO_REQUEST messages
- Check if control socket is available/connected

**Current globals in server.cpp**:
```cpp
#define g_control_socket    (g_ipc.get_control_socket())
```

Already available! Just need to use it.

### Byte Order Handling

**CRITICAL**: Keep the fix from commit `cd4f0070`:
```cpp
// Emulator does direct memcpy (like SDL)
memcpy(audio_mix_buffer, src, data_len);  // NO byte swapping!

// Server receives big-endian S16MSB data
// Opus encoder needs to handle byte order
```

**Check Opus encoder**: Does `encode_dynamic()` expect little-endian or big-endian?

If Opus expects LE, we need to byte-swap on **server side** (not emulator):
```cpp
// In server, before encoding:
if (needs_byte_swap) {
    int16_t* samples = (int16_t*)audio_data;
    for (int i = 0; i < samples_count * channels; i++) {
        uint16_t s = samples[i];
        samples[i] = (s >> 8) | (s << 8);  // Swap on server
    }
}
```

## Testing Plan

1. **Build emulator** with pull model changes
2. **Build server** with request-based loop
3. **Test with SDL** to confirm byte order is correct
4. **Test with IPC** - should match SDL quality
5. **Monitor timing** - check request→response latency
6. **Verify synchronization** - no overlapping frames

## Expected Results

✅ Audio quality matches SDL (perfect)
✅ No clock drift over time
✅ Correct frame timing (93ms @ 44.1kHz, 20ms @ 48kHz)
✅ Natural backpressure (server can't overrun emulator)
✅ Robust to temporary slowdowns

## Rollback Plan

If pull model doesn't work:
- Revert to `ipc-audio-socket` branch (Unix socket approach)
- Or revert to commit before `563aebff` (original SHM push model)
- Keep the byte-swap fix (direct memcpy) regardless

## Current Git State

**Branch**: `fix-audio-shm-byte-swap`

**Commits**:
1. `cd4f0070` - Fix byte swapping (memcpy instead of ntohs)
2. `85474761` - Convert emulator to pull model (THIS COMMIT)

**Next commit** (after server changes):
- "Implement server-side pull model for audio IPC"

## Files to Modify (Next Session)

1. `web-streaming/server/server.cpp`
   - Modify `audio_loop_mac_ipc()` function
   - Add request sending logic
   - Keep existing SHM read / Opus / send code

2. **Maybe** `web-streaming/server/audio/opus_encoder.cpp`
   - Check byte order expectations
   - Add byte swapping if needed

## References

- SDL audio driver: `BasiliskII/src/SDL/audio_sdl.cpp:230-277`
- Emulator audio thread: `BasiliskII/src/IPC/audio_ipc.cpp:427-573`
- Control message handling: `BasiliskII/src/IPC/video_ipc.cpp:297-412`
- Protocol definitions: `BasiliskII/src/IPC/ipc_protocol.h:232-312`

---

**Status**: Emulator ready, server pending. Continue in next session.
