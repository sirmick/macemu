/*
 * Basilisk II WebSocket Integration Header
 *
 * This header provides the interface for integrating the WebSocket
 * streaming server with Basilisk II's video and input subsystems.
 */

#ifndef BASILISK_INTEGRATION_H
#define BASILISK_INTEGRATION_H

#include <cstdint>
#include <functional>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the WebSocket streaming system
 * Call this from main() after SDL initialization
 *
 * @param port WebSocket server port (default 8090)
 * @return true on success
 */
bool ws_streaming_init(int port);

/*
 * Shutdown the WebSocket streaming system
 * Call this before exiting
 */
void ws_streaming_exit(void);

/*
 * Check if WebSocket streaming is enabled
 */
bool ws_streaming_enabled(void);

/*
 * Send a frame to connected WebSocket clients
 * Call this after each frame is rendered (from present_sdl_video or similar)
 *
 * @param rgba_data Pointer to RGBA pixel data
 * @param width Frame width in pixels
 * @param height Frame height in pixels
 * @param bytes_per_row Bytes per row (pitch)
 */
void ws_streaming_send_frame(const uint8_t* rgba_data, int width, int height, int bytes_per_row);

/*
 * Send audio samples to connected WebSocket clients
 *
 * @param samples Pointer to audio samples (16-bit signed)
 * @param count Number of samples
 * @param sample_rate Sample rate in Hz
 */
void ws_streaming_send_audio(const int16_t* samples, int count, int sample_rate);

/*
 * Get the number of connected clients
 */
int ws_streaming_client_count(void);

/*
 * Process pending WebSocket events
 * Call this periodically from the main loop if not using a separate thread
 */
void ws_streaming_poll(void);

/*
 * Input injection callbacks - set by Basilisk II
 */
typedef void (*ws_mouse_move_cb)(int x, int y);
typedef void (*ws_mouse_button_cb)(int x, int y, int button, bool pressed);
typedef void (*ws_key_cb)(int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta);

void ws_set_input_callbacks(ws_mouse_move_cb mouse_move,
                           ws_mouse_button_cb mouse_button,
                           ws_key_cb key);

#ifdef __cplusplus
}
#endif

#endif // BASILISK_INTEGRATION_H
