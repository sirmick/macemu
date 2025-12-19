/*
 * libdatachannel WebRTC Integration for Basilisk II
 *
 * Lightweight WebRTC streaming using libdatachannel.
 * Provides signaling server, WebRTC connections, and DataChannel for input.
 * Video encoding handled separately (VP8 via libvpx).
 */

#ifndef DATACHANNEL_WEBRTC_H
#define DATACHANNEL_WEBRTC_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback types for input events
typedef void (*dc_mouse_move_cb)(int x, int y);
typedef void (*dc_mouse_button_cb)(int x, int y, int button, bool pressed);
typedef void (*dc_key_cb)(int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta);

// Initialize WebRTC streaming
// signaling_port: WebSocket port for signaling (e.g., 8090)
// Returns true on success
bool dc_webrtc_init(int signaling_port);

// Shutdown WebRTC streaming
void dc_webrtc_exit(void);

// Push a video frame
// rgba_data: pointer to RGBA pixel data
// width, height: frame dimensions
// stride: bytes per row (usually width * 4)
void dc_webrtc_push_frame(const uint8_t* rgba_data, int width, int height, int stride);

// Get number of connected peers
int dc_webrtc_peer_count(void);

// Check if streaming is enabled/initialized
bool dc_webrtc_enabled(void);

// Set input callbacks
void dc_webrtc_set_input_callbacks(
    dc_mouse_move_cb on_mouse_move,
    dc_mouse_button_cb on_mouse_button,
    dc_key_cb on_key
);

#ifdef __cplusplus
}
#endif

#endif // DATACHANNEL_WEBRTC_H
