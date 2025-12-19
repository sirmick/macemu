/*
 * GStreamer WebRTC Integration for Basilisk II
 *
 * This header provides the interface for WebRTC streaming using
 * GStreamer's webrtcsink element with built-in signaling server.
 */

#ifndef GSTREAMER_WEBRTC_H
#define GSTREAMER_WEBRTC_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize GStreamer WebRTC pipeline
 *
 * @param signaling_port Port for built-in WebSocket signaling server
 * @return true on success
 */
bool gst_webrtc_init(int signaling_port);

/*
 * Shutdown the WebRTC streaming system
 * Call this before exiting
 */
void gst_webrtc_exit(void);

/*
 * Check if WebRTC streaming is enabled and running
 */
bool gst_webrtc_enabled(void);

/*
 * Push a video frame to the WebRTC pipeline
 * Called from video refresh thread
 *
 * @param rgba_data Pointer to RGBA pixel data
 * @param width Frame width in pixels
 * @param height Frame height in pixels
 * @param stride Bytes per row (pitch)
 */
void gst_webrtc_push_frame(const uint8_t* rgba_data, int width, int height, int stride);

/*
 * Get the number of connected WebRTC peers
 */
int gst_webrtc_peer_count(void);

/*
 * Input callbacks - invoked from DataChannel messages
 */
typedef void (*gst_mouse_move_cb)(int x, int y);
typedef void (*gst_mouse_button_cb)(int x, int y, int button, bool pressed);
typedef void (*gst_key_cb)(int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta);

/*
 * Set input callbacks for mouse and keyboard events from WebRTC DataChannel
 */
void gst_webrtc_set_input_callbacks(
    gst_mouse_move_cb mouse_move,
    gst_mouse_button_cb mouse_button,
    gst_key_cb key
);

#ifdef __cplusplus
}
#endif

#endif /* GSTREAMER_WEBRTC_H */
