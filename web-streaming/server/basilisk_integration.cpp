/*
 * Basilisk II WebSocket Integration Implementation
 *
 * Provides the bridge between Basilisk II's emulation core and
 * the WebSocket streaming server.
 */

#include "basilisk_integration.h"
#include "websocket_server.h"
#include <cstdio>
#include <cstring>
#include <atomic>
#include <mutex>
#include <vector>

// Global state
static WebSocketServer* g_server = nullptr;
static std::atomic<bool> g_enabled(false);
static std::mutex g_frame_mutex;

// Frame conversion buffer (for removing row padding if needed)
static std::vector<uint8_t> g_frame_buffer;

// Input callbacks
static ws_mouse_move_cb g_mouse_move_cb = nullptr;
static ws_mouse_button_cb g_mouse_button_cb = nullptr;
static ws_key_cb g_key_cb = nullptr;

// Forward input events from WebSocket to emulator
static void handle_mouse_move(int x, int y) {
    if (g_mouse_move_cb) {
        g_mouse_move_cb(x, y);
    }
}

static void handle_mouse_button(int x, int y, int button, bool pressed) {
    if (g_mouse_button_cb) {
        g_mouse_button_cb(x, y, button, pressed);
    }
}

static void handle_key(int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta) {
    if (g_key_cb) {
        g_key_cb(keycode, pressed, ctrl, alt, shift, meta);
    }
}

bool ws_streaming_init(int port) {
    if (g_server) {
        fprintf(stderr, "WebSocket streaming already initialized\n");
        return false;
    }

    printf("Initializing WebSocket streaming on port %d...\n", port);

    g_server = new WebSocketServer(port);

    // Set up input callbacks
    WebSocketCallbacks callbacks;
    callbacks.on_mouse_move = handle_mouse_move;
    callbacks.on_mouse_button = handle_mouse_button;
    callbacks.on_key = handle_key;

    // Config callbacks (can be extended later)
    callbacks.on_get_config = []() -> std::string {
        return "{\"status\":\"running\"}";
    };

    callbacks.on_set_config = [](const std::string&) -> bool {
        return true;
    };

    callbacks.on_restart = []() {
        printf("Restart requested via WebSocket\n");
    };

    g_server->set_callbacks(callbacks);

    if (!g_server->start()) {
        fprintf(stderr, "Failed to start WebSocket server\n");
        delete g_server;
        g_server = nullptr;
        return false;
    }

    g_enabled = true;
    printf("WebSocket streaming initialized successfully\n");
    return true;
}

void ws_streaming_exit(void) {
    if (g_server) {
        printf("Shutting down WebSocket streaming...\n");
        g_enabled = false;
        g_server->stop();
        delete g_server;
        g_server = nullptr;
    }
}

bool ws_streaming_enabled(void) {
    return g_enabled && g_server != nullptr;
}

void ws_streaming_send_frame(const uint8_t* rgba_data, int width, int height, int bytes_per_row) {
    if (!g_enabled || !g_server || g_server->get_client_count() == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_frame_mutex);

    // Ensure frame is contiguous (remove row padding if present)
    const uint8_t* frame_data;
    if (bytes_per_row == width * 4) {
        frame_data = rgba_data;
    } else {
        // Need to remove row padding
        size_t required_size = width * height * 4;
        if (g_frame_buffer.size() < required_size) {
            g_frame_buffer.resize(required_size);
        }
        uint8_t* dst = g_frame_buffer.data();
        for (int y = 0; y < height; y++) {
            memcpy(dst, rgba_data + y * bytes_per_row, width * 4);
            dst += width * 4;
        }
        frame_data = g_frame_buffer.data();
    }

    // Send full frame
    g_server->broadcast_frame(frame_data, width, height);
}

void ws_streaming_send_audio(const int16_t* samples, int count, int sample_rate) {
    if (!g_enabled || !g_server) {
        return;
    }

    g_server->broadcast_audio(samples, count, sample_rate);
}

int ws_streaming_client_count(void) {
    if (!g_server) {
        return 0;
    }
    return static_cast<int>(g_server->get_client_count());
}

void ws_streaming_poll(void) {
    // Currently handled by server thread, but could add explicit polling
}

void ws_set_input_callbacks(ws_mouse_move_cb mouse_move,
                           ws_mouse_button_cb mouse_button,
                           ws_key_cb key) {
    g_mouse_move_cb = mouse_move;
    g_mouse_button_cb = mouse_button;
    g_key_cb = key;
}
