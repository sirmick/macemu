/*
 * Test WebSocket Server
 *
 * A standalone test server that sends test frames to verify the
 * WebSocket and rendering pipeline works before integrating with Basilisk II.
 */

#include "websocket_server.h"
#include <cstdio>
#include <cmath>
#include <csignal>
#include <unistd.h>

static volatile bool running = true;

void signal_handler(int sig) {
    printf("\nShutting down...\n");
    running = false;
}

// Generate a test pattern frame
void generate_test_frame(uint8_t* buffer, int width, int height, int frame_num) {
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            int idx = (y * width + x) * 4;

            // Create animated pattern
            float fx = (float)x / width;
            float fy = (float)y / height;
            float t = frame_num * 0.05f;

            // Animated gradient with moving circle
            float cx = 0.5f + 0.3f * sinf(t);
            float cy = 0.5f + 0.3f * cosf(t * 0.7f);
            float dist = sqrtf((fx - cx) * (fx - cx) + (fy - cy) * (fy - cy));

            uint8_t r, g, b;

            if (dist < 0.15f) {
                // Mac-style happy face in circle
                r = 255;
                g = 255;
                b = 255;
            } else {
                // Background gradient
                r = (uint8_t)(128 + 127 * sinf(fx * 3.14159f + t));
                g = (uint8_t)(128 + 127 * sinf(fy * 3.14159f + t * 1.3f));
                b = (uint8_t)(128 + 127 * sinf((fx + fy) * 3.14159f + t * 0.7f));
            }

            // Classic Mac desktop pattern in corners
            if ((x < 50 && y < 50) || (x >= width - 50 && y < 50) ||
                (x < 50 && y >= height - 50) || (x >= width - 50 && y >= height - 50)) {
                // Checkerboard pattern
                bool check = ((x / 4) % 2) == ((y / 4) % 2);
                r = check ? 200 : 100;
                g = check ? 200 : 100;
                b = check ? 255 : 150;
            }

            // Top menu bar
            if (y < 20) {
                r = 255;
                g = 255;
                b = 255;
            }

            buffer[idx + 0] = r;  // R
            buffer[idx + 1] = g;  // G
            buffer[idx + 2] = b;  // B
            buffer[idx + 3] = 255;  // A
        }
    }

    // Draw "Test" text area
    int text_x = 10;
    int text_y = 5;
    for (int dy = 0; dy < 10; dy++) {
        for (int dx = 0; dx < 40; dx++) {
            int px = text_x + dx;
            int py = text_y + dy;
            int idx = (py * width + px) * 4;
            buffer[idx + 0] = 0;    // R
            buffer[idx + 1] = 0;    // G
            buffer[idx + 2] = 0;    // B
            buffer[idx + 3] = 255;  // A
        }
    }
}

int main(int argc, char* argv[]) {
    int port = 8080;
    int width = 640;
    int height = 480;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            width = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            height = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-p port] [-w width] [-h height]\n", argv[0]);
            printf("  -p port    WebSocket port (default: 8080)\n");
            printf("  -w width   Frame width (default: 640)\n");
            printf("  -h height  Frame height (default: 480)\n");
            return 0;
        }
    }

    printf("Basilisk II Web Streaming Test Server\n");
    printf("=====================================\n");
    printf("Port: %d\n", port);
    printf("Resolution: %dx%d\n", width, height);
    printf("\n");

    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create frame buffer
    size_t frame_size = width * height * 4;
    uint8_t* frame_buffer = new uint8_t[frame_size];

    // Create WebSocket server
    WebSocketServer server(port);

    // Set up input callbacks (for testing)
    WebSocketCallbacks callbacks;

    callbacks.on_mouse_move = [](int x, int y) {
        printf("Mouse move: %d, %d\n", x, y);
    };

    callbacks.on_mouse_button = [](int x, int y, int button, bool pressed) {
        printf("Mouse %s: %d, %d, button %d\n",
               pressed ? "down" : "up", x, y, button);
    };

    callbacks.on_key = [](int keycode, bool pressed, bool ctrl, bool alt,
                          bool shift, bool meta) {
        printf("Key %s: 0x%02X (ctrl=%d alt=%d shift=%d meta=%d)\n",
               pressed ? "down" : "up", keycode, ctrl, alt, shift, meta);
    };

    callbacks.on_get_config = []() -> std::string {
        return "{\"test\":true,\"version\":\"1.0\"}";
    };

    callbacks.on_set_config = [](const std::string& config) -> bool {
        printf("Set config: %s\n", config.c_str());
        return true;
    };

    callbacks.on_restart = []() {
        printf("Restart requested\n");
    };

    server.set_callbacks(callbacks);

    // Start server
    if (!server.start()) {
        fprintf(stderr, "Failed to start WebSocket server\n");
        delete[] frame_buffer;
        return 1;
    }

    printf("Server running. Press Ctrl+C to stop.\n");
    printf("Open http://localhost:%d in a browser.\n\n", port);

    // Main loop - generate and send test frames
    int frame_num = 0;
    const int target_fps = 30;
    const int frame_delay_us = 1000000 / target_fps;

    while (running) {
        // Generate test frame
        generate_test_frame(frame_buffer, width, height, frame_num);

        // Broadcast to all clients
        if (server.get_client_count() > 0) {
            server.broadcast_frame(frame_buffer, width, height);

            if (frame_num % 30 == 0) {
                printf("Clients: %zu, Frame: %d\n",
                       server.get_client_count(), frame_num);
            }
        }

        frame_num++;
        usleep(frame_delay_us);
    }

    // Cleanup
    server.stop();
    delete[] frame_buffer;

    printf("Server stopped.\n");
    return 0;
}
