/*
 * Test harness for GStreamer WebRTC streaming
 *
 * Generates a simple test pattern and streams it via WebRTC.
 * Used to verify the GStreamer pipeline works before integrating
 * with the actual emulator.
 */

#include "gstreamer_webrtc.h"

#include <glib.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <csignal>
#include <thread>
#include <chrono>
#include <atomic>

static std::atomic<bool> running{true};
static GMainLoop* main_loop = nullptr;

void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    running = false;
    if (main_loop) {
        g_main_loop_quit(main_loop);
    }
}

// GMainLoop thread - required for GStreamer signalling to work
void glib_main_loop_thread() {
    main_loop = g_main_loop_new(nullptr, FALSE);
    g_main_loop_run(main_loop);
    g_main_loop_unref(main_loop);
    main_loop = nullptr;
}

// Generate a simple animated test pattern
void generate_test_pattern(uint8_t* rgba, int width, int height, int frame) {
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            uint8_t* pixel = rgba + (y * width + x) * 4;

            // Animated gradient with moving bars
            int bar_x = (x + frame * 2) % 64;
            int bar_y = (y + frame) % 64;

            // Color channels based on position
            pixel[0] = (uint8_t)((x * 255) / width);   // R: horizontal gradient
            pixel[1] = (uint8_t)((y * 255) / height);  // G: vertical gradient
            pixel[2] = (uint8_t)(128 + 127 * sin(frame * 0.05));  // B: animated

            // Add grid pattern
            if (bar_x < 2 || bar_y < 2) {
                pixel[0] = 255;
                pixel[1] = 255;
                pixel[2] = 255;
            }

            // Border
            if (x < 2 || x >= width - 2 || y < 2 || y >= height - 2) {
                pixel[0] = 255;
                pixel[1] = 0;
                pixel[2] = 0;
            }

            pixel[3] = 255;  // Alpha
        }
    }

    // Draw frame counter in top-left
    int digit_x = 10;
    int digit_y = 10;
    int num = frame % 1000;
    for (int i = 0; i < 3; i++) {
        int d = (num / (int)pow(10, 2 - i)) % 10;
        for (int dy = 0; dy < 10; dy++) {
            for (int dx = 0; dx < 8; dx++) {
                int px = digit_x + i * 10 + dx;
                int py = digit_y + dy;
                if (px < width && py < height) {
                    uint8_t* pixel = rgba + (py * width + px) * 4;
                    // Simple digit representation
                    bool on = false;
                    if (d == 0) on = (dx < 6 && (dy < 2 || dy > 7)) || (dx < 2) || (dx > 3 && dx < 6);
                    else if (d == 1) on = (dx > 3 && dx < 6);
                    else on = ((dx + dy + d) % 3 == 0);  // Placeholder pattern
                    if (on) {
                        pixel[0] = 0;
                        pixel[1] = 255;
                        pixel[2] = 0;
                    }
                }
            }
        }
    }
}

void mouse_move_callback(int x, int y) {
    printf("Mouse move: %d, %d\n", x, y);
}

void mouse_button_callback(int x, int y, int button, bool pressed) {
    printf("Mouse %s: %d, %d button=%d\n", pressed ? "down" : "up", x, y, button);
}

void key_callback(int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta) {
    printf("Key %s: code=%d ctrl=%d alt=%d shift=%d meta=%d\n",
           pressed ? "down" : "up", keycode, ctrl, alt, shift, meta);
}

int main(int argc, char* argv[]) {
    int port = 8090;
    int width = 640;
    int height = 480;
    int fps = 30;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            width = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            height = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            fps = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  -p PORT   Signaling server port (default: 8090)\n");
            printf("  -w WIDTH  Frame width (default: 640)\n");
            printf("  -h HEIGHT Frame height (default: 480)\n");
            printf("  -f FPS    Frames per second (default: 30)\n");
            return 0;
        }
    }

    printf("GStreamer WebRTC Test Server\n");
    printf("  Resolution: %dx%d @ %d fps\n", width, height, fps);
    printf("  Signaling port: %d\n", port);
    printf("\n");

    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Start GLib main loop in a separate thread
    // This is required for GStreamer's webrtcsink signalling to work
    std::thread glib_thread(glib_main_loop_thread);

    // Wait for main loop to start
    while (!main_loop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Give the main loop time to initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Initialize WebRTC
    if (!gst_webrtc_init(port)) {
        fprintf(stderr, "Failed to initialize WebRTC streaming\n");
        if (main_loop) g_main_loop_quit(main_loop);
        glib_thread.join();
        return 1;
    }

    // Set input callbacks
    gst_webrtc_set_input_callbacks(
        mouse_move_callback,
        mouse_button_callback,
        key_callback
    );

    printf("WebRTC streaming started.\n");
    printf("Connect a browser to ws://localhost:%d\n", port);
    printf("Press Ctrl+C to stop.\n\n");

    // Allocate frame buffer
    uint8_t* rgba = new uint8_t[width * height * 4];

    int frame = 0;
    auto frame_duration = std::chrono::microseconds(1000000 / fps);
    auto last_stats = std::chrono::steady_clock::now();
    int frames_since_stats = 0;

    while (running) {
        auto frame_start = std::chrono::steady_clock::now();

        // Generate test pattern
        generate_test_pattern(rgba, width, height, frame);

        // Push frame
        gst_webrtc_push_frame(rgba, width, height, width * 4);

        frame++;
        frames_since_stats++;

        // Print stats every 5 seconds
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats);
        if (elapsed.count() >= 5) {
            float actual_fps = frames_since_stats / (float)elapsed.count();
            printf("Stats: frame=%d peers=%d actual_fps=%.1f\n",
                   frame, gst_webrtc_peer_count(), actual_fps);
            frames_since_stats = 0;
            last_stats = now;
        }

        // Sleep to maintain frame rate
        auto frame_end = std::chrono::steady_clock::now();
        auto frame_time = std::chrono::duration_cast<std::chrono::microseconds>(frame_end - frame_start);
        if (frame_time < frame_duration) {
            std::this_thread::sleep_for(frame_duration - frame_time);
        }
    }

    delete[] rgba;

    // Cleanup
    gst_webrtc_exit();

    // Stop GLib main loop
    if (main_loop) {
        g_main_loop_quit(main_loop);
    }
    glib_thread.join();

    printf("Done.\n");
    return 0;
}
