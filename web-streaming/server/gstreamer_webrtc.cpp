/*
 * GStreamer WebRTC Integration for Basilisk II
 *
 * Implements WebRTC streaming using GStreamer's webrtcsink element.
 * Provides hardware-accelerated VP9 encoding with software fallback,
 * built-in signaling server, and DataChannel for input.
 */

#include "gstreamer_webrtc.h"

#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/webrtc/webrtc.h>

#include <string>
#include <mutex>
#include <atomic>
#include <map>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <cstdlib>

// Simple JSON value parser for input messages
static bool json_get_string(const char* json, const char* key, char* out, size_t max_len);
static bool json_get_int(const char* json, const char* key, int* out);
static bool json_get_bool(const char* json, const char* key, bool* out);

class GStreamerWebRTC {
private:
    GstElement* pipeline = nullptr;
    GstElement* appsrc = nullptr;
    GstElement* webrtcsink = nullptr;

    // GLib main loop - required for GStreamer signaling
    GMainLoop* main_loop = nullptr;
    std::thread* glib_thread = nullptr;

    int current_width = 0;
    int current_height = 0;
    std::mutex frame_mutex;
    std::atomic<bool> initialized{false};
    std::atomic<int> peer_count{0};

    // Track DataChannels per peer
    std::map<std::string, GstWebRTCDataChannel*> data_channels;
    std::mutex dc_mutex;

    // Timestamp tracking for frame timing
    GstClockTime base_time = GST_CLOCK_TIME_NONE;
    uint64_t frame_count = 0;

    // Input callbacks
    gst_mouse_move_cb on_mouse_move = nullptr;
    gst_mouse_button_cb on_mouse_button = nullptr;
    gst_key_cb on_key = nullptr;

public:
    bool init(int port);
    void shutdown();
    void push_frame(const uint8_t* rgba, int w, int h, int stride);
    int get_peer_count() { return peer_count.load(); }
    bool is_enabled() { return initialized.load(); }

    void set_callbacks(gst_mouse_move_cb mm, gst_mouse_button_cb mb, gst_key_cb k) {
        on_mouse_move = mm;
        on_mouse_button = mb;
        on_key = k;
    }

    // Accessor for callbacks (used by signal handlers)
    gst_mouse_move_cb get_mouse_move_cb() { return on_mouse_move; }
    gst_mouse_button_cb get_mouse_button_cb() { return on_mouse_button; }
    gst_key_cb get_key_cb() { return on_key; }

    // Process input message from DataChannel
    void process_input_message(const char* message);

private:
    std::string select_encoder();
    void update_caps(int width, int height);

    // GStreamer signal callbacks
    static void on_consumer_added(GstElement* sink, const gchar* peer_id,
                                   GstElement* webrtcbin, gpointer user_data);
    static void on_consumer_removed(GstElement* sink, const gchar* peer_id,
                                     GstElement* webrtcbin, gpointer user_data);
    static void on_data_channel(GstElement* webrtcbin, GstWebRTCDataChannel* channel,
                                 gpointer user_data);
    static void on_dc_message_string(GstWebRTCDataChannel* channel, gchar* message,
                                      gpointer user_data);
};

// Global instance
static GStreamerWebRTC* g_webrtc = nullptr;

// Simple JSON parsing utilities (avoids external dependency)
// These are minimal parsers for our specific input message format

static bool json_get_string(const char* json, const char* key, char* out, size_t max_len) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char* pos = strstr(json, search);
    if (!pos) return false;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return false;

    // Skip whitespace and find opening quote
    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) pos++;
    if (*pos != '"') return false;
    pos++;

    // Copy until closing quote
    size_t i = 0;
    while (*pos && *pos != '"' && i < max_len - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return true;
}

static bool json_get_int(const char* json, const char* key, int* out) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char* pos = strstr(json, search);
    if (!pos) return false;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return false;

    // Skip whitespace
    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) pos++;

    *out = atoi(pos);
    return true;
}

static bool json_get_bool(const char* json, const char* key, bool* out) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char* pos = strstr(json, search);
    if (!pos) return false;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return false;

    // Skip whitespace
    while (*pos && (*pos == ':' || *pos == ' ' || *pos == '\t')) pos++;

    *out = (strncmp(pos, "true", 4) == 0);
    return true;
}

void GStreamerWebRTC::process_input_message(const char* message) {
    char type[32] = {0};
    if (!json_get_string(message, "type", type, sizeof(type))) {
        return;
    }

    if (strcmp(type, "mouse_move") == 0) {
        int x = 0, y = 0;
        json_get_int(message, "x", &x);
        json_get_int(message, "y", &y);
        if (on_mouse_move) {
            on_mouse_move(x, y);
        }
    }
    else if (strcmp(type, "mouse_down") == 0 || strcmp(type, "mouse_up") == 0) {
        int x = 0, y = 0, button = 0;
        bool pressed = (strcmp(type, "mouse_down") == 0);
        json_get_int(message, "x", &x);
        json_get_int(message, "y", &y);
        json_get_int(message, "button", &button);
        if (on_mouse_button) {
            on_mouse_button(x, y, button, pressed);
        }
    }
    else if (strcmp(type, "key_down") == 0 || strcmp(type, "key_up") == 0) {
        int keycode = 0;
        bool pressed = (strcmp(type, "key_down") == 0);
        bool ctrl = false, alt = false, shift = false, meta = false;
        json_get_int(message, "keyCode", &keycode);
        json_get_bool(message, "ctrl", &ctrl);
        json_get_bool(message, "alt", &alt);
        json_get_bool(message, "shift", &shift);
        json_get_bool(message, "meta", &meta);
        if (on_key) {
            on_key(keycode, pressed, ctrl, alt, shift, meta);
        }
    }
}

std::string GStreamerWebRTC::select_encoder() {
    GstElementFactory* factory;

    // Check for hardware VP9 encoders in order of preference

    // VA-API (Intel/AMD, newer API)
    factory = gst_element_factory_find("vavp9enc");
    if (factory) {
        gst_object_unref(factory);
        fprintf(stderr, "GStreamer WebRTC: Using VA-API VP9 encoder (vavp9enc)\n");
        return "vavp9enc";
    }

    // VAAPI (Intel/AMD, older API)
    factory = gst_element_factory_find("vaapivp9enc");
    if (factory) {
        gst_object_unref(factory);
        fprintf(stderr, "GStreamer WebRTC: Using VAAPI VP9 encoder (vaapivp9enc)\n");
        return "vaapivp9enc";
    }

    // Software VP9 encoder (always available with gst-plugins-good)
    fprintf(stderr, "GStreamer WebRTC: Using software VP9 encoder (vp9enc)\n");
    return "vp9enc deadline=1 cpu-used=4 target-bitrate=2000000 keyframe-max-dist=30";
}

bool GStreamerWebRTC::init(int port) {
    // Initialize GStreamer
    GError* error = nullptr;
    if (!gst_init_check(nullptr, nullptr, &error)) {
        fprintf(stderr, "GStreamer WebRTC: Failed to initialize GStreamer: %s\n",
                error ? error->message : "unknown error");
        if (error) g_error_free(error);
        return false;
    }

    // Start GLib main loop in a separate thread
    // This is required for GStreamer's webrtcsink signaling to work
    glib_thread = new std::thread([this]() {
        main_loop = g_main_loop_new(nullptr, FALSE);
        g_main_loop_run(main_loop);
        g_main_loop_unref(main_loop);
        main_loop = nullptr;
    });

    // Wait for main loop to start
    while (!main_loop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Give the main loop time to fully initialize
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Check if webrtcsink is available
    GstElementFactory* webrtcsink_factory = gst_element_factory_find("webrtcsink");
    if (!webrtcsink_factory) {
        fprintf(stderr, "GStreamer WebRTC: webrtcsink element not found!\n");
        fprintf(stderr, "GStreamer WebRTC: Install gst-plugins-rs or build from source.\n");
        fprintf(stderr, "GStreamer WebRTC: See: https://gitlab.freedesktop.org/gstreamer/gst-plugins-rs\n");
        return false;
    }
    gst_object_unref(webrtcsink_factory);

    // Note: webrtcsink handles encoding internally, so we just feed it raw video
    // Build pipeline description
    // appsrc provides raw RGBA frames
    // videoconvert converts to format webrtcsink expects
    // webrtcsink handles encoding, WebRTC negotiation and streaming
    // enable-data-channel-navigation=true enables DataChannel for input
    std::string pipeline_desc =
        "appsrc name=src format=time is-live=true do-timestamp=true "
        "caps=video/x-raw,format=RGBA,width=640,height=480,framerate=30/1 ! "
        "queue max-size-buffers=2 leaky=downstream ! "
        "videoconvert ! "
        "video/x-raw,format=I420 ! "
        "webrtcsink name=sink "
        "enable-data-channel-navigation=true "
        "run-signalling-server=true "
        "signalling-server-host=0.0.0.0 "
        "signalling-server-port=" + std::to_string(port);

    fprintf(stderr, "GStreamer WebRTC: Creating pipeline...\n");

    pipeline = gst_parse_launch(pipeline_desc.c_str(), &error);
    if (error) {
        fprintf(stderr, "GStreamer WebRTC: Pipeline error: %s\n", error->message);
        g_error_free(error);
        return false;
    }

    if (!pipeline) {
        fprintf(stderr, "GStreamer WebRTC: Failed to create pipeline\n");
        return false;
    }

    // Get element references
    appsrc = gst_bin_get_by_name(GST_BIN(pipeline), "src");
    webrtcsink = gst_bin_get_by_name(GST_BIN(pipeline), "sink");

    if (!appsrc || !webrtcsink) {
        fprintf(stderr, "GStreamer WebRTC: Failed to get pipeline elements\n");
        shutdown();
        return false;
    }

    // Configure appsrc
    g_object_set(G_OBJECT(appsrc),
        "stream-type", GST_APP_STREAM_TYPE_STREAM,
        "format", GST_FORMAT_TIME,
        "is-live", TRUE,
        "do-timestamp", TRUE,
        "min-latency", (gint64)0,
        "max-latency", (gint64)(GST_SECOND / 30),  // One frame at 30fps
        nullptr);

    // Connect signals for consumer tracking
    g_signal_connect(webrtcsink, "consumer-added",
                     G_CALLBACK(on_consumer_added), this);
    g_signal_connect(webrtcsink, "consumer-removed",
                     G_CALLBACK(on_consumer_removed), this);

    // Start the pipeline
    GstStateChangeReturn ret = gst_element_set_state(pipeline, GST_STATE_PLAYING);
    if (ret == GST_STATE_CHANGE_FAILURE) {
        fprintf(stderr, "GStreamer WebRTC: Failed to start pipeline\n");
        shutdown();
        return false;
    }

    initialized = true;
    fprintf(stderr, "GStreamer WebRTC: Streaming on port %d\n", port);

    return true;
}

void GStreamerWebRTC::update_caps(int width, int height) {
    if (!appsrc) return;

    GstCaps* caps = gst_caps_new_simple("video/x-raw",
        "format", G_TYPE_STRING, "RGBA",
        "width", G_TYPE_INT, width,
        "height", G_TYPE_INT, height,
        "framerate", GST_TYPE_FRACTION, 30, 1,
        nullptr);

    gst_app_src_set_caps(GST_APP_SRC(appsrc), caps);
    gst_caps_unref(caps);

    fprintf(stderr, "GStreamer WebRTC: Resolution changed to %dx%d\n", width, height);
}

void GStreamerWebRTC::push_frame(const uint8_t* rgba, int w, int h, int stride) {
    if (!initialized.load() || !appsrc) return;

    // Note: We must continue pushing frames even when no peers are connected
    // because webrtcsink needs data flowing through the pipeline to register
    // itself as a producer with the signalling server.

    std::lock_guard<std::mutex> lock(frame_mutex);

    // Handle resolution changes
    if (w != current_width || h != current_height) {
        update_caps(w, h);
        current_width = w;
        current_height = h;
        frame_count = 0;
        base_time = GST_CLOCK_TIME_NONE;
    }

    // Create buffer
    size_t size = w * h * 4;
    GstBuffer* buffer = gst_buffer_new_allocate(nullptr, size, nullptr);
    if (!buffer) {
        fprintf(stderr, "GStreamer WebRTC: Failed to allocate buffer\n");
        return;
    }

    // Copy frame data
    GstMapInfo map;
    if (!gst_buffer_map(buffer, &map, GST_MAP_WRITE)) {
        gst_buffer_unref(buffer);
        return;
    }

    if (stride == w * 4) {
        // Fast path: no stride conversion needed
        memcpy(map.data, rgba, size);
    } else {
        // Copy row by row handling stride
        for (int y = 0; y < h; y++) {
            memcpy(map.data + y * w * 4, rgba + y * stride, w * 4);
        }
    }
    gst_buffer_unmap(buffer, &map);

    // Set buffer timestamps for proper playback
    GstClockTime duration = GST_SECOND / 30;  // 30 fps
    GstClockTime pts = frame_count * duration;

    GST_BUFFER_PTS(buffer) = pts;
    GST_BUFFER_DTS(buffer) = pts;
    GST_BUFFER_DURATION(buffer) = duration;

    frame_count++;

    // Push buffer to pipeline
    GstFlowReturn ret = gst_app_src_push_buffer(GST_APP_SRC(appsrc), buffer);
    if (ret != GST_FLOW_OK) {
        // Buffer was already taken by gst_app_src_push_buffer, don't unref
        if (ret == GST_FLOW_FLUSHING) {
            // Pipeline is shutting down, ignore
        } else {
            fprintf(stderr, "GStreamer WebRTC: Push buffer failed: %d\n", ret);
        }
    }
}

void GStreamerWebRTC::on_data_channel(GstElement* webrtcbin, GstWebRTCDataChannel* channel,
                                       gpointer user_data) {
    (void)webrtcbin;
    auto* self = static_cast<GStreamerWebRTC*>(user_data);

    gchar* label = nullptr;
    g_object_get(channel, "label", &label, nullptr);
    fprintf(stderr, "GStreamer WebRTC: DataChannel opened: %s\n", label ? label : "unnamed");
    g_free(label);

    // Connect message handler
    g_signal_connect(channel, "on-message-string",
                     G_CALLBACK(on_dc_message_string), self);
}

void GStreamerWebRTC::on_dc_message_string(GstWebRTCDataChannel* channel, gchar* message,
                                            gpointer user_data) {
    (void)channel;
    auto* self = static_cast<GStreamerWebRTC*>(user_data);

    self->process_input_message(message);
}

void GStreamerWebRTC::on_consumer_added(GstElement* sink, const gchar* peer_id,
                                         GstElement* webrtcbin, gpointer user_data) {
    (void)sink;

    auto* self = static_cast<GStreamerWebRTC*>(user_data);
    self->peer_count++;
    fprintf(stderr, "GStreamer WebRTC: Consumer connected: %s (%d total)\n",
            peer_id, self->peer_count.load());

    // Connect to on-data-channel signal to receive DataChannels created by remote peer
    g_signal_connect(webrtcbin, "on-data-channel",
                     G_CALLBACK(on_data_channel), self);
}

void GStreamerWebRTC::on_consumer_removed(GstElement* sink, const gchar* peer_id,
                                           GstElement* webrtcbin, gpointer user_data) {
    (void)sink;
    (void)webrtcbin;

    auto* self = static_cast<GStreamerWebRTC*>(user_data);
    if (self->peer_count > 0) {
        self->peer_count--;
    }
    fprintf(stderr, "GStreamer WebRTC: Consumer disconnected: %s (%d total)\n",
            peer_id, self->peer_count.load());
}

void GStreamerWebRTC::shutdown() {
    if (pipeline) {
        fprintf(stderr, "GStreamer WebRTC: Shutting down...\n");

        // Send EOS to cleanly finish encoding
        if (appsrc) {
            gst_app_src_end_of_stream(GST_APP_SRC(appsrc));
        }

        // Stop the pipeline
        gst_element_set_state(pipeline, GST_STATE_NULL);

        // Unref elements
        if (appsrc) {
            gst_object_unref(appsrc);
            appsrc = nullptr;
        }
        if (webrtcsink) {
            gst_object_unref(webrtcsink);
            webrtcsink = nullptr;
        }

        gst_object_unref(pipeline);
        pipeline = nullptr;
    }

    // Stop GLib main loop
    if (main_loop) {
        g_main_loop_quit(main_loop);
    }
    if (glib_thread) {
        glib_thread->join();
        delete glib_thread;
        glib_thread = nullptr;
    }

    initialized = false;
    peer_count = 0;
    current_width = 0;
    current_height = 0;
    frame_count = 0;

    fprintf(stderr, "GStreamer WebRTC: Shutdown complete\n");
}

// C API Implementation

bool gst_webrtc_init(int signaling_port) {
    if (g_webrtc) {
        fprintf(stderr, "GStreamer WebRTC: Already initialized\n");
        return false;
    }

    g_webrtc = new GStreamerWebRTC();
    if (!g_webrtc->init(signaling_port)) {
        delete g_webrtc;
        g_webrtc = nullptr;
        return false;
    }

    return true;
}

void gst_webrtc_exit(void) {
    if (g_webrtc) {
        g_webrtc->shutdown();
        delete g_webrtc;
        g_webrtc = nullptr;
    }
}

bool gst_webrtc_enabled(void) {
    return g_webrtc && g_webrtc->is_enabled();
}

void gst_webrtc_push_frame(const uint8_t* rgba_data, int width, int height, int stride) {
    if (g_webrtc) {
        g_webrtc->push_frame(rgba_data, width, height, stride);
    }
}

int gst_webrtc_peer_count(void) {
    return g_webrtc ? g_webrtc->get_peer_count() : 0;
}

void gst_webrtc_set_input_callbacks(gst_mouse_move_cb mm, gst_mouse_button_cb mb, gst_key_cb k) {
    if (g_webrtc) {
        g_webrtc->set_callbacks(mm, mb, k);
    }
}
