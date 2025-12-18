/*
 * WebSocket Server for Basilisk II Web Streaming
 *
 * This header defines the WebSocket server interface for streaming
 * the emulator display to web browsers.
 */

#ifndef WEBSOCKET_SERVER_H
#define WEBSOCKET_SERVER_H

#include <libwebsockets.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <cstring>

// Message types for binary protocol
enum MessageType : uint8_t {
    MSG_FRAME = 0x01,       // Video frame data
    MSG_AUDIO = 0x02,       // Audio data
    MSG_INPUT = 0x03,       // Input event from client
    MSG_CONFIG = 0x04,      // Configuration command
    MSG_STATUS = 0x05,      // Status/heartbeat
};

// Input event types
enum InputEventType : uint8_t {
    INPUT_MOUSE_MOVE = 0x01,
    INPUT_MOUSE_DOWN = 0x02,
    INPUT_MOUSE_UP = 0x03,
    INPUT_KEY_DOWN = 0x04,
    INPUT_KEY_UP = 0x05,
};

// Client connection state
struct ClientSession {
    struct lws* wsi;
    std::string id;
    double latency;
    int bandwidth;
    int quality_level;  // 0=low, 1=medium, 2=high
    bool ready;
    std::vector<uint8_t> send_buffer;
    std::mutex buffer_mutex;
};

// Callbacks for the emulator integration
struct WebSocketCallbacks {
    std::function<void(int x, int y)> on_mouse_move;
    std::function<void(int x, int y, int button, bool pressed)> on_mouse_button;
    std::function<void(int keycode, bool pressed, bool ctrl, bool alt, bool shift, bool meta)> on_key;
    std::function<std::string()> on_get_config;
    std::function<bool(const std::string&)> on_set_config;
    std::function<void()> on_restart;
};

class WebSocketServer {
public:
    // Static callback wrapper for libwebsockets (must be public for C callback)
    static int callback_wrapper(struct lws* wsi,
                               enum lws_callback_reasons reason,
                               void* user, void* in, size_t len);

private:
    struct lws_context* context;
    std::thread server_thread;
    std::atomic<bool> running;
    int port;

    std::vector<ClientSession*> clients;
    std::mutex clients_mutex;

    WebSocketCallbacks callbacks;

    // Frame data
    std::vector<uint8_t> current_frame;
    std::mutex frame_mutex;
    int frame_width;
    int frame_height;

    // Instance callback
    int handle_callback(struct lws* wsi,
                       enum lws_callback_reasons reason,
                       void* user, void* in, size_t len);

    // Client management
    ClientSession* add_client(struct lws* wsi);
    void remove_client(struct lws* wsi);
    ClientSession* find_client(struct lws* wsi);

    // Message handling
    void handle_message(ClientSession* client, const uint8_t* data, size_t len);
    void handle_input_message(ClientSession* client, const uint8_t* data, size_t len);
    void handle_config_message(ClientSession* client, const uint8_t* data, size_t len);

    // Generate unique client ID
    std::string generate_client_id();

public:
    WebSocketServer(int port = 8080);
    ~WebSocketServer();

    // Server lifecycle
    bool start();
    void stop();
    bool is_running() const { return running; }

    // Set callbacks for emulator integration
    void set_callbacks(const WebSocketCallbacks& cbs) { callbacks = cbs; }

    // Send frame to all clients
    void broadcast_frame(const uint8_t* rgba_data, int width, int height);

    // Send audio to all clients
    void broadcast_audio(const int16_t* samples, int count, int sample_rate);

    // Send status message to all clients
    void broadcast_status(const std::string& status);

    // Get client count
    size_t get_client_count();

    // Server statistics
    struct Stats {
        size_t clients_connected;
        uint64_t frames_sent;
        uint64_t bytes_sent;
        double avg_latency;
    };
    Stats get_stats();
};

// Global instance pointer for libwebsockets callback
extern WebSocketServer* g_ws_server;

#endif // WEBSOCKET_SERVER_H
