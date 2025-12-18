/*
 * WebSocket Server Implementation for Basilisk II Web Streaming
 */

#include "websocket_server.h"
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <chrono>

// Global instance for libwebsockets callback
WebSocketServer* g_ws_server = nullptr;

// Protocol definition
static struct lws_protocols protocols[] = {
    {
        "basilisk-protocol",
        WebSocketServer::callback_wrapper,
        sizeof(ClientSession*),
        65536,  // rx buffer size
        0,
        nullptr,
        0
    },
    { nullptr, nullptr, 0, 0, 0, nullptr, 0 }
};

// Static callback wrapper that forwards to instance method
int WebSocketServer::callback_wrapper(struct lws* wsi,
                                      enum lws_callback_reasons reason,
                                      void* user, void* in, size_t len) {
    if (g_ws_server) {
        return g_ws_server->handle_callback(wsi, reason, user, in, len);
    }
    return 0;
}

WebSocketServer::WebSocketServer(int port)
    : context(nullptr), running(false), port(port),
      frame_width(640), frame_height(480) {
    g_ws_server = this;
}

WebSocketServer::~WebSocketServer() {
    stop();
    g_ws_server = nullptr;
}

bool WebSocketServer::start() {
    if (running) return true;

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.port = port;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

    // Enable permessage-deflate for compression
    // info.extensions = lws_get_builtin_extensions();

    context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "WebSocket server: failed to create context\n");
        return false;
    }

    running = true;

    // Start server thread
    server_thread = std::thread([this]() {
        printf("WebSocket server started on port %d\n", port);

        while (running) {
            lws_service(context, 50);

            // Process pending writes for all clients
            {
                std::lock_guard<std::mutex> lock(clients_mutex);
                for (auto* client : clients) {
                    if (client->ready) {
                        std::lock_guard<std::mutex> buf_lock(client->buffer_mutex);
                        if (!client->send_buffer.empty()) {
                            lws_callback_on_writable(client->wsi);
                        }
                    }
                }
            }
        }

        printf("WebSocket server stopped\n");
    });

    return true;
}

void WebSocketServer::stop() {
    if (!running) return;

    running = false;

    if (server_thread.joinable()) {
        server_thread.join();
    }

    if (context) {
        lws_context_destroy(context);
        context = nullptr;
    }

    // Clean up clients
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto* client : clients) {
        delete client;
    }
    clients.clear();
}

int WebSocketServer::handle_callback(struct lws* wsi,
                                     enum lws_callback_reasons reason,
                                     void* user, void* in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            auto* client = add_client(wsi);
            printf("Client connected: %s (Total: %zu)\n",
                   client->id.c_str(), clients.size());

            // Send initial status
            std::string status = "{\"type\":\"connected\",\"id\":\"" +
                                client->id + "\"}";
            // Queue for sending
            {
                std::lock_guard<std::mutex> lock(client->buffer_mutex);
                client->send_buffer.insert(client->send_buffer.end(),
                                          status.begin(), status.end());
            }
            lws_callback_on_writable(wsi);
            break;
        }

        case LWS_CALLBACK_CLOSED: {
            auto* client = find_client(wsi);
            if (client) {
                printf("Client disconnected: %s\n", client->id.c_str());
                remove_client(wsi);
            }
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            auto* client = find_client(wsi);
            if (client && in && len > 0) {
                handle_message(client, static_cast<uint8_t*>(in), len);
            }
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            auto* client = find_client(wsi);
            if (client) {
                std::lock_guard<std::mutex> lock(client->buffer_mutex);
                if (!client->send_buffer.empty()) {
                    // Prepend LWS_PRE bytes
                    std::vector<uint8_t> buf(LWS_PRE + client->send_buffer.size());
                    memcpy(&buf[LWS_PRE], client->send_buffer.data(),
                           client->send_buffer.size());

                    // Determine write mode: TEXT for JSON (starts with '{'), BINARY otherwise
                    lws_write_protocol write_mode = LWS_WRITE_BINARY;
                    if (!client->send_buffer.empty() && client->send_buffer[0] == '{') {
                        write_mode = LWS_WRITE_TEXT;
                    }

                    int written = lws_write(wsi, &buf[LWS_PRE],
                                           client->send_buffer.size(),
                                           write_mode);

                    if (written > 0) {
                        client->send_buffer.clear();
                    }
                }
            }
            break;
        }

        case LWS_CALLBACK_PROTOCOL_INIT:
            printf("WebSocket protocol initialized\n");
            break;

        default:
            break;
    }

    return 0;
}

ClientSession* WebSocketServer::add_client(struct lws* wsi) {
    std::lock_guard<std::mutex> lock(clients_mutex);

    auto* client = new ClientSession();
    client->wsi = wsi;
    client->id = generate_client_id();
    client->latency = 0;
    client->bandwidth = 0;
    client->quality_level = 2;  // Start at high quality
    client->ready = true;

    clients.push_back(client);
    return client;
}

void WebSocketServer::remove_client(struct lws* wsi) {
    std::lock_guard<std::mutex> lock(clients_mutex);

    clients.erase(
        std::remove_if(clients.begin(), clients.end(),
            [wsi](ClientSession* c) {
                if (c->wsi == wsi) {
                    delete c;
                    return true;
                }
                return false;
            }),
        clients.end()
    );
}

ClientSession* WebSocketServer::find_client(struct lws* wsi) {
    std::lock_guard<std::mutex> lock(clients_mutex);

    for (auto* client : clients) {
        if (client->wsi == wsi) {
            return client;
        }
    }
    return nullptr;
}

std::string WebSocketServer::generate_client_id() {
    static int counter = 0;
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    char buf[32];
    snprintf(buf, sizeof(buf), "client_%lld_%d",
             static_cast<long long>(timestamp), ++counter);
    return buf;
}

void WebSocketServer::handle_message(ClientSession* client,
                                     const uint8_t* data, size_t len) {
    if (len < 1) return;

    uint8_t msg_type = data[0];

    switch (msg_type) {
        case MSG_INPUT:
            handle_input_message(client, data + 1, len - 1);
            break;

        case MSG_CONFIG:
            handle_config_message(client, data + 1, len - 1);
            break;

        case MSG_STATUS:
            // Client sending latency info, etc.
            if (len >= 5) {
                uint32_t latency_ms = *(uint32_t*)(data + 1);
                client->latency = latency_ms;

                // Adjust quality based on latency
                if (latency_ms > 100) {
                    client->quality_level = 0;
                } else if (latency_ms > 50) {
                    client->quality_level = 1;
                } else {
                    client->quality_level = 2;
                }
            }
            break;

        default:
            fprintf(stderr, "Unknown message type: %d\n", msg_type);
            break;
    }
}

void WebSocketServer::handle_input_message(ClientSession* client,
                                           const uint8_t* data, size_t len) {
    if (len < 1) return;

    uint8_t input_type = data[0];
    static int input_log_count = 0;

    switch (input_type) {
        case INPUT_MOUSE_MOVE:
            if (len >= 5 && callbacks.on_mouse_move) {
                int16_t x = *(int16_t*)(data + 1);
                int16_t y = *(int16_t*)(data + 3);
                if (input_log_count++ % 100 == 0) {
                    printf("WS: Mouse move received #%d: %d,%d\n", input_log_count, x, y);
                    fflush(stdout);
                }
                callbacks.on_mouse_move(x, y);
            }
            break;

        case INPUT_MOUSE_DOWN:
        case INPUT_MOUSE_UP:
            if (len >= 6 && callbacks.on_mouse_button) {
                int16_t x = *(int16_t*)(data + 1);
                int16_t y = *(int16_t*)(data + 3);
                uint8_t button = data[5];
                bool pressed = (input_type == INPUT_MOUSE_DOWN);
                printf("WS: Mouse %s received: %d,%d btn=%d\n",
                       pressed ? "DOWN" : "UP", x, y, button);
                fflush(stdout);
                callbacks.on_mouse_button(x, y, button, pressed);
            }
            break;

        case INPUT_KEY_DOWN:
        case INPUT_KEY_UP:
            if (len >= 3 && callbacks.on_key) {
                uint16_t keycode = *(uint16_t*)(data + 1);
                uint8_t modifiers = (len >= 4) ? data[3] : 0;
                bool pressed = (input_type == INPUT_KEY_DOWN);
                bool ctrl = (modifiers & 0x01) != 0;
                bool alt = (modifiers & 0x02) != 0;
                bool shift = (modifiers & 0x04) != 0;
                bool meta = (modifiers & 0x08) != 0;
                callbacks.on_key(keycode, pressed, ctrl, alt, shift, meta);
            }
            break;
    }
}

void WebSocketServer::handle_config_message(ClientSession* client,
                                            const uint8_t* data, size_t len) {
    // Config messages are JSON strings
    std::string json(reinterpret_cast<const char*>(data), len);

    // Simple command parsing - look for "cmd" field
    if (json.find("\"cmd\":\"get_config\"") != std::string::npos) {
        if (callbacks.on_get_config) {
            std::string config = callbacks.on_get_config();

            // Send config response
            std::vector<uint8_t> response;
            response.push_back(MSG_CONFIG);
            response.insert(response.end(), config.begin(), config.end());

            std::lock_guard<std::mutex> lock(client->buffer_mutex);
            client->send_buffer = std::move(response);
            lws_callback_on_writable(client->wsi);
        }
    }
    else if (json.find("\"cmd\":\"set_config\"") != std::string::npos) {
        if (callbacks.on_set_config) {
            bool success = callbacks.on_set_config(json);
            std::string response = success ?
                "{\"status\":\"ok\"}" : "{\"status\":\"error\"}";

            std::vector<uint8_t> buf;
            buf.push_back(MSG_CONFIG);
            buf.insert(buf.end(), response.begin(), response.end());

            std::lock_guard<std::mutex> lock(client->buffer_mutex);
            client->send_buffer = std::move(buf);
            lws_callback_on_writable(client->wsi);
        }
    }
    else if (json.find("\"cmd\":\"restart\"") != std::string::npos) {
        if (callbacks.on_restart) {
            callbacks.on_restart();

            std::string response = "{\"status\":\"restarting\"}";
            std::vector<uint8_t> buf;
            buf.push_back(MSG_CONFIG);
            buf.insert(buf.end(), response.begin(), response.end());

            std::lock_guard<std::mutex> lock(client->buffer_mutex);
            client->send_buffer = std::move(buf);
            lws_callback_on_writable(client->wsi);
        }
    }
}

void WebSocketServer::broadcast_frame(const uint8_t* rgba_data,
                                      int width, int height) {
    if (!running || clients.empty()) return;

    // Build frame packet
    // Format: MSG_FRAME(1) + width(4) + height(4) + pixel_data(w*h*4)
    size_t pixel_size = width * height * 4;
    std::vector<uint8_t> packet(1 + 4 + 4 + pixel_size);

    packet[0] = MSG_FRAME;
    *(uint32_t*)&packet[1] = width;
    *(uint32_t*)&packet[5] = height;
    memcpy(&packet[9], rgba_data, pixel_size);

    // Send to all clients
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto* client : clients) {
        if (client->ready) {
            std::lock_guard<std::mutex> buf_lock(client->buffer_mutex);
            client->send_buffer = packet;  // Copy for each client
            lws_callback_on_writable(client->wsi);
        }
    }

    // Update stored frame
    {
        std::lock_guard<std::mutex> lock(frame_mutex);
        current_frame = packet;
        frame_width = width;
        frame_height = height;
    }
}

void WebSocketServer::broadcast_audio(const int16_t* samples, int count,
                                      int sample_rate) {
    if (!running || clients.empty()) return;

    // Build audio packet
    // Format: MSG_AUDIO(1) + sample_rate(4) + count(4) + samples(count*2)
    std::vector<uint8_t> packet(1 + 4 + 4 + count * 2);

    packet[0] = MSG_AUDIO;
    *(uint32_t*)&packet[1] = sample_rate;
    *(uint32_t*)&packet[5] = count;
    memcpy(&packet[9], samples, count * 2);

    // Send to all clients
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto* client : clients) {
        if (client->ready) {
            std::lock_guard<std::mutex> buf_lock(client->buffer_mutex);
            // Append audio to send buffer (don't overwrite pending video)
            client->send_buffer.insert(client->send_buffer.end(),
                                      packet.begin(), packet.end());
            lws_callback_on_writable(client->wsi);
        }
    }
}

void WebSocketServer::broadcast_status(const std::string& status) {
    if (!running) return;

    std::vector<uint8_t> packet;
    packet.push_back(MSG_STATUS);
    packet.insert(packet.end(), status.begin(), status.end());

    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto* client : clients) {
        if (client->ready) {
            std::lock_guard<std::mutex> buf_lock(client->buffer_mutex);
            client->send_buffer = packet;
            lws_callback_on_writable(client->wsi);
        }
    }
}

size_t WebSocketServer::get_client_count() {
    std::lock_guard<std::mutex> lock(clients_mutex);
    return clients.size();
}

WebSocketServer::Stats WebSocketServer::get_stats() {
    Stats stats = {};
    std::lock_guard<std::mutex> lock(clients_mutex);

    stats.clients_connected = clients.size();

    double total_latency = 0;
    for (auto* client : clients) {
        total_latency += client->latency;
    }
    if (!clients.empty()) {
        stats.avg_latency = total_latency / clients.size();
    }

    return stats;
}
