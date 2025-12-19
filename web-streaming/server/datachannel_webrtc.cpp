/*
 * libdatachannel WebRTC Integration for Basilisk II
 *
 * Uses libdatachannel for WebRTC and libvpx for VP8 encoding.
 * Includes embedded HTTP server for serving client files.
 * Much lighter weight than GStreamer approach.
 */

#include "datachannel_webrtc.h"

#include <rtc/rtc.hpp>

#include <vpx/vpx_encoder.h>
#include <vpx/vp8cx.h>

#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <vector>
#include <thread>
#include <queue>
#include <condition_variable>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <chrono>
#include <functional>
#include <sstream>
#include <fstream>

// For HTTP server
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

// Simple JSON helpers
static std::string json_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

static std::string json_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char next = s[i + 1];
            if (next == 'n') { out += '\n'; i++; }
            else if (next == 'r') { out += '\r'; i++; }
            else if (next == 't') { out += '\t'; i++; }
            else if (next == '"') { out += '"'; i++; }
            else if (next == '\\') { out += '\\'; i++; }
            else out += s[i];
        } else {
            out += s[i];
        }
    }
    return out;
}

static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos);
    if (pos == std::string::npos) return "";

    pos = json.find('"', pos);
    if (pos == std::string::npos) return "";
    pos++;

    size_t end = pos;
    while (end < json.size() && json[end] != '"') {
        if (json[end] == '\\' && end + 1 < json.size()) end++;
        end++;
    }

    // Unescape the JSON string before returning
    return json_unescape(json.substr(pos, end - pos));
}

static int json_get_int(const std::string& json, const std::string& key, int def = 0) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return def;

    pos = json.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    return std::atoi(json.c_str() + pos);
}

static bool json_get_bool(const std::string& json, const std::string& key, bool def = false) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return def;

    pos = json.find(':', pos);
    if (pos == std::string::npos) return def;
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (json.substr(pos, 4) == "true") return true;
    if (json.substr(pos, 5) == "false") return false;
    return def;
}

// Embedded client files (generated - see end of file for content)
extern const char* embedded_html;
extern const char* embedded_js;

// Simple HTTP server for serving client files
class SimpleHTTPServer {
public:
    bool start(int port) {
        port_ = port;

        server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            fprintf(stderr, "HTTP: Failed to create socket\n");
            return false;
        }

        int opt = 1;
        setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // Set non-blocking
        int flags = fcntl(server_fd_, F_GETFL, 0);
        fcntl(server_fd_, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            fprintf(stderr, "HTTP: Failed to bind port %d\n", port);
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        if (listen(server_fd_, 10) < 0) {
            fprintf(stderr, "HTTP: Failed to listen\n");
            close(server_fd_);
            server_fd_ = -1;
            return false;
        }

        running_ = true;
        thread_ = std::thread(&SimpleHTTPServer::run, this);

        fprintf(stderr, "HTTP: Server on port %d\n", port);
        return true;
    }

    void stop() {
        running_ = false;
        if (server_fd_ >= 0) {
            close(server_fd_);
            server_fd_ = -1;
        }
        if (thread_.joinable()) {
            thread_.join();
        }
    }

private:
    void run() {
        while (running_) {
            struct pollfd pfd;
            pfd.fd = server_fd_;
            pfd.events = POLLIN;

            int ret = poll(&pfd, 1, 100);  // 100ms timeout
            if (ret <= 0) continue;

            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) continue;

            handle_client(client_fd);
            close(client_fd);
        }
    }

    void handle_client(int fd) {
        char buffer[4096];
        ssize_t n = recv(fd, buffer, sizeof(buffer) - 1, 0);
        if (n <= 0) return;
        buffer[n] = '\0';

        // Parse HTTP request (very basic)
        std::string request(buffer);
        std::string path = "/";

        if (request.substr(0, 4) == "GET ") {
            size_t end = request.find(' ', 4);
            if (end != std::string::npos) {
                path = request.substr(4, end - 4);
            }
        }

        std::string content_type = "text/html";
        const char* content = nullptr;

        if (path == "/" || path == "/index.html" || path == "/index_datachannel.html") {
            content = embedded_html;
            content_type = "text/html";
        } else if (path == "/datachannel_client.js") {
            content = embedded_js;
            content_type = "application/javascript";
        }

        if (content) {
            std::string response = "HTTP/1.1 200 OK\r\n";
            response += "Content-Type: " + content_type + "\r\n";
            response += "Content-Length: " + std::to_string(strlen(content)) + "\r\n";
            response += "Connection: close\r\n";
            response += "\r\n";
            response += content;
            send(fd, response.c_str(), response.size(), 0);
        } else {
            std::string response = "HTTP/1.1 404 Not Found\r\n";
            response += "Content-Type: text/plain\r\n";
            response += "Content-Length: 9\r\n";
            response += "Connection: close\r\n";
            response += "\r\n";
            response += "Not Found";
            send(fd, response.c_str(), response.size(), 0);
        }
    }

    int port_ = 8000;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

// VP8 Encoder wrapper
class VP8Encoder {
public:
    VP8Encoder() = default;
    ~VP8Encoder() { cleanup(); }

    bool init(int width, int height, int fps = 30, int bitrate_kbps = 2000) {
        cleanup();

        vpx_codec_enc_cfg_t cfg;
        if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &cfg, 0) != VPX_CODEC_OK) {
            fprintf(stderr, "VP8: Failed to get default config\n");
            return false;
        }

        cfg.g_w = width;
        cfg.g_h = height;
        cfg.g_timebase.num = 1;
        cfg.g_timebase.den = fps;
        cfg.rc_target_bitrate = bitrate_kbps;
        cfg.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
        cfg.g_lag_in_frames = 0;  // Realtime
        cfg.rc_end_usage = VPX_CBR;
        cfg.kf_mode = VPX_KF_AUTO;
        cfg.kf_max_dist = 15;  // Keyframe every 15 frames (~2 per second)
        cfg.g_threads = 1;  // Single thread for deterministic output

        codec_ = new vpx_codec_ctx_t;
        if (vpx_codec_enc_init(codec_, vpx_codec_vp8_cx(), &cfg, 0) != VPX_CODEC_OK) {
            fprintf(stderr, "VP8: Failed to init encoder: %s\n", vpx_codec_error(codec_));
            delete codec_;
            codec_ = nullptr;
            return false;
        }

        // Realtime settings
        vpx_codec_control(codec_, VP8E_SET_CPUUSED, 8);  // Fastest
        vpx_codec_control(codec_, VP8E_SET_NOISE_SENSITIVITY, 0);
        vpx_codec_control(codec_, VP8E_SET_TOKEN_PARTITIONS, 0);  // Single partition for simpler RTP

        width_ = width;
        height_ = height;
        fps_ = fps;
        frame_count_ = 0;

        // Allocate image
        if (!vpx_img_alloc(&img_, VPX_IMG_FMT_I420, width, height, 16)) {
            fprintf(stderr, "VP8: Failed to allocate image\n");
            cleanup();
            return false;
        }

        fprintf(stderr, "VP8: Encoder initialized %dx%d @ %d kbps\n", width, height, bitrate_kbps);
        return true;
    }

    void cleanup() {
        if (codec_) {
            vpx_codec_destroy(codec_);
            delete codec_;
            codec_ = nullptr;
        }
        if (img_.planes[0]) {
            vpx_img_free(&img_);
            memset(&img_, 0, sizeof(img_));
        }
    }

    // Encode RGBA frame to VP8
    // Returns encoded data (may be empty if encoder is buffering)
    std::vector<uint8_t> encode(const uint8_t* rgba, int width, int height, int stride) {
        std::vector<uint8_t> result;

        if (!codec_ || width != width_ || height != height_) {
            if (!init(width, height)) {
                return result;
            }
        }

        // Convert RGBA to I420
        rgba_to_i420(rgba, stride);

        // Encode
        vpx_codec_pts_t pts = frame_count_++;
        int flags = 0;  // Could force keyframe with VPX_EFLAG_FORCE_KF

        if (vpx_codec_encode(codec_, &img_, pts, 1, flags, VPX_DL_REALTIME) != VPX_CODEC_OK) {
            fprintf(stderr, "VP8: Encode failed: %s\n", vpx_codec_error(codec_));
            return result;
        }

        // Get encoded data
        vpx_codec_iter_t iter = nullptr;
        const vpx_codec_cx_pkt_t* pkt;
        while ((pkt = vpx_codec_get_cx_data(codec_, &iter)) != nullptr) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                const uint8_t* data = static_cast<const uint8_t*>(pkt->data.frame.buf);
                result.insert(result.end(), data, data + pkt->data.frame.sz);
            }
        }

        return result;
    }

    bool is_keyframe(const std::vector<uint8_t>& data) {
        // VP8 keyframe detection: first byte bit 0 is 0 for keyframe
        if (data.empty()) return false;
        return (data[0] & 0x01) == 0;
    }

private:
    void rgba_to_i420(const uint8_t* rgba, int stride) {
        // Simple RGBA to I420 conversion
        uint8_t* y = img_.planes[VPX_PLANE_Y];
        uint8_t* u = img_.planes[VPX_PLANE_U];
        uint8_t* v = img_.planes[VPX_PLANE_V];

        int y_stride = img_.stride[VPX_PLANE_Y];
        int u_stride = img_.stride[VPX_PLANE_U];
        int v_stride = img_.stride[VPX_PLANE_V];

        for (int row = 0; row < height_; row++) {
            const uint8_t* src = rgba + row * stride;
            uint8_t* dst_y = y + row * y_stride;

            for (int col = 0; col < width_; col++) {
                int r = src[0];
                int g = src[1];
                int b = src[2];

                // Y = 0.299*R + 0.587*G + 0.114*B
                dst_y[col] = static_cast<uint8_t>((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;

                src += 4;
            }
        }

        // Subsample for U and V
        for (int row = 0; row < height_ / 2; row++) {
            uint8_t* dst_u = u + row * u_stride;
            uint8_t* dst_v = v + row * v_stride;

            for (int col = 0; col < width_ / 2; col++) {
                // Average 2x2 block
                int r = 0, g = 0, b = 0;
                for (int dy = 0; dy < 2; dy++) {
                    const uint8_t* src = rgba + (row * 2 + dy) * stride + col * 2 * 4;
                    for (int dx = 0; dx < 2; dx++) {
                        r += src[0];
                        g += src[1];
                        b += src[2];
                        src += 4;
                    }
                }
                r /= 4;
                g /= 4;
                b /= 4;

                // U = -0.169*R - 0.331*G + 0.500*B + 128
                dst_u[col] = static_cast<uint8_t>((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                // V = 0.500*R - 0.419*G - 0.081*B + 128
                dst_v[col] = static_cast<uint8_t>((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
            }
        }
    }

    vpx_codec_ctx_t* codec_ = nullptr;
    vpx_image_t img_ = {};
    int width_ = 0;
    int height_ = 0;
    int fps_ = 30;
    int64_t frame_count_ = 0;
};

// Peer connection wrapper
struct PeerConnection {
    std::shared_ptr<rtc::PeerConnection> pc;
    std::shared_ptr<rtc::Track> video_track;
    std::shared_ptr<rtc::DataChannel> data_channel;
    std::string id;
    bool ready = false;
    std::vector<std::pair<std::string, std::string>> pending_candidates;  // candidate, mid
};

// Main WebRTC manager
class DataChannelWebRTC {
public:
    bool init(int port);
    void shutdown();
    void push_frame(const uint8_t* rgba, int w, int h, int stride);
    int peer_count() { return peer_count_.load(); }
    bool is_enabled() { return initialized_.load(); }

    void set_callbacks(dc_mouse_move_cb mm, dc_mouse_button_cb mb, dc_key_cb k) {
        on_mouse_move_ = mm;
        on_mouse_button_ = mb;
        on_key_ = k;
    }

private:
    void signaling_thread();
    void process_signaling_message(std::shared_ptr<rtc::WebSocket> ws, const std::string& msg);
    void handle_input_message(const std::string& msg);
    std::string create_peer(const std::string& peer_id);
    void send_to_all_peers(const std::vector<uint8_t>& data, bool is_keyframe);

    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    std::atomic<int> peer_count_{0};

    int port_ = 8090;
    std::unique_ptr<rtc::WebSocketServer> ws_server_;
    std::thread signaling_thread_;

    // HTTP server for client files
    SimpleHTTPServer http_server_;

    std::mutex peers_mutex_;
    std::map<std::string, std::shared_ptr<PeerConnection>> peers_;
    std::map<rtc::WebSocket*, std::string> ws_to_peer_id_;

    VP8Encoder encoder_;
    std::mutex encoder_mutex_;

    dc_mouse_move_cb on_mouse_move_ = nullptr;
    dc_mouse_button_cb on_mouse_button_ = nullptr;
    dc_key_cb on_key_ = nullptr;

    uint32_t ssrc_ = 1;
    uint16_t seq_num_ = 0;
    uint32_t timestamp_ = 0;
};

static DataChannelWebRTC* g_webrtc = nullptr;

bool DataChannelWebRTC::init(int port) {
    port_ = port;

    rtc::InitLogger(rtc::LogLevel::Error);

    // Preload libdatachannel to ensure proper initialization of all subsystems
    rtc::Preload();

    try {
        rtc::WebSocketServer::Configuration config;
        config.port = port;

        // Check for TLS certificate files for WSS support
        // If cert/key files exist, enable TLS for HTTPS compatibility
        const char* cert_file = getenv("BASILISK_WSS_CERT");
        const char* key_file = getenv("BASILISK_WSS_KEY");

        if (cert_file && key_file) {
            // Read certificate and key from files
            std::ifstream cert_stream(cert_file);
            std::ifstream key_stream(key_file);
            if (cert_stream.good() && key_stream.good()) {
                std::stringstream cert_buf, key_buf;
                cert_buf << cert_stream.rdbuf();
                key_buf << key_stream.rdbuf();
                config.certificatePemFile = cert_file;
                config.keyPemFile = key_file;
                config.enableTls = true;
                fprintf(stderr, "WebRTC: TLS enabled (WSS) using cert: %s\n", cert_file);
            } else {
                fprintf(stderr, "WebRTC: TLS cert/key files not readable, using plain WS\n");
                config.enableTls = false;
            }
        } else {
            config.enableTls = false;
        }

        ws_server_ = std::make_unique<rtc::WebSocketServer>(config);

        ws_server_->onClient([this](std::shared_ptr<rtc::WebSocket> ws) {
            ws->onOpen([this, ws]() {
                // Send welcome message
                std::string welcome = "{\"type\":\"welcome\",\"peerId\":\"server\"}";
                ws->send(welcome);
            });

            ws->onMessage([this, ws](auto data) {
                if (std::holds_alternative<std::string>(data)) {
                    process_signaling_message(ws, std::get<std::string>(data));
                }
            });

            ws->onClosed([this, ws]() {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                auto it = ws_to_peer_id_.find(ws.get());
                if (it != ws_to_peer_id_.end()) {
                    peers_.erase(it->second);
                    ws_to_peer_id_.erase(it);
                    peer_count_--;
                }
            });
        });

        initialized_ = true;
        running_ = true;

        fprintf(stderr, "WebRTC: Signaling server on port %d\n", port);

        // Start HTTP server for client files on port 8000
        // (WebSocket signaling runs on 'port', HTTP on 8000)
        http_server_.start(8000);
        fprintf(stderr, "WebRTC: Open http://localhost:8000 in your browser\n");

    } catch (const std::exception& e) {
        fprintf(stderr, "WebRTC: Failed to start server: %s\n", e.what());
        return false;
    }

    return true;
}

void DataChannelWebRTC::process_signaling_message(std::shared_ptr<rtc::WebSocket> ws,
                                                    const std::string& msg) {
    std::string type = json_get_string(msg, "type");

    if (type == "connect") {
        // Client wants to connect, create peer connection
        std::string peer_id = "peer_" + std::to_string(rand());

        auto peer = std::make_shared<PeerConnection>();
        peer->id = peer_id;

        rtc::Configuration config;
        config.iceServers.emplace_back("stun:stun.l.google.com:19302");
        // Note: Don't use disableAutoNegotiation - follow streamer example pattern

        peer->pc = std::make_shared<rtc::PeerConnection>(config);

        // Add peer to maps FIRST, before setting up callbacks
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            ws_to_peer_id_[ws.get()] = peer_id;
            peers_[peer_id] = peer;
            peer_count_++;
        }

        peer->pc->onStateChange([peer_id](rtc::PeerConnection::State state) {
            // Only log significant state changes
            if (state == rtc::PeerConnection::State::Connected) {
                fprintf(stderr, "WebRTC: Peer %s connected\n", peer_id.c_str());
            } else if (state == rtc::PeerConnection::State::Failed) {
                fprintf(stderr, "WebRTC: Peer %s failed\n", peer_id.c_str());
            }
        });

        // Wait for ICE gathering to complete before sending offer
        std::weak_ptr<rtc::PeerConnection> wpc = peer->pc;
        peer->pc->onGatheringStateChange([ws, peer_id, wpc](rtc::PeerConnection::GatheringState state) {
            if (state == rtc::PeerConnection::GatheringState::Complete) {
                if (auto pc = wpc.lock()) {
                    auto description = pc->localDescription();
                    if (description) {
                        std::string sdp = std::string(description.value());
                        std::string type_str = description->typeString();
                        std::string response = "{\"type\":\"" + type_str + "\",\"sdp\":\"" + json_escape(sdp) + "\"}";
                        ws->send(response);
                    }
                }
            }
        });

        // Add video track with SSRC
        rtc::Description::Video media("video-stream", rtc::Description::Direction::SendOnly);
        media.addVP8Codec(96);
        media.addSSRC(ssrc_, "video-stream", "stream1", "video-stream");
        peer->video_track = peer->pc->addTrack(media);

        // Set up track open callback (no logging needed)
        peer->video_track->onOpen([]() {});

        // Create data channel for input
        peer->data_channel = peer->pc->createDataChannel("input");
        peer->data_channel->onOpen([]() {});
        peer->data_channel->onClosed([]() {});
        peer->data_channel->onMessage([this](auto data) {
            if (std::holds_alternative<std::string>(data)) {
                handle_input_message(std::get<std::string>(data));
            }
        });

        fprintf(stderr, "WebRTC: New peer %s\n", peer_id.c_str());

        // Generate offer - gathering will start, and onGatheringStateChange will send it when complete
        peer->pc->setLocalDescription();

    } else if (type == "answer") {
        std::string sdp = json_get_string(msg, "sdp");

        std::shared_ptr<PeerConnection> peer;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = ws_to_peer_id_.find(ws.get());
            if (it != ws_to_peer_id_.end()) {
                auto peer_it = peers_.find(it->second);
                if (peer_it != peers_.end()) {
                    peer = peer_it->second;
                }
            }
        }

        if (peer) {
            try {
                rtc::Description answer(sdp, rtc::Description::Type::Answer);
                peer->pc->setRemoteDescription(answer);
                peer->ready = true;

                // Process any pending ICE candidates
                for (const auto& [cand_str, mid] : peer->pending_candidates) {
                    try {
                        rtc::Candidate cand(cand_str, mid);
                        peer->pc->addRemoteCandidate(cand);
                    } catch (...) {}
                }
                peer->pending_candidates.clear();
            } catch (...) {}
        }

    } else if (type == "candidate") {
        std::string candidate = json_get_string(msg, "candidate");
        std::string mid = json_get_string(msg, "mid");

        std::shared_ptr<PeerConnection> peer;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            auto it = ws_to_peer_id_.find(ws.get());
            if (it != ws_to_peer_id_.end()) {
                auto peer_it = peers_.find(it->second);
                if (peer_it != peers_.end()) {
                    peer = peer_it->second;
                }
            }
        }

        if (peer) {
            if (peer->ready) {
                try {
                    rtc::Candidate cand(candidate, mid);
                    peer->pc->addRemoteCandidate(cand);
                } catch (...) {}
            } else {
                peer->pending_candidates.emplace_back(candidate, mid);
            }
        }
    }
}

void DataChannelWebRTC::handle_input_message(const std::string& msg) {
    std::string type = json_get_string(msg, "type");

    if (type == "mouse_move") {
        int x = json_get_int(msg, "x");
        int y = json_get_int(msg, "y");
        if (on_mouse_move_) {
            on_mouse_move_(x, y);
        }
    } else if (type == "mouse_down" || type == "mouse_up") {
        int x = json_get_int(msg, "x");
        int y = json_get_int(msg, "y");
        int button = json_get_int(msg, "button");
        bool pressed = (type == "mouse_down");
        if (on_mouse_button_) {
            on_mouse_button_(x, y, button, pressed);
        }
    } else if (type == "key_down" || type == "key_up") {
        int keycode = json_get_int(msg, "keyCode");
        bool pressed = (type == "key_down");
        bool ctrl = json_get_bool(msg, "ctrl");
        bool alt = json_get_bool(msg, "alt");
        bool shift = json_get_bool(msg, "shift");
        bool meta = json_get_bool(msg, "meta");
        if (on_key_) {
            on_key_(keycode, pressed, ctrl, alt, shift, meta);
        }
    }
}

void DataChannelWebRTC::push_frame(const uint8_t* rgba, int w, int h, int stride) {
    if (!initialized_.load()) return;
    if (peer_count_.load() == 0) return;  // Don't encode if no one watching

    std::lock_guard<std::mutex> lock(encoder_mutex_);

    auto start = std::chrono::steady_clock::now();

    // Encode frame
    std::vector<uint8_t> encoded = encoder_.encode(rgba, w, h, stride);
    if (encoded.empty()) return;

    auto end = std::chrono::steady_clock::now();
    auto encode_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    bool is_keyframe = encoder_.is_keyframe(encoded);

    // Stats
    static int frame_count = 0;
    static int keyframe_count = 0;
    static long total_encode_ms = 0;
    static size_t total_bytes = 0;
    static auto last_stats = std::chrono::steady_clock::now();

    frame_count++;
    if (is_keyframe) keyframe_count++;
    total_encode_ms += encode_ms;
    total_bytes += encoded.size();

    auto stats_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - last_stats).count();
    if (stats_elapsed >= 10000) {  // Log every 10 seconds
        float fps = frame_count * 1000.0f / stats_elapsed;
        float avg_encode = frame_count > 0 ? (float)total_encode_ms / frame_count : 0;
        float kbps = total_bytes * 8.0f / stats_elapsed;
        fprintf(stderr, "[VP8] fps=%.1f kf=%d enc=%.1fms kbps=%.0f\n",
                fps, keyframe_count, avg_encode, kbps);
        frame_count = 0;
        keyframe_count = 0;
        total_encode_ms = 0;
        total_bytes = 0;
        last_stats = end;
    }

    // Send to all peers
    send_to_all_peers(encoded, is_keyframe);
}

void DataChannelWebRTC::send_to_all_peers(const std::vector<uint8_t>& data, bool is_keyframe) {
    std::lock_guard<std::mutex> lock(peers_mutex_);

    // Create RTP packet with VP8 payload descriptor per RFC 7741
    // RTP header (12 bytes) + VP8 payload descriptor (variable, we use 4 bytes with PictureID)
    const int RTP_HEADER_SIZE = 12;
    const int MAX_PAYLOAD = 1200;  // Safe MTU

    timestamp_ += 3000;  // 90kHz clock, ~30fps
    static uint16_t picture_id = 0;
    picture_id = (picture_id + 1) & 0x7FFF;  // 15-bit picture ID

    size_t offset = 0;
    bool first = true;

    while (offset < data.size()) {
        // VP8 payload descriptor: 4 bytes with extended picture ID
        // Byte 0: X=1, R=0, N=0, S=start, PartID=0
        // Byte 1 (X ext): I=1, L=0, T=0, K=0
        // Byte 2-3: M=1 + 15-bit PictureID
        const int VP8_DESC_SIZE = 4;

        size_t chunk_size = std::min(data.size() - offset, (size_t)(MAX_PAYLOAD - VP8_DESC_SIZE));
        bool last = (offset + chunk_size >= data.size());

        std::vector<uint8_t> packet(RTP_HEADER_SIZE + VP8_DESC_SIZE + chunk_size);

        // RTP header
        packet[0] = 0x80;  // Version 2
        packet[1] = 96 | (last ? 0x80 : 0);  // Payload type 96, marker if last
        packet[2] = (seq_num_ >> 8) & 0xFF;
        packet[3] = seq_num_ & 0xFF;
        packet[4] = (timestamp_ >> 24) & 0xFF;
        packet[5] = (timestamp_ >> 16) & 0xFF;
        packet[6] = (timestamp_ >> 8) & 0xFF;
        packet[7] = timestamp_ & 0xFF;
        packet[8] = (ssrc_ >> 24) & 0xFF;
        packet[9] = (ssrc_ >> 16) & 0xFF;
        packet[10] = (ssrc_ >> 8) & 0xFF;
        packet[11] = ssrc_ & 0xFF;

        // VP8 payload descriptor (RFC 7741)
        // Byte 0: |X|R|N|S|R| PID | - X=1 (extension present), S=1 for first packet
        packet[12] = 0x80 | (first ? 0x10 : 0x00);  // X=1, S=start
        // Byte 1: |I|L|T|K| RSV   | - I=1 (PictureID present)
        packet[13] = 0x80;  // I=1
        // Bytes 2-3: |M| PictureID | - M=1 for 15-bit PictureID
        packet[14] = 0x80 | ((picture_id >> 8) & 0x7F);  // M=1 + high 7 bits
        packet[15] = picture_id & 0xFF;  // low 8 bits

        // Payload
        memcpy(&packet[RTP_HEADER_SIZE + VP8_DESC_SIZE], &data[offset], chunk_size);

        // Send to all ready peers
        for (auto& [id, peer] : peers_) {
            if (peer->ready && peer->video_track && peer->video_track->isOpen()) {
                try {
                    peer->video_track->send(reinterpret_cast<const std::byte*>(packet.data()),
                                            packet.size());
                } catch (const std::exception& e) {
                    // Silently ignore send errors (peer may have disconnected)
                }
            }
        }

        seq_num_++;
        offset += chunk_size;
        first = false;
    }
}

void DataChannelWebRTC::shutdown() {
    running_ = false;
    initialized_ = false;

    // Stop HTTP server
    http_server_.stop();

    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto& [id, peer] : peers_) {
            if (peer->pc) {
                peer->pc->close();
            }
        }
        peers_.clear();
        ws_to_peer_id_.clear();
    }

    ws_server_.reset();
    encoder_.cleanup();
    peer_count_ = 0;

    fprintf(stderr, "WebRTC: Shutdown complete\n");
}

// C API implementation

bool dc_webrtc_init(int signaling_port) {
    if (g_webrtc) {
        fprintf(stderr, "WebRTC: Already initialized\n");
        return true;
    }

    g_webrtc = new DataChannelWebRTC();
    if (!g_webrtc->init(signaling_port)) {
        delete g_webrtc;
        g_webrtc = nullptr;
        return false;
    }

    return true;
}

void dc_webrtc_exit() {
    if (g_webrtc) {
        g_webrtc->shutdown();
        delete g_webrtc;
        g_webrtc = nullptr;
    }
}

void dc_webrtc_push_frame(const uint8_t* rgba_data, int width, int height, int stride) {
    if (g_webrtc) {
        g_webrtc->push_frame(rgba_data, width, height, stride);
    }
}

int dc_webrtc_peer_count() {
    return g_webrtc ? g_webrtc->peer_count() : 0;
}

bool dc_webrtc_enabled() {
    return g_webrtc ? g_webrtc->is_enabled() : false;
}

void dc_webrtc_set_input_callbacks(
    dc_mouse_move_cb on_mouse_move,
    dc_mouse_button_cb on_mouse_button,
    dc_key_cb on_key
) {
    if (g_webrtc) {
        g_webrtc->set_callbacks(on_mouse_move, on_mouse_button, on_key);
    }
}

// ============================================================================
// Embedded client files
// ============================================================================

const char* embedded_html = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Basilisk II - WebRTC Streaming</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #1a1a1a;
            color: #fff;
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        h1 {
            font-size: 1.2em;
            margin-bottom: 10px;
            color: #888;
        }
        #container {
            background: #000;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5);
        }
        #screen {
            display: block;
            max-width: 100%;
            max-height: 80vh;
            cursor: none;
        }
        #status {
            margin-top: 15px;
            padding: 8px 16px;
            background: #333;
            border-radius: 20px;
            font-size: 0.85em;
            color: #aaa;
        }
        #status.connected { background: #234; color: #4a9; }
        .info {
            margin-top: 20px;
            font-size: 0.75em;
            color: #555;
        }
    </style>
</head>
<body>
    <h1>Basilisk II Web Streaming</h1>
    <div id="container">
        <video id="screen" autoplay playsinline muted></video>
    </div>
    <div id="status">Initializing...</div>
    <div class="info">Click video to capture input | WebRTC streaming</div>
    <script src="datachannel_client.js"></script>
</body>
</html>
)HTML";

const char* embedded_js = R"JS(/*
 * Simple WebRTC client for libdatachannel backend
 */
class BasiliskWebRTC {
    constructor(videoElement, statusCallback) {
        this.video = videoElement;
        this.onStatus = statusCallback || (() => {});
        this.ws = null;
        this.pc = null;
        this.dataChannel = null;
        this.connected = false;
    }

    connect(wsUrl) {
        this.onStatus('Connecting...');
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this.onStatus('Signaling connected');
            this.ws.send(JSON.stringify({ type: 'connect' }));
        };

        this.ws.onmessage = (e) => {
            const msg = JSON.parse(e.data);
            this.handleSignaling(msg);
        };

        this.ws.onclose = () => {
            this.onStatus('Disconnected');
            this.connected = false;
            this.cleanup();
            setTimeout(() => this.connect(wsUrl), 3000);
        };

        this.ws.onerror = (e) => console.error('WebSocket error:', e);
    }

    async handleSignaling(msg) {
        console.log('Signaling:', msg.type);

        if (msg.type === 'welcome') {
            this.onStatus('Waiting for offer...');
        } else if (msg.type === 'offer') {
            this.createPeerConnection();
            const offer = new RTCSessionDescription({ type: 'offer', sdp: msg.sdp });
            await this.pc.setRemoteDescription(offer);
            const answer = await this.pc.createAnswer();
            await this.pc.setLocalDescription(answer);
            this.ws.send(JSON.stringify({ type: 'answer', sdp: answer.sdp }));
        } else if (msg.type === 'candidate') {
            if (this.pc) {
                await this.pc.addIceCandidate(new RTCIceCandidate({
                    candidate: msg.candidate,
                    sdpMid: msg.mid
                }));
            }
        }
    }

    createPeerConnection() {
        this.pc = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });

        this.pc.ontrack = (e) => {
            console.log('Track received:', e.track.kind);
            if (e.streams && e.streams[0]) {
                this.video.srcObject = e.streams[0];
                this.video.play().catch(e => console.warn('Play failed:', e));
                this.connected = true;
                this.onStatus('Connected');
            }
        };

        this.pc.ondatachannel = (e) => {
            console.log('DataChannel received:', e.channel.label);
            if (e.channel.label === 'input') {
                this.dataChannel = e.channel;
                this.setupDataChannel();
            }
        };

        this.pc.onicecandidate = (e) => {
            if (e.candidate) {
                this.ws.send(JSON.stringify({
                    type: 'candidate',
                    candidate: e.candidate.candidate,
                    mid: e.candidate.sdpMid
                }));
            }
        };

        this.pc.oniceconnectionstatechange = () => {
            console.log('ICE state:', this.pc.iceConnectionState);
            if (this.pc.iceConnectionState === 'failed') {
                this.onStatus('Connection failed');
            }
        };
    }

    setupDataChannel() {
        if (!this.dataChannel) return;
        this.dataChannel.onopen = () => {
            console.log('DataChannel open');
            this.setupInputHandlers();
        };
        this.dataChannel.onclose = () => console.log('DataChannel closed');
    }

    setupInputHandlers() {
        const target = this.video;
        if (!target) return;

        const getCoords = (e) => {
            const rect = target.getBoundingClientRect();
            const scaleX = this.video.videoWidth / rect.width;
            const scaleY = this.video.videoHeight / rect.height;
            return {
                x: Math.round((e.clientX - rect.left) * scaleX),
                y: Math.round((e.clientY - rect.top) * scaleY)
            };
        };

        // Throttle mouse moves to ~30 updates/sec
        let lastMouseTime = 0;
        target.addEventListener('mousemove', (e) => {
            const now = performance.now();
            if (now - lastMouseTime >= 33) {  // ~30fps
                const coords = getCoords(e);
                this.sendInput({ type: 'mouse_move', x: coords.x, y: coords.y });
                lastMouseTime = now;
            }
        });

        target.addEventListener('mousedown', (e) => {
            e.preventDefault();
            const coords = getCoords(e);
            this.sendInput({ type: 'mouse_down', x: coords.x, y: coords.y, button: e.button }, true);
        });

        target.addEventListener('mouseup', (e) => {
            e.preventDefault();
            const coords = getCoords(e);
            this.sendInput({ type: 'mouse_up', x: coords.x, y: coords.y, button: e.button }, true);
        });

        target.addEventListener('contextmenu', (e) => e.preventDefault());

        document.addEventListener('keydown', (e) => {
            if (!this.connected) return;
            e.preventDefault();
            this.sendInput({
                type: 'key_down',
                keyCode: e.keyCode,
                ctrl: e.ctrlKey,
                alt: e.altKey,
                shift: e.shiftKey,
                meta: e.metaKey
            }, true);
        });

        document.addEventListener('keyup', (e) => {
            if (!this.connected) return;
            e.preventDefault();
            this.sendInput({
                type: 'key_up',
                keyCode: e.keyCode,
                ctrl: e.ctrlKey,
                alt: e.altKey,
                shift: e.shiftKey,
                meta: e.metaKey
            }, true);
        });
    }

    sendInput(msg, priority = false) {
        if (this.dataChannel && this.dataChannel.readyState === 'open') {
            // Skip low-priority messages (mouse moves) if buffer is backing up
            if (!priority && this.dataChannel.bufferedAmount > 1024) {
                this.droppedMoves = (this.droppedMoves || 0) + 1;
                return;  // Drop this mouse move to prevent congestion
            }
            this.sentMessages = (this.sentMessages || 0) + 1;
            this.dataChannel.send(JSON.stringify(msg));
        }
    }

    startDiagnostics() {
        this.sentMessages = 0;
        this.droppedMoves = 0;
        this.lastVideoTime = 0;
        this.videoFrames = 0;
        setInterval(() => {
            let log = '';
            if (this.dataChannel) {
                const buf = this.dataChannel.bufferedAmount;
                log += '[Input] sent=' + this.sentMessages + ' dropped=' + this.droppedMoves + ' buf=' + buf;
                this.sentMessages = 0;
                this.droppedMoves = 0;
            }
            // Video stats from video element
            if (this.video && this.video.srcObject) {
                const vw = this.video.videoWidth;
                const vh = this.video.videoHeight;
                const paused = this.video.paused;
                const readyState = this.video.readyState;
                log += ' [Video] ' + vw + 'x' + vh + ' paused=' + paused + ' ready=' + readyState;
            }
            // WebRTC stats
            if (this.pc) {
                this.pc.getStats().then(stats => {
                    stats.forEach(report => {
                        if (report.type === 'inbound-rtp' && report.kind === 'video') {
                            const fps = report.framesPerSecond || 0;
                            const frames = report.framesReceived || 0;
                            const decoded = report.framesDecoded || 0;
                            const dropped = report.framesDropped || 0;
                            console.log('[RTP] fps=' + fps + ' recv=' + frames + ' decoded=' + decoded + ' dropped=' + dropped);
                        }
                    });
                });
            }
            if (log) console.log(log);
        }, 3000);
    }

    cleanup() {
        if (this.dataChannel) { this.dataChannel.close(); this.dataChannel = null; }
        if (this.pc) { this.pc.close(); this.pc = null; }
    }

    disconnect() {
        this.cleanup();
        if (this.ws) { this.ws.close(); this.ws = null; }
    }
}

// Auto-connect on page load
document.addEventListener('DOMContentLoaded', () => {
    const video = document.getElementById('screen');
    const status = document.getElementById('status');

    if (!video) {
        console.error('No video element found');
        return;
    }

    const client = new BasiliskWebRTC(video, (msg) => {
        console.log('Status:', msg);
        if (status) status.textContent = msg;
    });
    client.startDiagnostics();

    // Connect to same host on port 8090 for WebSocket signaling
    // Use WSS if page is loaded over HTTPS, otherwise plain WS
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.hostname}:8090`;
    console.log('Connecting to:', wsUrl);
    client.connect(wsUrl);
});
)JS";
