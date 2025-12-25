/*
 * API Handlers Module
 *
 * Implementation of all /api/ endpoints
 */

#include "api_handlers.h"
#include "../storage/file_scanner.h"
#include "../storage/prefs_manager.h"
#include "../utils/json_utils.h"
#include "../../BasiliskII/src/IPC/ipc_protocol.h"
#include <sstream>
#include <iomanip>
#include <cstdio>

namespace http {

APIRouter::APIRouter(APIContext* context)
    : ctx_(context)
{}

Response APIRouter::handle(const Request& req, bool* handled) {
    *handled = false;

    // Check if this is an API route
    if (req.path.rfind("/api/", 0) != 0) {
        return Response::not_found();
    }

    *handled = true;

    // Route to handlers
    if (req.path == "/api/config" && req.method == "GET") {
        return handle_config(req);
    }
    if (req.path == "/api/storage" && req.method == "GET") {
        return handle_storage(req);
    }
    if (req.path == "/api/prefs" && req.method == "GET") {
        return handle_prefs_get(req);
    }
    if (req.path == "/api/prefs" && req.method == "POST") {
        return handle_prefs_post(req);
    }
    if (req.path == "/api/restart" && req.method == "POST") {
        return handle_restart(req);
    }
    if (req.path == "/api/status" && req.method == "GET") {
        return handle_status(req);
    }
    if (req.path == "/api/codec" && req.method == "GET") {
        return handle_codec_get(req);
    }
    if (req.path == "/api/codec" && req.method == "POST") {
        return handle_codec_post(req);
    }
    if (req.path == "/api/emulator/start" && req.method == "POST") {
        return handle_emulator_start(req);
    }
    if (req.path == "/api/emulator/stop" && req.method == "POST") {
        return handle_emulator_stop(req);
    }
    if (req.path == "/api/emulator/restart" && req.method == "POST") {
        return handle_emulator_restart(req);
    }
    if (req.path == "/api/log" && req.method == "POST") {
        return handle_log(req);
    }
    if (req.path == "/api/error" && req.method == "POST") {
        return handle_error(req);
    }

    // Unknown API endpoint
    Response resp;
    resp.set_status(404);
    resp.set_body("{\"error\": \"Unknown API endpoint\"}");
    resp.set_content_type("application/json");
    return resp;
}

Response APIRouter::handle_config(const Request& req) {
    std::ostringstream json;
    json << "{";
    json << "\"debug_connection\": " << (ctx_->debug_connection ? "true" : "false");
    json << ", \"debug_mode_switch\": " << (ctx_->debug_mode_switch ? "true" : "false");
    json << ", \"debug_perf\": " << (ctx_->debug_perf ? "true" : "false");
    json << "}";
    return Response::json(json.str());
}

Response APIRouter::handle_storage(const Request& req) {
    std::string json_body = storage::get_storage_json(ctx_->roms_path, ctx_->images_path);
    return Response::json(json_body);
}

Response APIRouter::handle_prefs_get(const Request& req) {
    std::string prefs_content = storage::read_prefs_file(ctx_->prefs_path);
    std::string json_body = "{\"content\": \"" + storage::json_escape(prefs_content) + "\", ";
    json_body += "\"path\": \"" + storage::json_escape(ctx_->prefs_path) + "\", ";
    json_body += "\"romsPath\": \"" + storage::json_escape(ctx_->roms_path) + "\", ";
    json_body += "\"imagesPath\": \"" + storage::json_escape(ctx_->images_path) + "\"}";
    return Response::json(json_body);
}

Response APIRouter::handle_prefs_post(const Request& req) {
    fprintf(stderr, "Config: Received prefs POST (body length=%zu)\n", req.body.size());
    auto j = json_utils::parse(req.body);
    std::string content = json_utils::get_string(j, "content");
    fprintf(stderr, "Config: Extracted content length=%zu\n", content.size());
    if (content.empty()) {
        fprintf(stderr, "Config: WARNING - extracted content is empty! Body: %s\n",
                req.body.substr(0, 200).c_str());
    }
    if (storage::write_prefs_file(ctx_->prefs_path, content)) {
        return Response::json("{\"success\": true}");
    } else {
        return Response::json("{\"success\": false, \"error\": \"Failed to write prefs file\"}");
    }
}

Response APIRouter::handle_restart(const Request& req) {
    fprintf(stderr, "Server: Restart requested via API\n");
    if (ctx_->send_command_fn) {
        ctx_->send_command_fn(MACEMU_CMD_RESET);
    }
    return Response::json("{\"success\": true, \"message\": \"Restart sent to emulator\"}");
}

Response APIRouter::handle_status(const Request& req) {
    std::ostringstream json;
    json << "{";
    json << "\"emulator_connected\": " << (ctx_->emulator_connected ? "true" : "false");
    json << ", \"emulator_running\": " << (ctx_->started_emulator_pid > 0 ? "true" : "false");
    json << ", \"emulator_pid\": " << ctx_->emulator_pid;

    if (ctx_->video_shm) {
        json << ", \"video\": {\"width\": " << ctx_->video_shm->width;
        json << ", \"height\": " << ctx_->video_shm->height;
        json << ", \"frame_count\": " << ctx_->video_shm->frame_count;
        json << ", \"state\": " << ctx_->video_shm->state << "}";

        // Mouse latency from emulator (atomic - can be updated by stats thread)
        uint32_t latency_x10 = ATOMIC_LOAD(ctx_->video_shm->mouse_latency_avg_ms);
        uint32_t latency_samples = ATOMIC_LOAD(ctx_->video_shm->mouse_latency_samples);
        json << ", \"mouse_latency_ms\": " << std::fixed << std::setprecision(1) << (latency_x10 / 10.0);
        json << ", \"mouse_latency_samples\": " << latency_samples;
    }

    json << "}";
    return Response::json(json.str());
}

Response APIRouter::handle_emulator_start(const Request& req) {
    std::string json_body;
    if (ctx_->started_emulator_pid > 0) {
        json_body = "{\"success\": false, \"message\": \"Emulator already running\", \"pid\": " +
                    std::to_string(ctx_->started_emulator_pid) + "}";
    } else if (ctx_->start_emulator_fn && ctx_->start_emulator_fn()) {
        json_body = "{\"success\": true, \"message\": \"Emulator started\", \"pid\": " +
                    std::to_string(ctx_->started_emulator_pid) + "}";
    } else {
        json_body = "{\"success\": false, \"message\": \"Failed to start emulator\"}";
    }
    return Response::json(json_body);
}

Response APIRouter::handle_emulator_stop(const Request& req) {
    std::string json_body;
    if (ctx_->started_emulator_pid <= 0 && ctx_->emulator_pid <= 0) {
        json_body = "{\"success\": false, \"message\": \"Emulator not running\"}";
    } else {
        if (ctx_->started_emulator_pid > 0) {
            if (ctx_->stop_emulator_fn) {
                ctx_->stop_emulator_fn();
            }
        } else {
            // Just disconnect from external emulator
            if (ctx_->send_command_fn) {
                ctx_->send_command_fn(MACEMU_CMD_STOP);
            }
            if (ctx_->disconnect_emulator_fn) {
                ctx_->disconnect_emulator_fn();
            }
        }
        json_body = "{\"success\": true, \"message\": \"Emulator stopped\"}";
    }
    return Response::json(json_body);
}

Response APIRouter::handle_emulator_restart(const Request& req) {
    if (ctx_->request_restart_fn) {
        ctx_->request_restart_fn(true);
    }
    return Response::json("{\"success\": true, \"message\": \"Restart requested\"}");
}

Response APIRouter::handle_log(const Request& req) {
    // Client logging endpoint - parse and display browser logs
    auto j = json_utils::parse(req.body);
    std::string level = json_utils::get_string(j, "level");
    std::string msg = json_utils::get_string(j, "message");
    std::string data = json_utils::get_string(j, "data");

    // Format: [Browser] level: message
    const char* prefix = "[Browser]";
    if (level == "error") {
        fprintf(stderr, "\033[31m%s ERROR: %s%s%s\033[0m\n", prefix, msg.c_str(),
                data.empty() ? "" : " | ", data.c_str());
    } else if (level == "warn") {
        fprintf(stderr, "\033[33m%s WARN: %s%s%s\033[0m\n", prefix, msg.c_str(),
                data.empty() ? "" : " | ", data.c_str());
    } else {
        fprintf(stderr, "%s %s: %s%s%s\n", prefix, level.c_str(), msg.c_str(),
                data.empty() ? "" : " | ", data.c_str());
    }

    return Response::json("{\"ok\": true}");
}

Response APIRouter::handle_error(const Request& req) {
    // Client error reporting endpoint - capture JavaScript errors, exceptions, and crashes
    auto j = json_utils::parse(req.body);
    std::string message = json_utils::get_string(j, "message");
    std::string stack = json_utils::get_string(j, "stack");
    std::string url = json_utils::get_string(j, "url");
    std::string line = json_utils::get_string(j, "line");
    std::string col = json_utils::get_string(j, "col");
    std::string type = json_utils::get_string(j, "type");

    // Format: [Browser ERROR] with red color for visibility
    fprintf(stderr, "\033[1;31m[Browser ERROR]\033[0m ");

    if (!type.empty()) {
        fprintf(stderr, "%s: ", type.c_str());
    }

    fprintf(stderr, "%s", message.c_str());

    if (!url.empty()) {
        fprintf(stderr, "\n  at %s", url.c_str());
        if (!line.empty()) {
            fprintf(stderr, ":%s", line.c_str());
            if (!col.empty()) {
                fprintf(stderr, ":%s", col.c_str());
            }
        }
    }

    if (!stack.empty()) {
        // Print stack trace with indentation
        fprintf(stderr, "\n  Stack trace:\n");
        // Split by newlines and indent each line
        size_t pos = 0;
        std::string stack_copy = stack;
        while ((pos = stack_copy.find('\n')) != std::string::npos) {
            std::string line_str = stack_copy.substr(0, pos);
            if (!line_str.empty()) {
                fprintf(stderr, "    %s\n", line_str.c_str());
            }
            stack_copy.erase(0, pos + 1);
        }
        if (!stack_copy.empty()) {
            fprintf(stderr, "    %s\n", stack_copy.c_str());
        }
    } else {
        fprintf(stderr, "\n");
    }

    return Response::json("{\"ok\": true}");
}

Response APIRouter::handle_codec_get(const Request& req) {
    (void)req;  // Unused parameter

    if (!ctx_->server_codec) {
        return Response::json("{\"error\": \"Codec not available\"}");
    }

    const char* codec_name = "";
    switch (*ctx_->server_codec) {
        case CodecType::H264: codec_name = "h264"; break;
        case CodecType::AV1: codec_name = "av1"; break;
        case CodecType::PNG: codec_name = "png"; break;
        case CodecType::RAW: codec_name = "raw"; break;
    }

    std::string json_body = "{\"codec\": \"";
    json_body += codec_name;
    json_body += "\"}";
    return Response::json(json_body);
}

Response APIRouter::handle_codec_post(const Request& req) {
    if (!ctx_->server_codec || !ctx_->notify_codec_change_fn) {
        return Response::json("{\"error\": \"Codec change not available\"}");
    }

    auto j = json_utils::parse(req.body);
    std::string codec_str = json_utils::get_string(j, "codec");

    CodecType new_codec;
    if (codec_str == "h264" || codec_str == "H264") {
        new_codec = CodecType::H264;
    } else if (codec_str == "av1" || codec_str == "AV1") {
        new_codec = CodecType::AV1;
    } else if (codec_str == "png" || codec_str == "PNG") {
        new_codec = CodecType::PNG;
    } else if (codec_str == "raw" || codec_str == "RAW") {
        new_codec = CodecType::RAW;
    } else {
        return Response::json("{\"error\": \"Invalid codec. Use h264, av1, png, or raw\"}");
    }

    // Update codec
    CodecType old_codec = *ctx_->server_codec;
    *ctx_->server_codec = new_codec;

    fprintf(stderr, "Config: Codec changed from %d to %d via API\n", (int)old_codec, (int)new_codec);

    // Notify all clients (will send reconnect message via WebSocket)
    if (new_codec != old_codec) {
        ctx_->notify_codec_change_fn(new_codec);
    }

    return Response::json("{\"ok\": true}");
}

} // namespace http
