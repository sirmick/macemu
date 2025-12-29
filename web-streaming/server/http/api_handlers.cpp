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
    if (req.path == "/api/config" && req.method == "POST") {
        return handle_config_post(req);
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
    // Parse prefs file to extract webcodec and mousemode
    std::string prefs_content = storage::read_prefs_file(ctx_->prefs_path);
    std::string webcodec = "h264";  // default
    std::string mousemode = "relative";  // default
    std::string resolution = "800x600";  // default

    // Parse prefs file line by line
    std::istringstream stream(prefs_content);
    std::string line;
    while (std::getline(stream, line)) {
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos || line[start] == '#') continue;

        size_t space = line.find(' ', start);
        if (space == std::string::npos) continue;

        std::string key = line.substr(start, space - start);
        std::string value = line.substr(space + 1);

        // Trim value
        size_t value_start = value.find_first_not_of(" \t\r\n");
        if (value_start != std::string::npos) {
            value = value.substr(value_start);
            size_t value_end = value.find_last_not_of(" \t\r\n");
            if (value_end != std::string::npos) {
                value = value.substr(0, value_end + 1);
            }
        }

        if (key == "webcodec") {
            webcodec = value;
        } else if (key == "mousemode") {
            mousemode = value;
        } else if (key == "screen") {
            // Parse "ipc/800/600" format
            size_t slash1 = value.find('/');
            if (slash1 != std::string::npos) {
                size_t slash2 = value.find('/', slash1 + 1);
                if (slash2 != std::string::npos) {
                    std::string w = value.substr(slash1 + 1, slash2 - slash1 - 1);
                    std::string h = value.substr(slash2 + 1);
                    resolution = w + "x" + h;
                }
            }
        }
    }

    std::ostringstream json;
    json << "{";
    json << "\"debug_connection\": " << (ctx_->debug_connection ? "true" : "false");
    json << ", \"debug_mode_switch\": " << (ctx_->debug_mode_switch ? "true" : "false");
    json << ", \"debug_perf\": " << (ctx_->debug_perf ? "true" : "false");
    json << ", \"webcodec\": \"" << storage::json_escape(webcodec) << "\"";
    json << ", \"mousemode\": \"" << storage::json_escape(mousemode) << "\"";
    json << ", \"resolution\": \"" << storage::json_escape(resolution) << "\"";
    json << "}";
    return Response::json(json.str());
}

Response APIRouter::handle_config_post(const Request& req) {
    // Parse JSON body
    auto j = json_utils::parse(req.body);

    // Check if mousemode is being updated
    if (j.contains("mousemode")) {
        std::string mousemode = json_utils::get_string(j, "mousemode");
        if (mousemode == "relative" || mousemode == "absolute") {
            if (storage::write_mousemode_pref(ctx_->prefs_path, mousemode)) {
                fprintf(stderr, "Config: Updated mousemode to '%s'\n", mousemode.c_str());
                return Response::json("{\"success\": true}");
            } else {
                return Response::json("{\"success\": false, \"error\": \"Failed to write mousemode\"}");
            }
        } else {
            return Response::json("{\"success\": false, \"error\": \"Invalid mousemode value\"}");
        }
    }

    return Response::json("{\"success\": false, \"error\": \"No valid config parameter provided\"}");
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

    if (ctx_->ipc_shm) {
        json << ", \"video\": {\"width\": " << ctx_->ipc_shm->width;
        json << ", \"height\": " << ctx_->ipc_shm->height;
        json << ", \"frame_count\": " << ctx_->ipc_shm->frame_count;
        json << ", \"state\": " << ctx_->ipc_shm->state << "}";

        // Mouse latency from emulator (atomic - can be updated by stats thread)
        uint32_t latency_x10 = ATOMIC_LOAD(ctx_->ipc_shm->mouse_latency_avg_ms);
        uint32_t latency_samples = ATOMIC_LOAD(ctx_->ipc_shm->mouse_latency_samples);
        json << ", \"mouse_latency_ms\": " << std::fixed << std::setprecision(1) << (latency_x10 / 10.0);
        json << ", \"mouse_latency_samples\": " << latency_samples;
    }

    json << "}";
    return Response::json(json.str());
}

Response APIRouter::handle_emulator_start(const Request& req) {
    // Clear the "user stopped" flag - allow connection manager to scan/connect
    if (ctx_->user_stopped_emulator) {
        *ctx_->user_stopped_emulator = false;
    }

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
    // Set flag to prevent connection manager from auto-reconnecting
    if (ctx_->user_stopped_emulator) {
        *ctx_->user_stopped_emulator = true;
    }

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
    // Clear the "user stopped" flag - restart is an intentional start action
    if (ctx_->user_stopped_emulator) {
        *ctx_->user_stopped_emulator = false;
    }

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
    } else if (codec_str == "vp9" || codec_str == "VP9") {
        new_codec = CodecType::VP9;
    } else if (codec_str == "png" || codec_str == "PNG") {
        new_codec = CodecType::PNG;
    } else {
        return Response::json("{\"error\": \"Invalid codec. Use h264, av1, vp9, or png\"}");
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
