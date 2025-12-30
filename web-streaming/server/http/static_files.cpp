/*
 * Static File Handler Module
 *
 * Implementation of static file serving
 */

#include "static_files.h"
#include <fstream>
#include <sstream>

namespace http {

StaticFileHandler::StaticFileHandler(const std::string& root_dir)
    : root_dir_(root_dir)
{}

bool StaticFileHandler::handles(const std::string& path) const {
    // Handle root paths and known static files
    return path == "/" ||
           path == "/index.html" ||
           path == "/client.js" ||
           path == "/styles.css" ||
           path == "/Apple.svg" ||
           path == "/Motorola.svg" ||
           path == "/PowerPC.svg";
}

Response StaticFileHandler::serve(const std::string& path) {
    std::string file_path = map_path_to_file(path);
    if (file_path.empty()) {
        return Response::not_found();
    }

    // Read file
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return Response::not_found();
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();

    // Build response
    Response resp;
    resp.set_content_type(get_content_type(path));
    resp.set_body(content);
    return resp;
}

std::string StaticFileHandler::map_path_to_file(const std::string& path) const {
    // Map URL paths to disk files
    if (path == "/" || path == "/index.html") {
        return root_dir_ + "/index.html";
    } else if (path == "/client.js") {
        return root_dir_ + "/client.js";
    } else if (path == "/styles.css") {
        return root_dir_ + "/styles.css";
    } else if (path == "/Apple.svg") {
        return root_dir_ + "/Apple.svg";
    } else if (path == "/Motorola.svg") {
        return root_dir_ + "/Motorola.svg";
    } else if (path == "/PowerPC.svg") {
        return root_dir_ + "/PowerPC.svg";
    }
    return "";  // Not found
}

std::string StaticFileHandler::get_content_type(const std::string& path) const {
    if (path.find(".html") != std::string::npos || path == "/") {
        return "text/html";
    } else if (path.find(".js") != std::string::npos) {
        return "application/javascript";
    } else if (path.find(".css") != std::string::npos) {
        return "text/css";
    } else if (path.find(".svg") != std::string::npos) {
        return "image/svg+xml";
    }
    return "text/plain";
}

} // namespace http
