/*
 * Storage Manager Implementation
 */

#include "storage_manager.h"
#include "json_utils.h"
#include "codec.h"  // For CodecType

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>

// External reference to global codec setting (in server.cpp)
extern CodecType g_server_codec;

// Global storage paths
std::string g_roms_path = "storage/roms";
std::string g_images_path = "storage/images";
std::string g_prefs_path = "basilisk_ii.prefs";

// Helper: Check if filename has one of the given extensions
bool has_extension(const std::string& filename, const std::vector<std::string>& extensions) {
    size_t dot = filename.rfind('.');
    if (dot == std::string::npos) return false;
    std::string ext = filename.substr(dot);
    for (auto& c : ext) c = tolower(c);
    for (const auto& e : extensions) {
        if (ext == e) return true;
    }
    return false;
}

// Helper: Read ROM checksum (first 4 bytes)
uint32_t read_rom_checksum(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return 0;
    uint8_t buf[4];
    if (fread(buf, 1, 4, f) != 4) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}

// Helper: Recursive directory scanner
static void scan_directory_recursive(const std::string& base_dir, const std::string& relative_path,
                                     const std::vector<std::string>& extensions, bool read_checksums,
                                     std::vector<FileInfo>& files) {
    std::string current_dir = relative_path.empty() ? base_dir : base_dir + "/" + relative_path;

    DIR* dir = opendir(current_dir.c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        std::string name = entry->d_name;
        std::string full_path = current_dir + "/" + name;
        std::string rel_name = relative_path.empty() ? name : relative_path + "/" + name;

        struct stat st;
        if (stat(full_path.c_str(), &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            scan_directory_recursive(base_dir, rel_name, extensions, read_checksums, files);
        } else if (S_ISREG(st.st_mode)) {
            if (has_extension(name, extensions)) {
                FileInfo info;
                info.name = rel_name;
                info.size = st.st_size;
                info.checksum = 0;
                info.has_checksum = false;

                if (read_checksums) {
                    info.checksum = read_rom_checksum(full_path);
                    info.has_checksum = true;
                }

                files.push_back(info);
            }
        }
    }
    closedir(dir);
}

// Scan directory for files with specific extensions
std::vector<FileInfo> scan_directory(const std::string& directory,
                                      const std::vector<std::string>& extensions,
                                      bool read_checksums, bool recursive) {
    std::vector<FileInfo> files;

    if (recursive) {
        scan_directory_recursive(directory, "", extensions, read_checksums, files);
    } else {
        DIR* dir = opendir(directory.c_str());
        if (!dir) return files;

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_name[0] == '.') continue;

            std::string name = entry->d_name;
            if (has_extension(name, extensions)) {
                FileInfo info;
                info.name = name;
                info.size = 0;
                info.checksum = 0;
                info.has_checksum = false;

                std::string full_path = directory + "/" + name;
                struct stat st;
                if (stat(full_path.c_str(), &st) == 0) {
                    info.size = st.st_size;
                }

                if (read_checksums) {
                    info.checksum = read_rom_checksum(full_path);
                    info.has_checksum = true;
                }

                files.push_back(info);
            }
        }
        closedir(dir);
    }

    std::sort(files.begin(), files.end(), [](const FileInfo& a, const FileInfo& b) {
        return a.name < b.name;
    });
    return files;
}

// Get JSON representation of available storage
std::string get_storage_json() {
    auto roms = scan_directory(g_roms_path, {".rom"}, true, true);
    auto disks = scan_directory(g_images_path, {".img", ".dsk", ".hfv", ".toast"});
    auto cdroms = scan_directory(g_images_path, {".iso"});

    std::ostringstream json;
    json << "{\n";
    json << "  \"romsPath\": \"" << json_escape(g_roms_path) << "\",\n";
    json << "  \"imagesPath\": \"" << json_escape(g_images_path) << "\",\n";
    json << "  \"roms\": [";
    for (size_t i = 0; i < roms.size(); i++) {
        if (i > 0) json << ", ";
        json << "{\"name\": \"" << json_escape(roms[i].name) << "\", \"size\": " << roms[i].size;
        char checksum_hex[16];
        snprintf(checksum_hex, sizeof(checksum_hex), "%08x", roms[i].checksum);
        json << ", \"checksum\": \"" << checksum_hex << "\"}";
    }
    json << "],\n";
    json << "  \"disks\": [";
    for (size_t i = 0; i < disks.size(); i++) {
        if (i > 0) json << ", ";
        json << "{\"name\": \"" << json_escape(disks[i].name) << "\", \"size\": " << disks[i].size << "}";
    }
    json << "],\n";
    json << "  \"cdroms\": [";
    for (size_t i = 0; i < cdroms.size(); i++) {
        if (i > 0) json << ", ";
        json << "{\"name\": \"" << json_escape(cdroms[i].name) << "\", \"size\": " << cdroms[i].size << "}";
    }
    json << "]\n";
    json << "}";

    return json.str();
}

// Write raw prefs file content
bool write_prefs_file(const std::string& content) {
    std::ofstream file(g_prefs_path);
    if (!file) {
        fprintf(stderr, "Config: Failed to open prefs file for writing: %s\n", g_prefs_path.c_str());
        return false;
    }

    file << content;
    file.close();

    fprintf(stderr, "Config: Wrote prefs file: %s (%zu bytes)\n", g_prefs_path.c_str(), content.size());
    return true;
}

// Read raw prefs file content
std::string read_prefs_file() {
    std::ifstream file(g_prefs_path);
    if (!file) {
        return "";  // Empty string means no file exists
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Create minimal prefs file if it doesn't exist
void create_minimal_prefs_if_needed() {
    // Check if file already exists
    std::ifstream check(g_prefs_path);
    if (check.good()) {
        check.close();
        return;  // File exists, nothing to do
    }

    fprintf(stderr, "Config: Creating minimal prefs file at %s\n", g_prefs_path.c_str());

    // Minimal configuration template - matches client.js PREFS_TEMPLATE
    const char* minimal_prefs =
        "# Basilisk II preferences - minimal config for cold boot\n"
        "\n"
        "# ROM file (configure via web UI)\n"
        "rom \n"
        "\n"
        "# Hardware settings\n"
        "ramsize 33554432\n"  // 32 MB
        "screen ipc/800/600\n"
        "cpu 4\n"
        "modelid 14\n"
        "fpu true\n"
        "jit true\n"
        "nosound false\n"
        "\n"
        "# Video codec for web streaming (png or h264)\n"
        "webcodec png\n"
        "\n"
        "# JIT settings\n"
        "jitfpu true\n"
        "jitcachesize 8192\n"
        "jitlazyflush true\n"
        "jitinline true\n"
        "jitdebug false\n"
        "\n"
        "# Display settings\n"
        "displaycolordepth 0\n"
        "frameskip 0\n"
        "scale_nearest false\n"
        "scale_integer false\n"
        "\n"
        "# Input settings\n"
        "keyboardtype 5\n"
        "keycodes false\n"
        "mousewheelmode 1\n"
        "mousewheellines 3\n"
        "swap_opt_cmd true\n"
        "hotkey 0\n"
        "\n"
        "# Serial/Network\n"
        "seriala /dev/null\n"
        "serialb /dev/null\n"
        "udptunnel false\n"
        "udpport 6066\n"
        "etherpermanentaddress true\n"
        "ethermulticastmode 0\n"
        "routerenabled false\n"
        "ftp_port_list 21\n"
        "\n"
        "# Boot settings\n"
        "bootdrive 0\n"
        "bootdriver 0\n"
        "nocdrom false\n"
        "\n"
        "# System settings\n"
        "ignoresegv true\n"
        "idlewait true\n"
        "noclipconversion false\n"
        "nogui true\n"
        "sound_buffer 0\n"
        "name_encoding 0\n"
        "delay 0\n"
        "init_grab false\n"
        "yearofs 0\n"
        "dayofs 0\n"
        "reservewindowskey false\n"
        "\n"
        "# ExtFS settings\n"
        "enableextfs false\n"
        "debugextfs false\n"
        "extfs ./storage\n"
        "extdrives CDEFGHIJKLMNOPQRSTUVWXYZ\n"
        "pollmedia true\n";

    if (!write_prefs_file(minimal_prefs)) {
        fprintf(stderr, "Config: Failed to create minimal prefs file\n");
    }
}

// Read webcodec preference from prefs file
void read_webcodec_pref() {
    std::ifstream file(g_prefs_path);
    if (!file) {
        fprintf(stderr, "Config: No prefs file, defaulting to PNG codec\n");
        g_server_codec = CodecType::PNG;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        // Look for "webcodec" preference
        if (line.rfind("webcodec ", 0) == 0) {
            std::string value = line.substr(9);
            // Trim whitespace
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
                value.pop_back();
            }

            if (value == "h264" || value == "H264") {
                g_server_codec = CodecType::H264;
                fprintf(stderr, "Config: webcodec = h264\n");
            } else if (value == "av1" || value == "AV1") {
                g_server_codec = CodecType::AV1;
                fprintf(stderr, "Config: webcodec = av1\n");
            } else if (value == "png" || value == "PNG") {
                g_server_codec = CodecType::PNG;
                fprintf(stderr, "Config: webcodec = png\n");
            } else {
                fprintf(stderr, "Config: Unknown webcodec '%s', defaulting to PNG\n", value.c_str());
                g_server_codec = CodecType::PNG;
            }
            return;
        }
    }

    // Not found - default to PNG
    fprintf(stderr, "Config: webcodec not set, defaulting to PNG\n");
    g_server_codec = CodecType::PNG;
}
