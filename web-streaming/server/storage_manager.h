/*
 * Storage Manager
 *
 * Handles file system operations for ROMs, disk images, and preferences.
 * Scans directories, reads ROM checksums, manages prefs files.
 */

#ifndef STORAGE_MANAGER_H
#define STORAGE_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>

// File information structure
struct FileInfo {
    std::string name;
    int64_t size;
    uint32_t checksum;
    bool has_checksum;
};

// Get JSON representation of available storage (ROMs, disks, CD-ROMs)
std::string get_storage_json();

// Write prefs file content (raw format)
bool write_prefs_file(const std::string& content);

// Read prefs file content (raw format)
std::string read_prefs_file();

// Create minimal prefs file if it doesn't exist
void create_minimal_prefs_if_needed();

// Read webcodec preference from prefs file
void read_webcodec_pref();

// Scan directory for files with specific extensions
std::vector<FileInfo> scan_directory(const std::string& directory,
                                      const std::vector<std::string>& extensions,
                                      bool read_checksums = false,
                                      bool recursive = false);

// Read ROM checksum (first 4 bytes)
uint32_t read_rom_checksum(const std::string& path);

// Check if filename has one of the given extensions
bool has_extension(const std::string& filename, const std::vector<std::string>& extensions);

// Global paths (set by main)
extern std::string g_roms_path;
extern std::string g_images_path;
extern std::string g_prefs_path;

#endif // STORAGE_MANAGER_H
