/*
 * Simple JSON Utilities
 *
 * Basic JSON escaping and parsing functions.
 * These are minimal implementations for server-side needs.
 */

#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <string>

// Escape special characters for JSON strings
std::string json_escape(const std::string& s);

// Extract a string value from JSON (simple key-value parsing)
std::string json_get_string(const std::string& json, const std::string& key);

#endif // JSON_UTILS_H
