/*
 * JSON Utilities Implementation
 */

#include "json_utils.h"

namespace json_utils {

json parse(const std::string& str) {
    return json::parse(str);
}

std::string to_string(const json& j, int indent) {
    return j.dump(indent);
}

std::string get_string(const json& j, const std::string& key,
                       const std::string& default_val) {
    if (!j.is_object()) {
        return default_val;
    }

    auto it = j.find(key);
    if (it == j.end() || !it->is_string()) {
        return default_val;
    }

    return it->get<std::string>();
}

int get_int(const json& j, const std::string& key, int default_val) {
    if (!j.is_object()) {
        return default_val;
    }

    auto it = j.find(key);
    if (it == j.end() || !it->is_number_integer()) {
        return default_val;
    }

    return it->get<int>();
}

bool get_bool(const json& j, const std::string& key, bool default_val) {
    if (!j.is_object()) {
        return default_val;
    }

    auto it = j.find(key);
    if (it == j.end() || !it->is_boolean()) {
        return default_val;
    }

    return it->get<bool>();
}

bool has_key(const json& j, const std::string& key) {
    if (!j.is_object()) {
        return false;
    }

    return j.find(key) != j.end();
}

} // namespace json_utils
