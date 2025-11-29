/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace kp::log {

inline bool enabled = false;

#define kp_log_info(fmt, ...) \
    do { if (::kp::log::enabled) std::fprintf(stdout, "[+] " fmt, ##__VA_ARGS__); } while (0)

#define kp_log_warn(fmt, ...) \
    std::fprintf(stderr, "[?] " fmt, ##__VA_ARGS__)

#define kp_log_error(fmt, ...) \
    std::fprintf(stderr, "[-] " fmt, ##__VA_ARGS__)

[[noreturn]] inline void fatal(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    std::fprintf(stderr, "[-] FATAL: ");
    std::vfprintf(stderr, fmt, args);
    va_end(args);
    std::exit(EXIT_FAILURE);
}

#define kp_fatal(fmt, ...) ::kp::log::fatal(fmt, ##__VA_ARGS__)

inline std::string hex_string(const uint8_t *data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        result += buf;
    }
    return result;
}

inline std::string hex_string(const void *data, size_t len) {
    return hex_string(static_cast<const uint8_t *>(data), len);
}

} // namespace kp::log