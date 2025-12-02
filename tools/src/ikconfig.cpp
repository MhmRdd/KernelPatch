/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2025 mhmrdd. All Rights Reserved.
 *
 * IKCONFIG finder and extractor implementation.
 */

#include "ikconfig.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <sstream>

#ifdef KPTOOLS_HAVE_ZLIB
#include <zlib.h>
#endif

namespace kptools {

namespace {

// Magic markers from kernel/configs.c
// The actual markers include a null byte to avoid false matches
constexpr uint8_t IKCFG_ST[] = {'I', 'K', 'C', 'F', 'G', '_', 'S', 'T'};
constexpr uint8_t IKCFG_ED[] = {'I', 'K', 'C', 'F', 'G', '_', 'E', 'D'};
constexpr size_t MARKER_LEN = 8;

constexpr size_t NPOS = static_cast<size_t>(-1);

} // anonymous namespace

// KernelConfig implementation

void KernelConfig::parse(const std::string& config_text) {
    raw_text_ = config_text;
    entries_.clear();

    std::istringstream stream(config_text);
    std::string line;

    while (std::getline(stream, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            // Check for "# CONFIG_FOO is not set" format
            if (line.find("# CONFIG_") == 0 && line.find(" is not set") != std::string::npos) {
                size_t start = 2; // Skip "# "
                size_t end = line.find(" is not set");
                if (end != std::string::npos) {
                    std::string key = line.substr(start, end - start);
                    entries_[key] = "n";
                }
            }
            continue;
        }

        // Parse CONFIG_FOO=value
        size_t eq_pos = line.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = line.substr(0, eq_pos);
            std::string value = line.substr(eq_pos + 1);

            // Remove trailing whitespace/carriage return
            while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) {
                value.pop_back();
            }

            // Remove quotes from string values
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }

            entries_[key] = value;
        }
    }
}

bool KernelConfig::is_set(const std::string& key) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    return it->second != "n";
}

bool KernelConfig::is_enabled(const std::string& key) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    return it->second == "y";
}

bool KernelConfig::is_module(const std::string& key) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    return it->second == "m";
}

std::string KernelConfig::get(const std::string& key) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) return "";
    return it->second;
}

// IkconfigFinder implementation

size_t IkconfigFinder::memfind(const uint8_t* haystack, size_t haystack_len,
                                const uint8_t* needle, size_t needle_len,
                                size_t start) {
    if (start >= haystack_len || needle_len == 0 || haystack_len - start < needle_len) {
        return NPOS;
    }

    const uint8_t* pos = std::search(haystack + start, haystack + haystack_len,
                                      needle, needle + needle_len);
    if (pos == haystack + haystack_len) return NPOS;
    return pos - haystack;
}

std::optional<std::pair<size_t, size_t>> IkconfigFinder::find(const uint8_t* data, size_t size) {
    // Search for IKCFG_ST marker
    size_t start = memfind(data, size, IKCFG_ST, MARKER_LEN, 0);
    if (start == NPOS) {
        return std::nullopt;
    }

    // Move past the marker to the gzip data
    size_t gzip_start = start + MARKER_LEN;

    // Search for IKCFG_ED marker after start
    size_t end = memfind(data, size, IKCFG_ED, MARKER_LEN, gzip_start);
    if (end == NPOS) {
        return std::nullopt;
    }

    start_offset_ = gzip_start;
    end_offset_ = end;

    return std::make_pair(gzip_start, end);
}

std::string IkconfigFinder::decompress_gzip(const uint8_t* data, size_t size) {
#ifdef KPTOOLS_HAVE_ZLIB
    // Initialize zlib for gzip decompression
    z_stream strm{};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = static_cast<uInt>(size);
    strm.next_in = const_cast<Bytef*>(data);

    // 15 + 16 = gzip format
    int ret = inflateInit2(&strm, 15 + 16);
    if (ret != Z_OK) {
        throw IkconfigNotFound("Failed to initialize zlib decompression");
    }

    std::string result;
    char buffer[16384];

    do {
        strm.avail_out = sizeof(buffer);
        strm.next_out = reinterpret_cast<Bytef*>(buffer);

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            throw IkconfigNotFound("Decompression error: " + std::string(strm.msg ? strm.msg : "unknown"));
        }

        size_t have = sizeof(buffer) - strm.avail_out;
        result.append(buffer, have);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return result;
#else
    throw IkconfigNotFound("zlib support not compiled in - cannot decompress config");
#endif
}

std::string IkconfigFinder::extract(const uint8_t* data, size_t size) {
    auto range = find(data, size);
    if (!range) {
        throw IkconfigNotFound("IKCONFIG markers not found in kernel image");
    }

    auto [gzip_start, gzip_end] = *range;
    size_t gzip_size = gzip_end - gzip_start;

    if (gzip_size == 0) {
        throw IkconfigNotFound("Empty config data between markers");
    }

    // Store the gzip data
    gzip_data_.assign(data + gzip_start, data + gzip_end);

    std::fprintf(stderr, "[+] Found IKCONFIG at 0x%zx - 0x%zx (%zu bytes compressed)\n",
                 gzip_start, gzip_end, gzip_size);

    // Decompress
    return decompress_gzip(gzip_data_.data(), gzip_data_.size());
}

} // namespace kptools