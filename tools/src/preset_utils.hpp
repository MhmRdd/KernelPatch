/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */

#pragma once

#ifndef _Static_assert
#define _Static_assert static_assert
#endif

extern "C" {
#include "preset.h"
}

#include <cstring>
#include <string>

namespace kptools {

using SetupHeader = setup_header_t;
using SetupPreset = setup_preset_t;
using Preset = preset_t;
using MapSymbol = map_symbol_t;
using PatchConfig = patch_config_t;
using PatchExtraItem = patch_extra_item_t;
using Version = version_t;
using ExtraType = extra_item_type;

inline const char* extra_type_name(ExtraType type) {
    switch (type) {
        case EXTRA_TYPE_KPM: return EXTRA_TYPE_KPM_STR;
        case EXTRA_TYPE_SHELL: return EXTRA_TYPE_SHELL_STR;
        case EXTRA_TYPE_EXEC: return EXTRA_TYPE_EXEC_STR;
        case EXTRA_TYPE_RAW: return EXTRA_TYPE_RAW_STR;
        case EXTRA_TYPE_ANDROID_RC: return EXTRA_TYPE_ANDROID_RC_STR;
        default: return "none";
    }
}

inline ExtraType extra_type_from_name(const std::string& s) {
    if (s == EXTRA_TYPE_KPM_STR) return EXTRA_TYPE_KPM;
    if (s == EXTRA_TYPE_SHELL_STR) return EXTRA_TYPE_SHELL;
    if (s == EXTRA_TYPE_EXEC_STR) return EXTRA_TYPE_EXEC;
    if (s == EXTRA_TYPE_RAW_STR) return EXTRA_TYPE_RAW;
    if (s == EXTRA_TYPE_ANDROID_RC_STR) return EXTRA_TYPE_ANDROID_RC;
    return EXTRA_TYPE_NONE;
}

inline std::string version_string(const Version& v) {
    return std::to_string(v.major) + "." + std::to_string(v.minor) + "." + std::to_string(v.patch);
}

inline uint32_t version_pack(const Version& v) {
    return VERSION(v.major, v.minor, v.patch);
}

inline Version version_unpack(uint32_t val) {
    Version v{};
    v.major = (val >> 16) & 0xff;
    v.minor = (val >> 8) & 0xff;
    v.patch = val & 0xff;
    return v;
}

inline bool header_valid(const SetupHeader& h) {
    return std::memcmp(h.magic, KP_MAGIC, 6) == 0;
}

inline bool header_android(const SetupHeader& h) { return h.config_flags & CONFIG_ANDROID; }
inline bool header_debug(const SetupHeader& h) { return h.config_flags & CONFIG_DEBUG; }

inline bool extra_valid(const PatchExtraItem& e) {
    return std::memcmp(e.magic, EXTRA_HDR_MAGIC, 3) == 0;
}

inline bool extra_end(const PatchExtraItem& e) { return e.type == EXTRA_TYPE_NONE; }

template<typename T>
constexpr T align_up(T val, T align) { return (val + align - 1) & ~(align - 1); }

template<typename T>
constexpr T align_down(T val, T align) { return val & ~(align - 1); }

template<typename T>
constexpr bool is_aligned(T val, T align) { return (val & (align - 1)) == 0; }

} // namespace kptools