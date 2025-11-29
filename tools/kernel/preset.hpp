/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "../core/types.hpp"
#include <cstdint>
#include <cstring>

namespace kp {
namespace kernel {

// Constants (from preset.h)

inline constexpr size_t MAGIC_LEN = 8;
inline constexpr size_t KP_HEADER_SIZE = 64;
inline constexpr size_t SUPER_KEY_LEN = 64;
inline constexpr size_t ROOT_SUPER_KEY_HASH_LEN = 32;
inline constexpr size_t SETUP_PRESERVE_LEN = 64;
inline constexpr size_t HDR_BACKUP_SIZE = 8;
inline constexpr size_t COMPILE_TIME_LEN = 24;
inline constexpr size_t MAP_MAX_SIZE = 0xa00;
inline constexpr size_t MAP_SYMBOL_NUM = 5;
inline constexpr size_t MAP_SYMBOL_SIZE = MAP_SYMBOL_NUM * 8;
inline constexpr size_t PATCH_CONFIG_LEN = 512;
inline constexpr size_t ADDITIONAL_LEN = 512;
inline constexpr size_t PATCH_EXTRA_ITEM_LEN = 128;

inline constexpr uint64_t CONFIG_DEBUG = 1 << 0;
inline constexpr uint64_t CONFIG_ANDROID = 1 << 1;

// Extra types
inline constexpr int32_t EXTRA_TYPE_NONE = 0;
inline constexpr int32_t EXTRA_TYPE_KPM = 1;
inline constexpr int32_t EXTRA_TYPE_SHELL = 2;
inline constexpr int32_t EXTRA_TYPE_EXEC = 3;
inline constexpr int32_t EXTRA_TYPE_RAW = 4;
inline constexpr int32_t EXTRA_TYPE_ANDROID_RC = 5;

inline constexpr size_t EXTRA_ALIGN = 16;
inline constexpr size_t EXTRA_NAME_LEN = 32;
inline constexpr size_t EXTRA_EVENT_LEN = 32;

// Structures (from preset.h)

#pragma pack(push, 1)

struct Version {
    uint8_t _reserved;
    uint8_t patch;
    uint8_t minor;
    uint8_t major;

    uint32_t to_int() const {
        return (major << 16) | (minor << 8) | patch;
    }
};

struct SetupHeader {
    char magic[MAGIC_LEN];
    Version kp_version;
    uint32_t _reserved;
    uint64_t config_flags;
    char compile_time[COMPILE_TIME_LEN];
    char _padding[64 - MAGIC_LEN - 4 - 4 - 8 - COMPILE_TIME_LEN];

    bool is_android() const { return config_flags & CONFIG_ANDROID; }
    bool is_debug() const { return config_flags & CONFIG_DEBUG; }
};

static_assert(sizeof(SetupHeader) == KP_HEADER_SIZE, "SetupHeader size mismatch");

struct MapSymbol {
    uint64_t memblock_reserve_relo;
    uint64_t memblock_free_relo;
    uint64_t memblock_phys_alloc_relo;
    uint64_t memblock_virt_alloc_relo;
    uint64_t memblock_mark_nomap_relo;
    // No padding needed - MAP_SYMBOL_SIZE = 5 * 8 = 40 bytes
};

static_assert(sizeof(MapSymbol) == MAP_SYMBOL_SIZE, "MapSymbol size mismatch");

struct PatchConfig {
    uint64_t kallsyms_lookup_name;
    uint64_t printk;
    uint64_t panic;
    uint64_t rest_init;
    uint64_t cgroup_init;
    uint64_t kernel_init;
    uint64_t report_cfi_failure;
    uint64_t __cfi_slowpath_diag;
    uint64_t __cfi_slowpath;
    uint64_t copy_process;
    uint64_t cgroup_post_fork;
    uint64_t avc_denied;
    uint64_t slow_avc_audit;
    uint64_t input_handle_event;
    uint8_t patch_su_config;
    char _padding[PATCH_CONFIG_LEN - 14 * 8 - 1];
};

static_assert(sizeof(PatchConfig) == PATCH_CONFIG_LEN, "PatchConfig size mismatch");

struct SetupPreset {
    Version kernel_version;
    int32_t _reserved;
    int64_t kimg_size;
    int64_t kpimg_size;
    int64_t kernel_size;
    int64_t page_shift;
    int64_t setup_offset;
    int64_t start_offset;
    int64_t extra_size;
    int64_t map_offset;
    int64_t map_max_size;
    int64_t kallsyms_lookup_name_offset;
    int64_t paging_init_offset;
    int64_t printk_offset;
    MapSymbol map_symbol;
    uint8_t header_backup[HDR_BACKUP_SIZE];
    uint8_t superkey[SUPER_KEY_LEN];
    uint8_t root_superkey[ROOT_SUPER_KEY_HASH_LEN];
    uint8_t _preserve[SETUP_PRESERVE_LEN];
    PatchConfig patch_config;
    char additional[ADDITIONAL_LEN];
};

struct Preset {
    SetupHeader header;
    SetupPreset setup;
};

struct PatchExtraItem {
    char magic[4];
    int32_t priority;
    int32_t args_size;
    int32_t con_size;
    int32_t type;
    char name[EXTRA_NAME_LEN];
    char event[EXTRA_EVENT_LEN];
    char _padding[PATCH_EXTRA_ITEM_LEN - 4 - 4 * 4 - EXTRA_NAME_LEN - EXTRA_EVENT_LEN];
};

static_assert(sizeof(PatchExtraItem) == PATCH_EXTRA_ITEM_LEN, "PatchExtraItem size mismatch");

#pragma pack(pop)

// Extra type helpers

inline const char *extra_type_str(int32_t type) {
    switch (type) {
    case EXTRA_TYPE_KPM: return "kpm";
    case EXTRA_TYPE_EXEC: return "exec";
    case EXTRA_TYPE_SHELL: return "shell";
    case EXTRA_TYPE_RAW: return "raw";
    case EXTRA_TYPE_ANDROID_RC: return "android_rc";
    default: return "none";
    }
}

inline int32_t extra_str_type(std::string_view str) {
    if (str == "kpm") return EXTRA_TYPE_KPM;
    if (str == "exec") return EXTRA_TYPE_EXEC;
    if (str == "shell") return EXTRA_TYPE_SHELL;
    if (str == "raw") return EXTRA_TYPE_RAW;
    if (str == "android_rc") return EXTRA_TYPE_ANDROID_RC;
    return EXTRA_TYPE_NONE;
}

// Extra event constants

inline constexpr const char *EXTRA_HDR_MAGIC = "kpe";
inline constexpr const char *EXTRA_EVENT_PAGING_INIT = "paging-init";
inline constexpr const char *EXTRA_EVENT_PRE_KERNEL_INIT = "pre-kernel-init";
inline constexpr const char *EXTRA_EVENT_POST_KERNEL_INIT = "post-kernel-init";
inline constexpr const char *EXTRA_EVENT_PRE_FIRST_STAGE = "pre-init-first-stage";
inline constexpr const char *EXTRA_EVENT_POST_FIRST_STAGE = "post-init-first-stage";
inline constexpr const char *EXTRA_EVENT_PRE_EXEC_INIT = "pre-exec-init";
inline constexpr const char *EXTRA_EVENT_POST_EXEC_INIT = "post-exec-init";

} // namespace kernel
} // namespace kp