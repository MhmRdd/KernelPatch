/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "../core/buffer.hpp"
#include "../core/types.hpp"
#include "image.hpp"
#include "kallsym.hpp"
#include "preset.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace kp {
namespace kernel {

// Session tags for output

inline constexpr const char *INFO_KERNEL_SESSION = "[kernel]";
inline constexpr const char *INFO_KPIMG_SESSION = "[kpimg]";
inline constexpr const char *INFO_ADDITIONAL_SESSION = "[additional]";
inline constexpr const char *INFO_EXTRA_SESSION = "[extras]";

// Extra item configuration

struct ExtraConfig {
    int32_t type = EXTRA_TYPE_NONE;
    bool is_path = false;
    std::string path_or_name;
    std::string args;
    std::string name;
    std::string event;
    int32_t priority = 0;

    // Loaded data (if from path)
    Buffer data;

    // Item header
    PatchExtraItem item{};
};

// Patched kernel image info

struct PatchedKernelInfo {
    KernelInfo kinfo;
    std::string banner;
    Preset *preset = nullptr;
    int32_t ori_kimg_len = 0;
    std::vector<PatchExtraItem *> embed_items;
};

// Kernel file wrapper (handles UNCOMPRESSED_IMG prefix)

class KernelFile {
    Buffer data_;
    bool has_prefix_ = false;
    size_t img_offset_ = 0;

public:
    KernelFile() = default;

    // Load from file
    static Result<KernelFile> from_file(const std::filesystem::path &path);

    // Create new kernel file based on old one
    static KernelFile create_new(const KernelFile &old, size_t kimg_len);

    // Accessors
    uint8_t *kimg() { return data_.data() + img_offset_; }
    const uint8_t *kimg() const { return data_.data() + img_offset_; }
    size_t kimg_len() const { return data_.size() - img_offset_; }

    Buffer &raw_data() { return data_; }
    const Buffer &raw_data() const { return data_; }

    bool has_prefix() const { return has_prefix_; }

    // Update image length
    void set_kimg_len(size_t len);

    // Save to file
    Result<void> to_file(const std::filesystem::path &path) const;
};

// Patching operations

class Patcher {
public:
    Patcher() = default;

    // Patch kernel image
    Result<void> patch(
        const std::filesystem::path &kimg_path,
        const std::filesystem::path &kpimg_path,
        const std::filesystem::path &out_path,
        const std::string &superkey,
        bool root_key,
        const std::vector<std::string> &additional,
        std::vector<ExtraConfig> &extras);

    // Unpatch kernel image
    Result<void> unpatch(
        const std::filesystem::path &kimg_path,
        const std::filesystem::path &out_path);

    // Reset superkey
    Result<void> reset_key(
        const std::filesystem::path &kimg_path,
        const std::filesystem::path &out_path,
        const std::string &new_key);

    // Dump kallsyms
    Result<void> dump_kallsyms(const std::filesystem::path &kimg_path);

    // Get patch info
    Result<PatchedKernelInfo> get_patch_info(const std::filesystem::path &kimg_path);

    // Print kpimg info
    Result<void> print_kpimg_info(const std::filesystem::path &kpimg_path);

    // Print patch info
    Result<void> print_patch_info(const std::filesystem::path &kimg_path);

private:
    // Parse patched image info
    Result<PatchedKernelInfo> parse_patch_info(const uint8_t *kimg, size_t len);

    // Get preset from kernel image
    Preset *find_preset(uint8_t *kimg, size_t len);
    const Preset *find_preset(const uint8_t *kimg, size_t len) const;
};

// Utility functions

// Get KP version from kpimg
Result<uint32_t> get_kpimg_version(const std::filesystem::path &path);

// Print preset info
void print_preset_info(const Preset *preset);

} // namespace kernel
} // namespace kp