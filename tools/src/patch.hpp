/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */
/* Copyright (C) 2025 mhmrdd. All Rights Reserved. */

#pragma once

#include "preset_utils.hpp"
#include "kallsyms.hpp"
#include "image.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
#include <stdexcept>

namespace kptools {

namespace fs = std::filesystem;

class PatchError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class SymbolNotFound : public PatchError {
    std::string sym_;
public:
    explicit SymbolNotFound(const std::string& sym)
        : PatchError("symbol not found: " + sym), sym_(sym) {}
    const std::string& symbol() const { return sym_; }
};

class InvalidKpimg : public PatchError {
public:
    explicit InvalidKpimg(const std::string& msg) : PatchError("invalid kpimg: " + msg) {}
};

class BranchOutOfRange : public PatchError {
    size_t from_, to_;
public:
    BranchOutOfRange(size_t from, size_t to)
        : PatchError("branch out of range"), from_(from), to_(to) {}
    size_t from() const { return from_; }
    size_t to() const { return to_; }
};

struct ExtraItem {
    ExtraType type = EXTRA_TYPE_NONE;
    std::string name;
    std::string event;
    std::string args;
    int32_t priority = 0;
    fs::path path;
    std::vector<uint8_t> data;
    PatchExtraItem header{};
};

struct PatchInfo {
    bool patched = false;
    std::string banner;
    KernelVersion version{};
    size_t original_size = 0;
    std::string kp_version;
    std::string compile_time;
    bool android = false;
    bool debug = false;
    std::string superkey;
    std::vector<PatchExtraItem> extras;
    std::vector<std::pair<std::string, std::string>> metadata;
};

struct PatchOptions {
    fs::path kernel;
    fs::path kpimg;
    fs::path output;
    std::string superkey;
    bool root_key = false;
    std::vector<std::string> metadata;
    std::vector<ExtraItem> extras;
    bool verbose = false;
};

class KernelFile {
    std::vector<uint8_t> data_;
    size_t offset_ = 0;
    bool has_prefix_ = false;

public:
    static KernelFile load(const fs::path& path);
    static KernelFile create(const KernelFile& base, size_t size);

    uint8_t* data() { return data_.data() + offset_; }
    const uint8_t* data() const { return data_.data() + offset_; }
    size_t size() const { return data_.size() - offset_; }

    void resize(size_t n);
    void save(const fs::path& path) const;
    bool has_prefix() const { return has_prefix_; }
};

class Patcher {
    bool verbose_ = false;

    Preset* find_preset(uint8_t* data, size_t size);
    const Preset* find_preset(const uint8_t* data, size_t size) const;
    std::string find_banner(const uint8_t* data, size_t size) const;
    std::vector<std::pair<std::string, std::string>> parse_metadata(const SetupPreset& s) const;

    void fill_map_symbols(KallsymsFinder& k, MapSymbol& m);
    void fill_patch_config(KallsymsFinder& k, PatchConfig& c, bool android);

    std::optional<uint64_t> lookup(KallsymsFinder& k, const std::string& name);
    std::optional<uint64_t> lookup_suffixed(KallsymsFinder& k, const std::string& name);
    uint64_t require(KallsymsFinder& k, const std::string& name);

    // Offset lookup functions (return file offsets, not kernel addresses)
    std::optional<int64_t> lookup_offset(KallsymsFinder& k, const std::string& name);
    std::optional<int64_t> lookup_suffixed_offset(KallsymsFinder& k, const std::string& name);
    int64_t require_offset(KallsymsFinder& k, const std::string& name);

    void check_branch(size_t from, size_t to);
    void log(const char* fmt, ...) const;

public:
    void patch(const PatchOptions& opts);
    void unpatch(const fs::path& input, const fs::path& output);
    PatchInfo info(const fs::path& path);
    void reset_key(const fs::path& input, const fs::path& output, const std::string& key);

    static std::string kpimg_version(const fs::path& path);
    static void kpimg_info(const fs::path& path);
};

const uint8_t* memmem(const uint8_t* h, size_t hl, const void* n, size_t nl);
std::string hexify(const uint8_t* data, size_t len);

} // namespace kptools