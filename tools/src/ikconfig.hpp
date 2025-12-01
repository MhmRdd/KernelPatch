/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 *
 * IKCONFIG (kernel .config) finder and extractor.
 * Extracts the embedded kernel configuration from raw kernel images.
 *
 * The kernel stores the config between magic markers:
 *   IKCFG_ST<gzip data>IKCFG_ED
 *
 * See kernel/configs.c for details.
 */

#ifndef KPTOOLS_IKCONFIG_HPP
#define KPTOOLS_IKCONFIG_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <optional>
#include <unordered_map>

namespace kptools {

// Exception for config not found
class IkconfigNotFound : public std::runtime_error {
public:
    explicit IkconfigNotFound(const std::string& msg) : std::runtime_error(msg) {}
};

// Parsed kernel configuration
class KernelConfig {
public:
    KernelConfig() = default;

    // Parse config text (key=value or key is not set format)
    void parse(const std::string& config_text);

    // Get raw config text
    const std::string& raw_text() const { return raw_text_; }

    // Check if a config option is set (CONFIG_FOO=y or CONFIG_FOO=m)
    bool is_set(const std::string& key) const;

    // Check if a config option is enabled (CONFIG_FOO=y)
    bool is_enabled(const std::string& key) const;

    // Check if a config option is a module (CONFIG_FOO=m)
    bool is_module(const std::string& key) const;

    // Get config value (returns empty string if not set)
    std::string get(const std::string& key) const;

    // Get all config entries
    const std::unordered_map<std::string, std::string>& entries() const { return entries_; }

    // Useful config queries for kallsyms
    bool has_kallsyms() const { return is_enabled("CONFIG_KALLSYMS"); }
    bool has_kallsyms_all() const { return is_enabled("CONFIG_KALLSYMS_ALL"); }
    bool has_kallsyms_absolute_percpu() const { return is_enabled("CONFIG_KALLSYMS_ABSOLUTE_PERCPU"); }
    bool has_kallsyms_base_relative() const { return is_enabled("CONFIG_KALLSYMS_BASE_RELATIVE"); }
    bool has_relocatable() const { return is_enabled("CONFIG_RELOCATABLE"); }
    bool has_randomize_base() const { return is_enabled("CONFIG_RANDOMIZE_BASE"); }

private:
    std::string raw_text_;
    std::unordered_map<std::string, std::string> entries_;
};

// IKCONFIG finder and extractor
class IkconfigFinder {
public:
    IkconfigFinder() = default;

    // Find and extract config from kernel image
    // Returns the decompressed config text
    // Throws IkconfigNotFound if not found or decompression fails
    std::string extract(const uint8_t* data, size_t size);

    // Find config location (returns start and end offsets of gzip data)
    // Returns nullopt if not found
    std::optional<std::pair<size_t, size_t>> find(const uint8_t* data, size_t size);

    // Get the raw gzip data (after find() or extract())
    const std::vector<uint8_t>& gzip_data() const { return gzip_data_; }

    // Offsets (valid after find() or extract())
    size_t start_offset() const { return start_offset_; }
    size_t end_offset() const { return end_offset_; }

private:
    // Decompress gzip data
    std::string decompress_gzip(const uint8_t* data, size_t size);

    // Memory search helper
    size_t memfind(const uint8_t* haystack, size_t haystack_len,
                   const uint8_t* needle, size_t needle_len,
                   size_t start = 0);

    std::vector<uint8_t> gzip_data_;
    size_t start_offset_ = 0;
    size_t end_offset_ = 0;
};

} // namespace kptools

#endif // KPTOOLS_IKCONFIG_HPP