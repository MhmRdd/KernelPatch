/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "../core/buffer.hpp"
#include "../core/types.hpp"
#include "image.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kp {
namespace kernel {

// Constants

inline constexpr size_t KSYM_TOKEN_NUMS = 256;
inline constexpr size_t KSYM_SYMBOL_LEN = 512;
inline constexpr size_t KSYM_MAX_SYMS = 1000000;
inline constexpr size_t KSYM_MIN_NEQ_SYMS = 25600;
inline constexpr size_t KSYM_MIN_MARKER = KSYM_MIN_NEQ_SYMS / 256;
inline constexpr size_t KSYM_FIND_NAMES_USED_MARKER = 5;
inline constexpr size_t ARM64_RELO_MIN_NUM = 4000;

inline constexpr uint64_t ELF64_KERNEL_MIN_VA = 0xffffff8008080000ULL;
inline constexpr uint64_t ELF64_KERNEL_MAX_VA = 0xffffffffffffffffULL;

// Symbol types

enum class SymbolType : char {
    Absolute = 'A',
    Bss = 'B',
    Data = 'D',
    RoData = 'R',
    Text = 'T',
    WeakObjectDefault = 'V',
    WeakSymbolDefault = 'W',
    SmallData = 'G',
    IndirectFunction = 'I',
    Debugging = 'N',
    StackUnwind = 'P',
    Common = 'C',
    SmallBss = 'S',
    Undefined = 'U',
    UniqueGlobal = 'u',
    WeakObject = 'v',
    WeakSymbol = 'w',
    StabsDebug = '-',
    Unknown = '?',
};

// Current task pointer type (ARM64 specific)

enum class CurrentType {
    SpEl0,  // Current task via SP_EL0
    Sp,     // Current task via SP
};

// Kernel version

struct KernelVersion {
    uint8_t major = 0;
    uint8_t minor = 0;
    uint8_t patch = 0;

    uint32_t to_int() const {
        return (major << 16) | (minor << 8) | patch;
    }

    bool operator>=(const KernelVersion &other) const {
        return to_int() >= other.to_int();
    }

    bool operator<(const KernelVersion &other) const {
        return to_int() < other.to_int();
    }
};

// Symbol information

struct Symbol {
    std::string name;
    char type = '?';
    int32_t offset = 0;
    int32_t size = 0;
    int32_t index = 0;
};

// Kallsyms parser class

class Kallsyms {
public:
    Kallsyms() = default;

    // Parse kallsyms from kernel image buffer
    Result<void> parse(uint8_t *img, size_t imglen);

    // Get symbol offset by name
    std::optional<int32_t> get_offset(std::string_view name) const;

    // Get symbol offset and size by name
    std::optional<Symbol> get_symbol(std::string_view name) const;

    // Get symbol offset by index
    int32_t get_index_offset(int32_t index) const;

    // Dump all symbols to stdout
    void dump_all() const;

    // Check if kernel needs patching (version >= 6.7)
    bool needs_patch() const;

    // Iterate over all symbols
    void for_each_symbol(const std::function<bool(const Symbol &)> &callback) const;

    // Accessors
    const KernelVersion &version() const { return version_; }
    bool is_big_endian() const { return is_be_; }
    bool has_relative_base() const { return has_relative_base_; }
    bool is_absolute_percpu() const { return is_absolute_percpu_; }
    uint64_t kernel_base() const { return kernel_base_; }
    uint64_t relative_base() const { return relative_base_; }
    int32_t num_syms() const { return num_syms_; }
    CurrentType current_type() const { return current_type_; }
    bool is_kallsyms_all() const { return is_kallsyms_all_; }

    // Offset accessors for patching
    int32_t addresses_offset() const { return addresses_offset_; }
    int32_t offsets_offset() const { return offsets_offset_; }
    int32_t names_offset() const { return names_offset_; }
    int32_t markers_offset() const { return markers_offset_; }
    int32_t token_table_offset() const { return token_table_offset_; }
    int32_t token_index_offset() const { return token_index_offset_; }

private:
    // Internal parsing functions
    Result<void> find_linux_banner();
    Result<void> find_token_table();
    Result<void> find_token_index();
    Result<void> try_find_arm64_relo_table();
    Result<void> find_approx_addresses();
    Result<void> find_approx_offsets();
    Result<void> find_approx_addresses_or_offsets();
    Result<void> find_markers();
    Result<void> find_markers_internal(int32_t elem_size);
    Result<void> find_names();
    Result<void> find_num_syms();
    Result<void> correct_addresses_or_offsets();
    Result<void> correct_by_banner();
    Result<void> correct_by_vectors();

    // Helper functions
    int32_t decompress_symbol(int32_t &pos, char *type, std::string &name) const;
    bool is_symbol_name_pos(int32_t pos, std::string_view symbol) const;
    int arm64_verify_pid_vnr(int32_t offset);

    // Endian-aware unpacking
    uint64_t uint_unpack(int32_t offset, int32_t size) const;
    int64_t int_unpack(int32_t offset, int32_t size) const;

    // Size helpers
    int32_t get_markers_elem_size() const;
    int32_t get_num_syms_elem_size() const;
    int32_t get_addresses_elem_size() const { return asm_ptr_size_; }
    int32_t get_offsets_elem_size() const { return asm_long_size_; }

    // Image data (non-owning pointer)
    uint8_t *img_ = nullptr;
    size_t imglen_ = 0;

    // Parsed information
    KernelVersion version_{};
    bool is_be_ = false;
    bool has_relative_base_ = false;
    bool is_absolute_percpu_ = false;  // CONFIG_KALLSYMS_ABSOLUTE_PERCPU
    bool is_kallsyms_all_ = true;
    bool relo_applied_ = false;
    CurrentType current_type_ = CurrentType::SpEl0;

    // Architecture settings
    int32_t asm_long_size_ = 4;
    int32_t asm_ptr_size_ = 8;
    int32_t markers_elem_size_ = 0;

    // Symbol counts
    int32_t num_syms_ = 0;

    // Addresses/offsets
    uint64_t kernel_base_ = 0;
    int32_t addresses_offset_ = 0;
    int32_t offsets_offset_ = 0;

    // Table offsets
    int32_t num_syms_offset_ = 0;
    int32_t names_offset_ = 0;
    int32_t markers_offset_ = 0;
    int32_t token_table_offset_ = 0;
    int32_t token_index_offset_ = 0;

    // Approximate bounds (used during parsing)
    int32_t approx_offset_ = 0;
    int32_t approx_end_ = 0;
    int32_t approx_num_ = 0;
    int32_t marker_num_ = 0;

    // Token table
    const char *token_table_[KSYM_TOKEN_NUMS] = {};

    // Banner information
    int32_t banner_num_ = 0;
    int32_t banner_offsets_[4] = {};
    int32_t symbol_banner_idx_ = -1;
};

// Utility functions

// Extract kernel config (IKCONFIG) if present
Result<std::string> extract_ikconfig(const uint8_t *img, size_t imglen);

} // namespace kernel
} // namespace kp