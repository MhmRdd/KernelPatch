/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */
/* Copyright (C) 2024 Yervant7. All Rights Reserved. */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <stdexcept>

namespace ktool {

enum class SymbolType : char {
    Absolute = 'A',
    Bss = 'B',
    Data = 'D',
    RoData = 'R',
    Text = 'T',
    WeakObjectWithDefault = 'V',
    WeakSymbolWithDefault = 'W',
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

struct KernelVersion {
    int major = 0;
    int minor = 0;
    int patch = 0;

    bool operator>=(const KernelVersion& other) const {
        if (major != other.major) return major > other.major;
        if (minor != other.minor) return minor > other.minor;
        return patch >= other.patch;
    }

    bool operator<(const KernelVersion& other) const {
        return !(*this >= other);
    }
};

struct Symbol {
    std::string name;
    uint64_t address = 0;
    char type = '?';
    bool is_global = false;
};

class KallsymsNotFound : public std::runtime_error {
public:
    explicit KallsymsNotFound(const std::string& msg) : std::runtime_error(msg) {}
};

class KallsymsFinder {
public:
    KallsymsFinder() = default;

    void parse(const uint8_t* data, size_t size, int bit_size = 0,
               bool use_absolute = false, uint64_t base_address = 0);

    const KernelVersion& version() const { return version_; }
    const std::string& version_string() const { return version_string_; }

    bool is_64_bits() const { return is_64_bits_; }
    bool is_big_endian() const { return is_big_endian_; }

    bool has_relative_base() const { return has_relative_base_; }
    bool has_absolute_percpu() const { return has_absolute_percpu_; }
    uint64_t relative_base_address() const { return relative_base_address_; }

    // Returns the kernel base address used for converting symbol addresses to file offsets
    uint64_t kernel_base() const {
        return has_relative_base_ ? relative_base_address_ : kernel_base_;
    }

    // Convert a kernel symbol address to a file offset
    int64_t address_to_offset(uint64_t addr) const {
        return static_cast<int64_t>(addr - kernel_base());
    }

    size_t num_symbols() const { return num_symbols_; }
    const std::vector<Symbol>& symbols() const { return symbols_; }

    std::optional<Symbol> find_symbol(std::string_view name) const;
    void for_each_symbol(const std::function<bool(const Symbol&)>& callback) const;
    void print_symbols() const;

    size_t token_table_offset() const { return token_table_offset_; }
    size_t token_index_offset() const { return token_index_offset_; }
    size_t markers_offset() const { return markers_offset_; }
    size_t names_offset() const { return names_offset_; }
    size_t num_syms_offset() const { return num_syms_offset_; }
    size_t addresses_offset() const { return addresses_offset_; }

private:
    void find_linux_banner();
    void guess_architecture();
    void find_elf_relocations();
    void apply_relocations();
    void find_token_table();
    void find_token_index();
    void find_markers();
    void find_names();
    void find_num_syms();
    void find_addresses_or_offsets();
    void parse_symbol_table();

    uint64_t read_int(size_t offset, int size) const;
    int64_t read_signed_int(size_t offset, int size) const;

    size_t mem_find(const uint8_t* needle, size_t needle_len,
                    size_t start = 0, size_t end = 0) const;
    size_t mem_rfind(const uint8_t* needle, size_t needle_len,
                     size_t start = 0, size_t end = 0) const;

    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    std::vector<uint8_t> data_copy_;

    KernelVersion version_{};
    std::string version_string_;

    bool is_64_bits_ = true;
    bool is_big_endian_ = false;
    int offset_table_element_size_ = 4;

    struct Rela {
        uint64_t offset;
        uint64_t info;
        uint64_t addend;
    };
    std::vector<Rela> relocations_;
    size_t rela_start_ = 0;
    size_t rela_end_ = 0;
    uint64_t kernel_base_ = 0;

    size_t token_table_offset_ = 0;
    size_t token_index_offset_ = 0;
    size_t token_index_end_offset_ = 0;
    size_t markers_offset_ = 0;
    size_t names_offset_ = 0;
    size_t num_syms_offset_ = 0;
    size_t addresses_offset_ = 0;

    size_t num_symbols_ = 0;
    bool has_relative_base_ = false;
    bool has_absolute_percpu_ = false;
    uint64_t relative_base_address_ = 0;

    std::vector<std::string> token_table_;
    std::vector<std::string> symbol_names_;
    std::vector<uint64_t> symbol_addresses_;
    std::vector<Symbol> symbols_;

    bool use_absolute_ = false;
    uint64_t forced_base_address_ = 0;
};

} // namespace ktool