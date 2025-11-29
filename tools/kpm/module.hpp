/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "../core/buffer.hpp"
#include "../core/types.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

namespace kp {
namespace kpm {

// ELF64 structures (minimal definitions for KPM parsing)

#pragma pack(push, 1)

// ELF identification
inline constexpr char ELFMAG[] = "\x7f" "ELF";
inline constexpr size_t SELFMAG = 4;
inline constexpr uint16_t EM_AARCH64 = 183;
inline constexpr uint16_t ET_REL = 1;  // Relocatable file

// Section types
inline constexpr uint32_t SHT_NULL = 0;
inline constexpr uint32_t SHT_PROGBITS = 1;
inline constexpr uint32_t SHT_SYMTAB = 2;
inline constexpr uint32_t SHT_STRTAB = 3;
inline constexpr uint32_t SHT_RELA = 4;
inline constexpr uint32_t SHT_NOBITS = 8;

// Section flags
inline constexpr uint64_t SHF_ALLOC = 0x2;

// ELF64 header
struct Elf64_Ehdr {
    uint8_t e_ident[16];    // ELF identification
    uint16_t e_type;        // Object file type
    uint16_t e_machine;     // Machine type
    uint32_t e_version;     // Object file version
    uint64_t e_entry;       // Entry point address
    uint64_t e_phoff;       // Program header offset
    uint64_t e_shoff;       // Section header offset
    uint32_t e_flags;       // Processor-specific flags
    uint16_t e_ehsize;      // ELF header size
    uint16_t e_phentsize;   // Program header entry size
    uint16_t e_phnum;       // Number of program headers
    uint16_t e_shentsize;   // Section header entry size
    uint16_t e_shnum;       // Number of section headers
    uint16_t e_shstrndx;    // Section name string table index
};

// ELF64 section header
struct Elf64_Shdr {
    uint32_t sh_name;       // Section name (string table index)
    uint32_t sh_type;       // Section type
    uint64_t sh_flags;      // Section flags
    uint64_t sh_addr;       // Virtual address
    uint64_t sh_offset;     // File offset
    uint64_t sh_size;       // Section size
    uint32_t sh_link;       // Link to another section
    uint32_t sh_info;       // Additional section information
    uint64_t sh_addralign;  // Section alignment
    uint64_t sh_entsize;    // Entry size if section holds table
};

#pragma pack(pop)

// KPM module information

struct ModuleInfo {
    std::string name;
    std::string version;
    std::string license;
    std::string author;
    std::string description;

    void print() const;
};

// KPM module class

class Module {
    Buffer data_;
    ModuleInfo info_;
    bool parsed_ = false;

public:
    Module() = default;

    // Load from file
    static Result<Module> from_file(const std::filesystem::path &path);

    // Load from buffer
    static Result<Module> from_buffer(Buffer buf);

    // Parse and extract info
    Result<void> parse();

    // Accessors
    const ModuleInfo &info() const { return info_; }
    const Buffer &data() const { return data_; }
    bool parsed() const { return parsed_; }

    // Validation
    static bool is_valid_kpm(const uint8_t *data, size_t len);
    bool is_valid() const { return is_valid_kpm(data_.data(), data_.size()); }

private:
    // ELF parsing helpers
    const Elf64_Ehdr *elf_header() const;
    const Elf64_Shdr *section_headers() const;
    const char *section_strings() const;

    // Find section by name
    std::optional<size_t> find_section(std::string_view name) const;

    // Get section data
    std::pair<const uint8_t *, size_t> get_section_data(size_t idx) const;

    // Parse modinfo strings
    std::optional<std::string_view> get_modinfo(std::string_view tag) const;

    // Info section data
    const uint8_t *info_data_ = nullptr;
    size_t info_size_ = 0;
};

// Constants

inline constexpr const char *KPM_INFO_SECTION = ".kpm.info";
inline constexpr const char *INFO_EXTRA_KPM_SESSION = "[kpm]";

} // namespace kpm
} // namespace kp