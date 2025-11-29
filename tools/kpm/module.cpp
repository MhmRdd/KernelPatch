/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "module.hpp"
#include "../core/file.hpp"
#include "../core/logging.hpp"

#include <cstring>

namespace kp {
namespace kpm {

// ModuleInfo

void ModuleInfo::print() const {
    std::fprintf(stdout, "name=%s\n", name.c_str());
    std::fprintf(stdout, "version=%s\n", version.c_str());
    std::fprintf(stdout, "license=%s\n", license.c_str());
    std::fprintf(stdout, "author=%s\n", author.c_str());
    std::fprintf(stdout, "description=%s\n", description.c_str());
}

// Module loading

Result<Module> Module::from_file(const std::filesystem::path &path) {
    auto buf_result = Buffer::from_file(path);
    if (!buf_result) {
        return Result<Module>::Err(buf_result.error());
    }
    return from_buffer(std::move(buf_result).unwrap());
}

Result<Module> Module::from_buffer(Buffer buf) {
    Module mod;
    mod.data_ = std::move(buf);

    auto parse_result = mod.parse();
    if (!parse_result) {
        return Result<Module>::Err(parse_result.error());
    }

    return Result<Module>::Ok(std::move(mod));
}

// ELF parsing helpers

const Elf64_Ehdr *Module::elf_header() const {
    return reinterpret_cast<const Elf64_Ehdr *>(data_.data());
}

const Elf64_Shdr *Module::section_headers() const {
    const auto *ehdr = elf_header();
    return reinterpret_cast<const Elf64_Shdr *>(data_.data() + ehdr->e_shoff);
}

const char *Module::section_strings() const {
    const auto *ehdr = elf_header();
    const auto *shdrs = section_headers();
    return reinterpret_cast<const char *>(
        data_.data() + shdrs[ehdr->e_shstrndx].sh_offset);
}

std::optional<size_t> Module::find_section(std::string_view name) const {
    const auto *ehdr = elf_header();
    const auto *shdrs = section_headers();
    const char *strings = section_strings();

    for (uint16_t i = 1; i < ehdr->e_shnum; ++i) {
        const auto &shdr = shdrs[i];
        if ((shdr.sh_flags & SHF_ALLOC) == 0) continue;

        const char *sec_name = strings + shdr.sh_name;
        if (name == sec_name) {
            return i;
        }
    }
    return std::nullopt;
}

std::pair<const uint8_t *, size_t> Module::get_section_data(size_t idx) const {
    const auto *shdrs = section_headers();
    const auto &shdr = shdrs[idx];
    return {data_.data() + shdr.sh_offset, static_cast<size_t>(shdr.sh_size)};
}

// Modinfo parsing

std::optional<std::string_view> Module::get_modinfo(std::string_view tag) const {
    if (!info_data_ || info_size_ == 0) {
        return std::nullopt;
    }

    const char *p = reinterpret_cast<const char *>(info_data_);
    const char *end = p + info_size_;

    while (p < end) {
        // Skip null bytes
        while (p < end && *p == '\0') ++p;
        if (p >= end) break;

        // Find end of string
        const char *str_end = p;
        while (str_end < end && *str_end != '\0') ++str_end;

        std::string_view entry(p, str_end - p);

        // Check if this entry matches "tag=value"
        if (entry.size() > tag.size() && entry[tag.size()] == '=' &&
            entry.substr(0, tag.size()) == tag) {
            return entry.substr(tag.size() + 1);
        }

        p = str_end;
    }

    return std::nullopt;
}

// Parsing

Result<void> Module::parse() {
    if (data_.size() <= sizeof(Elf64_Ehdr)) {
        return Result<void>::Err("KPM file too small");
    }

    const auto *ehdr = elf_header();

    // Verify ELF magic
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return Result<void>::Err("Invalid ELF magic");
    }

    // Verify it's a relocatable file
    if (ehdr->e_type != ET_REL) {
        return Result<void>::Err("KPM must be relocatable (ET_REL)");
    }

    // Verify architecture
    if (ehdr->e_machine != EM_AARCH64) {
        return Result<void>::Err("KPM must be ARM64");
    }

    // Verify section header size
    if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        return Result<void>::Err("Invalid section header size");
    }

    // Verify section header table bounds
    if (ehdr->e_shoff >= data_.size() ||
        ehdr->e_shnum * sizeof(Elf64_Shdr) > data_.size() - ehdr->e_shoff) {
        return Result<void>::Err("Section header table out of bounds");
    }

    // Verify all sections are within file bounds
    const auto *shdrs = section_headers();
    for (uint16_t i = 1; i < ehdr->e_shnum; ++i) {
        const auto &shdr = shdrs[i];
        if (shdr.sh_type != SHT_NOBITS &&
            data_.size() < shdr.sh_offset + shdr.sh_size) {
            return Result<void>::Err("Section data out of bounds");
        }
    }

    // Find .kpm.info section
    auto info_idx = find_section(KPM_INFO_SECTION);
    if (!info_idx) {
        return Result<void>::Err("No .kpm.info section found");
    }

    // Get info section data
    auto [data, size] = get_section_data(*info_idx);
    info_data_ = data;
    info_size_ = size;

    // Extract module info
    auto get_or_empty = [this](std::string_view tag) -> std::string {
        auto val = get_modinfo(tag);
        return val ? std::string(*val) : std::string();
    };

    info_.name = get_or_empty("name");
    info_.version = get_or_empty("version");
    info_.license = get_or_empty("license");
    info_.author = get_or_empty("author");
    info_.description = get_or_empty("description");

    parsed_ = true;

    kp_log_info("KPM: %s %s by %s\n",
                info_.name.c_str(), info_.version.c_str(), info_.author.c_str());

    return Result<void>::Ok();
}

// Validation

bool Module::is_valid_kpm(const uint8_t *data, size_t len) {
    if (len <= sizeof(Elf64_Ehdr)) {
        return false;
    }

    const auto *ehdr = reinterpret_cast<const Elf64_Ehdr *>(data);

    // Check ELF magic
    if (std::memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return false;
    }

    // Check it's relocatable
    if (ehdr->e_type != ET_REL) {
        return false;
    }

    // Check architecture
    if (ehdr->e_machine != EM_AARCH64) {
        return false;
    }

    return true;
}

} // namespace kpm
} // namespace kp