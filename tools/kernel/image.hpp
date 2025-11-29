/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "../core/buffer.hpp"
#include "../core/types.hpp"
#include "../arm64/insn.hpp"
#include <cstdint>

namespace kp::kernel {

// ARM64 kernel image header (from arch/arm64/kernel/head.S)
#pragma pack(push, 1)
struct Arm64Header {
    union {
        struct { uint8_t mz[4]; uint32_t branch_insn; } efi;     // With EFI stub
        struct { uint32_t branch_insn; uint32_t reserved0; } plain; // Without EFI
    };
    uint64_t kernel_offset;
    uint64_t kernel_size;
    uint64_t kernel_flags;
    uint64_t reserved0;
    uint64_t reserved1;
    uint64_t reserved2;
    uint32_t magic;         // "ARM\x64"
    uint32_t pe_offset;
};
static_assert(sizeof(Arm64Header) == 64);
#pragma pack(pop)

struct KernelInfo {
    bool is_big_endian = false;
    bool has_uefi = false;
    int32_t load_offset = 0;
    int32_t kernel_size = 0;
    int32_t page_shift = 12;
    int32_t branch_offset = 0;
    int32_t entry_offset = 0;
    size_t page_size() const { return 1ULL << page_shift; }
};

class Image {
    Buffer data_;
    KernelInfo info_;
    bool parsed_ = false;

public:
    Image() = default;
    static Result<Image> from_file(const std::filesystem::path &path);
    static Result<Image> from_buffer(Buffer buf);
    Result<void> parse();

    const KernelInfo &info() const { return info_; }
    const Buffer &data() const { return data_; }
    Buffer &data() { return data_; }
    size_t size() const { return data_.size(); }
    bool parsed() const { return parsed_; }

    Arm64Header *header() { return data_.ptr_at<Arm64Header>(0); }
    const Arm64Header *header() const { return data_.ptr_at<Arm64Header>(0); }

    template<typename T> T read_at(size_t offset) const { return data_.read_at<T>(offset); }
    template<typename T> void write_at(size_t offset, T value) { data_.write_at(offset, value); }

    uint32_t insn_at(size_t offset) const { return endian::read_le<uint32_t>(data_.data() + offset); }
    void set_kernel_size(int64_t size);
    void resize(size_t new_size) { data_.resize(new_size); }
    Result<void> to_file(const std::filesystem::path &path) const { return data_.to_file(path); }

    static bool is_valid_arm64_kernel(const uint8_t *data, size_t len);
    bool is_valid() const { return is_valid_arm64_kernel(data_.data(), data_.size()); }
};

inline constexpr uint32_t ARM64_MAGIC = 0x644D5241; // "ARM\x64" LE
inline constexpr uint16_t EFI_MAGIC = 0x5A4D;       // "MZ" LE

namespace flags {
    inline constexpr uint64_t ENDIAN_BE = 0x01;
    inline constexpr uint64_t PAGE_SIZE_MASK = 0x06;
}

} // namespace kp::kernel