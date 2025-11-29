/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "image.hpp"
#include "../core/file.hpp"
#include "../core/logging.hpp"
#include <cstring>

namespace kp::kernel {

Result<Image> Image::from_file(const std::filesystem::path &path) {
    auto buf_result = Buffer::from_file(path);
    if (!buf_result) return Result<Image>::Err(buf_result.error());
    return from_buffer(std::move(buf_result).unwrap());
}

Result<Image> Image::from_buffer(Buffer buf) {
    Image img;
    img.data_ = std::move(buf);
    auto parse_result = img.parse();
    if (!parse_result) return Result<Image>::Err(parse_result.error());
    return Result<Image>::Ok(std::move(img));
}

Result<void> Image::parse() {
    if (data_.size() < sizeof(Arm64Header))
        return Result<void>::Err("Kernel image too small");

    const auto *hdr = header();

    if (endian::from_le(hdr->magic) != ARM64_MAGIC)
        return Result<void>::Err("Invalid kernel magic (expected ARM\\x64)");

    uint16_t mz_sig = static_cast<uint16_t>(hdr->efi.mz[0]) | (static_cast<uint16_t>(hdr->efi.mz[1]) << 8);
    info_.has_uefi = (mz_sig == EFI_MAGIC);

    uint32_t branch_insn;
    if (info_.has_uefi) {
        branch_insn = endian::from_le(hdr->efi.branch_insn);
        info_.branch_offset = 4;
    } else {
        branch_insn = endian::from_le(hdr->plain.branch_insn);
        info_.branch_offset = 0;
    }

    if (!arm64::is_branch(branch_insn))
        return Result<void>::Err("Invalid kernel entry branch instruction");

    info_.entry_offset = info_.branch_offset + static_cast<int32_t>(arm64::get_branch_offset(branch_insn));
    info_.load_offset = static_cast<int32_t>(endian::from_le(hdr->kernel_offset));
    info_.kernel_size = static_cast<int32_t>(endian::from_le(hdr->kernel_size));

    uint64_t flags_val = endian::from_le(hdr->kernel_flags);
    uint8_t flags = flags_val & 0x0F;

    info_.is_big_endian = (flags & flags::ENDIAN_BE) != 0;
    if (info_.is_big_endian)
        return Result<void>::Err("Big endian kernel images not supported");

    uint8_t page_bits = (flags & flags::PAGE_SIZE_MASK) >> 1;
    switch (page_bits) {
        case 2: info_.page_shift = 14; break;  // 16K
        case 3: info_.page_shift = 16; break;  // 64K
        default: info_.page_shift = 12; break; // 4K
    }

    parsed_ = true;

    kp_log_info("kernel image_size: 0x%08zx\n", data_.size());
    kp_log_info("kernel uefi header: %s\n", info_.has_uefi ? "true" : "false");
    kp_log_info("kernel load_offset: 0x%08x\n", info_.load_offset);
    kp_log_info("kernel kernel_size: 0x%08x\n", info_.kernel_size);
    kp_log_info("kernel page_shift: %d\n", info_.page_shift);

    return Result<void>::Ok();
}

void Image::set_kernel_size(int64_t size) {
    auto *hdr = header();
    hdr->kernel_size = endian::to_le(static_cast<uint64_t>(size));
    info_.kernel_size = static_cast<int32_t>(size);
}

bool Image::is_valid_arm64_kernel(const uint8_t *data, size_t len) {
    if (len < sizeof(Arm64Header)) return false;

    const auto *hdr = reinterpret_cast<const Arm64Header *>(data);
    if (endian::from_le(hdr->magic) != ARM64_MAGIC) return false;

    uint16_t mz_sig = static_cast<uint16_t>(hdr->efi.mz[0]) | (static_cast<uint16_t>(hdr->efi.mz[1]) << 8);
    bool has_uefi = (mz_sig == EFI_MAGIC);
    uint32_t branch_insn = has_uefi ? endian::from_le(hdr->efi.branch_insn) : endian::from_le(hdr->plain.branch_insn);

    return arm64::is_branch(branch_insn);
}

} // namespace kp::kernel