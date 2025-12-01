/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */

#pragma once

#include <cstdint>
#include <stdexcept>

namespace kptools {
namespace arm64 {

constexpr int64_t kBranchRange = 128 * 1024 * 1024;  // ±128 MB

constexpr uint32_t kNop = 0xD503201F;
constexpr uint32_t kAutiasp = 0xD50323BF;
constexpr uint32_t kAutibsp = 0xD50323FF;
constexpr uint32_t kPaciasp = 0xD503233F;
constexpr uint32_t kPacibsp = 0xD503237F;

constexpr bool is_branch(uint32_t i) { return (i & 0xFC000000) == 0x14000000; }
constexpr bool is_bl(uint32_t i) { return (i & 0xFC000000) == 0x94000000; }
constexpr bool is_branch_imm(uint32_t i) { return (i & 0x7C000000) == 0x14000000; }
constexpr bool is_bcond(uint32_t i) { return (i & 0xFF000010) == 0x54000000; }
constexpr bool is_cbz(uint32_t i) { return (i & 0x7E000000) == 0x34000000; }
constexpr bool is_tbz(uint32_t i) { return (i & 0x7E000000) == 0x36000000; }
constexpr bool is_br(uint32_t i) { return (i & 0xFE000000) == 0xD6000000; }
constexpr bool is_ret(uint32_t i) { return (i & 0xFFFFFC1F) == 0xD65F0000; }
constexpr bool is_nop(uint32_t i) { return i == kNop; }
constexpr bool is_hint(uint32_t i) { return (i & 0xFFFFF01F) == 0xD503201F; }
constexpr bool is_pac(uint32_t i) { return i == kAutiasp || i == kAutibsp || i == kPaciasp || i == kPacibsp; }
constexpr bool is_adr(uint32_t i) { return (i & 0x9F000000) == 0x10000000; }
constexpr bool is_adrp(uint32_t i) { return (i & 0x9F000000) == 0x90000000; }
constexpr bool is_ldr_lit(uint32_t i) { return (i & 0x3B000000) == 0x18000000; }

constexpr int64_t branch_offset(uint32_t i) {
    if (is_branch_imm(i)) {
        int32_t imm = i & 0x03FFFFFF;
        if (imm & 0x02000000) imm |= 0xFC000000;
        return static_cast<int64_t>(imm) << 2;
    }
    if (is_bcond(i) || is_cbz(i)) {
        int32_t imm = (i >> 5) & 0x7FFFF;
        if (imm & 0x40000) imm |= 0xFFF80000;
        return static_cast<int64_t>(imm) << 2;
    }
    if (is_tbz(i)) {
        int32_t imm = (i >> 5) & 0x3FFF;
        if (imm & 0x2000) imm |= 0xFFFFC000;
        return static_cast<int64_t>(imm) << 2;
    }
    return 0;
}

constexpr bool can_encode(int64_t off) {
    return off >= -kBranchRange && off < kBranchRange && (off & 3) == 0;
}

constexpr bool can_branch(uint64_t from, uint64_t to) {
    return can_encode(static_cast<int64_t>(to) - static_cast<int64_t>(from));
}

inline uint32_t encode_b(int64_t off) {
    if (!can_encode(off)) throw std::out_of_range("branch offset out of range");
    return 0x14000000 | ((static_cast<uint32_t>(off >> 2)) & 0x03FFFFFF);
}

inline uint32_t encode_bl(int64_t off) {
    if (!can_encode(off)) throw std::out_of_range("branch offset out of range");
    return 0x94000000 | ((static_cast<uint32_t>(off >> 2)) & 0x03FFFFFF);
}

inline uint32_t encode_branch(uint64_t from, uint64_t to) {
    return encode_b(static_cast<int64_t>(to) - static_cast<int64_t>(from));
}

inline uint32_t encode_branch_link(uint64_t from, uint64_t to) {
    return encode_bl(static_cast<int64_t>(to) - static_cast<int64_t>(from));
}

constexpr uint32_t patch_branch_off(uint32_t i, int64_t off) {
    if (is_branch_imm(i))
        return (i & 0xFC000000) | ((static_cast<uint32_t>(off >> 2)) & 0x03FFFFFF);
    if (is_bcond(i) || is_cbz(i))
        return (i & 0xFF00001F) | (((static_cast<uint32_t>(off >> 2)) & 0x7FFFF) << 5);
    if (is_tbz(i))
        return (i & 0xFFF8001F) | (((static_cast<uint32_t>(off >> 2)) & 0x3FFF) << 5);
    return i;
}

constexpr uint32_t movz(uint32_t rd, uint16_t imm, uint32_t sh = 0, bool x = true) {
    return (x ? 0x80000000u : 0u) | 0x52800000 | ((sh / 16) << 21) | (uint32_t(imm) << 5) | rd;
}

constexpr uint32_t movk(uint32_t rd, uint16_t imm, uint32_t sh = 0, bool x = true) {
    return (x ? 0x80000000u : 0u) | 0x72800000 | ((sh / 16) << 21) | (uint32_t(imm) << 5) | rd;
}

inline void mov_imm64(uint32_t* buf, uint32_t rd, uint64_t imm) {
    buf[0] = movz(rd, imm & 0xFFFF, 0);
    buf[1] = movk(rd, (imm >> 16) & 0xFFFF, 16);
    buf[2] = movk(rd, (imm >> 32) & 0xFFFF, 32);
    buf[3] = movk(rd, (imm >> 48) & 0xFFFF, 48);
}

constexpr uint32_t br(uint32_t rn) { return 0xD61F0000 | (rn << 5); }
constexpr uint32_t blr(uint32_t rn) { return 0xD63F0000 | (rn << 5); }
constexpr uint32_t ret(uint32_t rn = 30) { return 0xD65F0000 | (rn << 5); }
constexpr uint32_t svc(uint16_t imm) { return 0xD4000001 | (uint32_t(imm) << 5); }

inline int64_t follow_branches(const uint8_t* data, size_t size, size_t off) {
    size_t cur = off;
    for (int n = 0; n < 100 && cur + 4 <= size; ++n) {
        uint32_t i = *reinterpret_cast<const uint32_t*>(data + cur);
        if (!is_branch(i)) break;
        int64_t target = static_cast<int64_t>(cur) + branch_offset(i);
        if (target < 0 || size_t(target) >= size) break;
        cur = size_t(target);
    }
    return static_cast<int64_t>(cur) - static_cast<int64_t>(off);
}

inline size_t branch_target(size_t off, uint32_t i) {
    return size_t(int64_t(off) + branch_offset(i));
}

inline size_t skip_pac(const uint8_t* data, size_t size, size_t off) {
    while (off + 4 <= size && is_pac(*reinterpret_cast<const uint32_t*>(data + off)))
        off += 4;
    return off;
}

} // namespace arm64
} // namespace kptools