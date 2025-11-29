/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "insn.hpp"

namespace kp {
namespace arm64 {

// Relocate instruction from old_pc to new_pc
// Returns relocated instruction, or nullopt if relocation not possible
std::optional<uint32_t> relocate(uint32_t insn, uint64_t old_pc, uint64_t new_pc) {
    // B/BL: 26-bit signed offset
    if (is_branch_imm(insn)) {
        int64_t target = old_pc + get_branch_offset(insn);
        int64_t new_offset = target - new_pc;

        if (!can_branch_imm(new_offset)) {
            return std::nullopt;  // Out of range
        }
        return set_branch_offset(insn, new_offset);
    }

    // B.cond: 19-bit signed offset
    if (is_cond_branch(insn)) {
        int64_t target = old_pc + get_branch_offset(insn);
        int64_t new_offset = target - new_pc;

        // Check 19-bit range: ±1MB
        if (new_offset < -(1LL << 20) || new_offset >= (1LL << 20) || (new_offset & 3)) {
            return std::nullopt;
        }
        return set_branch_offset(insn, new_offset);
    }

    // CBZ/CBNZ: 19-bit signed offset
    if (is_comp_branch(insn)) {
        int64_t target = old_pc + get_branch_offset(insn);
        int64_t new_offset = target - new_pc;

        if (new_offset < -(1LL << 20) || new_offset >= (1LL << 20) || (new_offset & 3)) {
            return std::nullopt;
        }
        return set_branch_offset(insn, new_offset);
    }

    // TBZ/TBNZ: 14-bit signed offset
    if (is_test_branch(insn)) {
        int64_t target = old_pc + get_branch_offset(insn);
        int64_t new_offset = target - new_pc;

        // Check 14-bit range: ±32KB
        if (new_offset < -(1LL << 15) || new_offset >= (1LL << 15) || (new_offset & 3)) {
            return std::nullopt;
        }
        return set_branch_offset(insn, new_offset);
    }

    // ADR: 21-bit signed offset
    if (is_adr(insn)) {
        int64_t target = old_pc + get_adr_offset(insn);
        int64_t new_offset = target - new_pc;

        // Check 21-bit range: ±1MB
        if (new_offset < -(1LL << 20) || new_offset >= (1LL << 20)) {
            return std::nullopt;
        }

        // Encode new offset: immhi (bits 5-23), immlo (bits 29-30)
        uint32_t rd = get_adr_rd(insn);
        int32_t imm = static_cast<int32_t>(new_offset);
        uint32_t immlo = imm & 0x3;
        uint32_t immhi = (imm >> 2) & 0x7FFFF;

        return 0x10000000 | (immlo << 29) | (immhi << 5) | rd;
    }

    // ADRP: 21-bit signed page offset
    if (is_adrp(insn)) {
        // ADRP uses page-aligned addresses
        uint64_t old_page = old_pc & ~0xFFFULL;
        uint64_t target_page = old_page + get_adr_offset(insn);
        uint64_t new_page = new_pc & ~0xFFFULL;
        int64_t new_offset = static_cast<int64_t>(target_page - new_page);

        // Check range: ±4GB (21-bit page offset * 4KB)
        if (new_offset < -(1LL << 32) || new_offset >= (1LL << 32)) {
            return std::nullopt;
        }

        // Encode new offset
        uint32_t rd = get_adr_rd(insn);
        int32_t imm = static_cast<int32_t>(new_offset >> 12);
        uint32_t immlo = imm & 0x3;
        uint32_t immhi = (imm >> 2) & 0x7FFFF;

        return 0x90000000 | (immlo << 29) | (immhi << 5) | rd;
    }

    // LDR (literal): 19-bit signed offset
    if (is_ldr_literal(insn)) {
        int64_t target = old_pc + get_ldr_literal_offset(insn);
        int64_t new_offset = target - new_pc;

        // Check 19-bit range: ±1MB
        if (new_offset < -(1LL << 20) || new_offset >= (1LL << 20) || (new_offset & 3)) {
            return std::nullopt;
        }

        // Encode new offset in bits 5-23
        uint32_t imm19 = (static_cast<uint32_t>(new_offset >> 2)) & 0x7FFFF;
        return (insn & ~(0x7FFFF << 5)) | (imm19 << 5);
    }

    // Instruction doesn't need relocation (not PC-relative)
    return insn;
}

// Follow a chain of branches to find the final target
// Returns the final offset from the start of img
int32_t follow_branch(const uint8_t *img, int32_t offset) {
    constexpr int MAX_CHAIN = 32;  // Prevent infinite loops

    for (int i = 0; i < MAX_CHAIN; ++i) {
        uint32_t insn = *reinterpret_cast<const uint32_t *>(img + offset);

        // Only follow unconditional branches (B), not BL
        if (!is_branch(insn)) {
            break;
        }

        int64_t branch_offset = get_branch_offset(insn);
        offset += static_cast<int32_t>(branch_offset);
    }

    return offset;
}

} // namespace arm64
} // namespace kp