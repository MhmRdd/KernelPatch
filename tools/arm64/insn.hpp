/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "../core/types.hpp"

#include <cstdint>
#include <optional>

namespace kp {
namespace arm64 {

// Instruction classification

enum class InsnClass {
    Unknown,
    Branch,           // B
    BranchLink,       // BL
    BranchReg,        // BR, BLR, RET
    CondBranch,       // B.cond
    CompBranch,       // CBZ, CBNZ
    TestBranch,       // TBZ, TBNZ
    Adr,              // ADR
    Adrp,             // ADRP
    LoadLiteral,      // LDR (literal)
    LoadStorePair,    // LDP, STP
    LoadStoreReg,     // LDR, STR (register)
    MovWide,          // MOVZ, MOVN, MOVK
    AddSubImm,        // ADD, SUB (immediate)
    LogicalImm,       // AND, ORR, EOR (immediate)
    DataProc,         // Other data processing
    System,           // System instructions
    Hint,             // HINT (NOP, etc.)
    Exception,        // SVC, HVC, SMC, BRK
    Nop,              // NOP
};

// Classify an instruction
constexpr InsnClass classify(uint32_t insn) {
    // NOP: 0xD503201F
    if (insn == 0xD503201F) return InsnClass::Nop;

    // HINT: 0xD503201F mask 0xFFFFF01F
    if ((insn & 0xFFFFF01F) == 0xD503201F) return InsnClass::Hint;

    // Extract major opcode groups
    uint32_t op0 = (insn >> 25) & 0xF;

    // Branch, exception, system
    if ((op0 & 0xE) == 0xA) {
        // Unconditional branch (immediate)
        if ((insn & 0x7C000000) == 0x14000000) {
            return (insn & 0x80000000) ? InsnClass::BranchLink : InsnClass::Branch;
        }

        // Conditional branch
        if ((insn & 0xFF000010) == 0x54000000) return InsnClass::CondBranch;

        // Compare and branch
        if ((insn & 0x7E000000) == 0x34000000) return InsnClass::CompBranch;

        // Test and branch
        if ((insn & 0x7E000000) == 0x36000000) return InsnClass::TestBranch;

        // Unconditional branch (register)
        if ((insn & 0xFE000000) == 0xD6000000) return InsnClass::BranchReg;

        // Exception generation
        if ((insn & 0xFF000000) == 0xD4000000) return InsnClass::Exception;

        // System
        if ((insn & 0xFFC00000) == 0xD5000000) return InsnClass::System;
    }

    // Data processing - immediate
    if ((op0 & 0xE) == 0x8) {
        // PC-relative addressing
        if ((insn & 0x1F000000) == 0x10000000) {
            return (insn & 0x80000000) ? InsnClass::Adrp : InsnClass::Adr;
        }

        // Add/subtract (immediate)
        if ((insn & 0x1F000000) == 0x11000000) return InsnClass::AddSubImm;

        // Logical (immediate)
        if ((insn & 0x1F800000) == 0x12000000) return InsnClass::LogicalImm;

        // Move wide (immediate)
        if ((insn & 0x1F800000) == 0x12800000) return InsnClass::MovWide;
    }

    // Loads and stores
    if ((op0 & 0x5) == 0x4) {
        // Load literal
        if ((insn & 0x3B000000) == 0x18000000) return InsnClass::LoadLiteral;

        // Load/store pair
        if ((insn & 0x3A000000) == 0x28000000) return InsnClass::LoadStorePair;

        // Other load/store
        return InsnClass::LoadStoreReg;
    }

    // Data processing - register
    if ((op0 & 0x7) == 0x5) return InsnClass::DataProc;

    return InsnClass::Unknown;
}

// Branch instructions

// Check if instruction is a branch with immediate offset
constexpr bool is_branch_imm(uint32_t insn) {
    return (insn & 0x7C000000) == 0x14000000;  // B or BL
}

constexpr bool is_branch(uint32_t insn) {
    return (insn & 0xFC000000) == 0x14000000;  // B
}

constexpr bool is_branch_link(uint32_t insn) {
    return (insn & 0xFC000000) == 0x94000000;  // BL
}

constexpr bool is_cond_branch(uint32_t insn) {
    return (insn & 0xFF000010) == 0x54000000;  // B.cond
}

constexpr bool is_comp_branch(uint32_t insn) {
    return (insn & 0x7E000000) == 0x34000000;  // CBZ, CBNZ
}

constexpr bool is_test_branch(uint32_t insn) {
    return (insn & 0x7E000000) == 0x36000000;  // TBZ, TBNZ
}

constexpr bool is_ret(uint32_t insn) {
    return (insn & 0xFFFFFC1F) == 0xD65F0000;  // RET
}

constexpr bool is_branch_reg(uint32_t insn) {
    return (insn & 0xFE000000) == 0xD6000000;  // BR, BLR, RET
}

// Check if any type of branch
constexpr bool is_any_branch(uint32_t insn) {
    return is_branch_imm(insn) || is_cond_branch(insn) || is_comp_branch(insn) ||
           is_test_branch(insn) || is_branch_reg(insn);
}

// Get branch offset (signed, in bytes)
constexpr int64_t get_branch_offset(uint32_t insn) {
    if (is_branch_imm(insn)) {
        // 26-bit signed offset * 4
        int32_t imm26 = insn & 0x03FFFFFF;
        if (imm26 & 0x02000000) imm26 |= 0xFC000000;  // Sign extend
        return static_cast<int64_t>(imm26) << 2;
    }
    if (is_cond_branch(insn)) {
        // 19-bit signed offset * 4
        int32_t imm19 = (insn >> 5) & 0x7FFFF;
        if (imm19 & 0x40000) imm19 |= 0xFFF80000;  // Sign extend
        return static_cast<int64_t>(imm19) << 2;
    }
    if (is_comp_branch(insn)) {
        // 19-bit signed offset * 4
        int32_t imm19 = (insn >> 5) & 0x7FFFF;
        if (imm19 & 0x40000) imm19 |= 0xFFF80000;
        return static_cast<int64_t>(imm19) << 2;
    }
    if (is_test_branch(insn)) {
        // 14-bit signed offset * 4
        int32_t imm14 = (insn >> 5) & 0x3FFF;
        if (imm14 & 0x2000) imm14 |= 0xFFFFC000;
        return static_cast<int64_t>(imm14) << 2;
    }
    return 0;
}

// Check if distance can be encoded in a B/BL instruction
constexpr bool can_branch_imm(int64_t offset) {
    return offset >= -(1LL << 27) && offset < (1LL << 27) && (offset & 3) == 0;
}

constexpr bool can_branch_imm(uint64_t from, uint64_t to) {
    return can_branch_imm(static_cast<int64_t>(to - from));
}

// Generate branch instructions
constexpr uint32_t make_branch(int64_t offset) {
    return 0x14000000 | ((static_cast<uint32_t>(offset >> 2)) & 0x03FFFFFF);
}

constexpr uint32_t make_branch_link(int64_t offset) {
    return 0x94000000 | ((static_cast<uint32_t>(offset >> 2)) & 0x03FFFFFF);
}

constexpr uint32_t make_branch_to(uint64_t from, uint64_t to) {
    return make_branch(static_cast<int64_t>(to - from));
}

constexpr uint32_t make_branch_link_to(uint64_t from, uint64_t to) {
    return make_branch_link(static_cast<int64_t>(to - from));
}

// Set branch offset in existing instruction
constexpr uint32_t set_branch_offset(uint32_t insn, int64_t offset) {
    if (is_branch_imm(insn)) {
        return (insn & 0xFC000000) | ((static_cast<uint32_t>(offset >> 2)) & 0x03FFFFFF);
    }
    if (is_cond_branch(insn) || is_comp_branch(insn)) {
        return (insn & 0xFF00001F) | (((static_cast<uint32_t>(offset >> 2)) & 0x7FFFF) << 5);
    }
    if (is_test_branch(insn)) {
        return (insn & 0xFFF8001F) | (((static_cast<uint32_t>(offset >> 2)) & 0x3FFF) << 5);
    }
    return insn;
}

// PC-relative addressing

constexpr bool is_adr(uint32_t insn) {
    return (insn & 0x9F000000) == 0x10000000;  // ADR
}

constexpr bool is_adrp(uint32_t insn) {
    return (insn & 0x9F000000) == 0x90000000;  // ADRP
}

constexpr bool is_pc_relative(uint32_t insn) {
    return is_adr(insn) || is_adrp(insn);
}

// Get ADR/ADRP offset
constexpr int64_t get_adr_offset(uint32_t insn) {
    // immhi:immlo (21-bit signed)
    int32_t immhi = (insn >> 5) & 0x7FFFF;
    int32_t immlo = (insn >> 29) & 0x3;
    int32_t imm = (immhi << 2) | immlo;
    if (imm & 0x100000) imm |= 0xFFE00000;  // Sign extend from 21 bits

    if (is_adrp(insn)) {
        return static_cast<int64_t>(imm) << 12;  // Page offset
    }
    return imm;
}

// Get destination register from ADR/ADRP
constexpr uint32_t get_adr_rd(uint32_t insn) {
    return insn & 0x1F;
}

// Load literal

constexpr bool is_ldr_literal(uint32_t insn) {
    return (insn & 0x3B000000) == 0x18000000;
}

constexpr int64_t get_ldr_literal_offset(uint32_t insn) {
    int32_t imm19 = (insn >> 5) & 0x7FFFF;
    if (imm19 & 0x40000) imm19 |= 0xFFF80000;
    return static_cast<int64_t>(imm19) << 2;
}

// Special instructions

constexpr uint32_t NOP = 0xD503201F;

constexpr bool is_nop(uint32_t insn) {
    return insn == NOP;
}

constexpr bool is_hint(uint32_t insn) {
    return (insn & 0xFFFFF01F) == 0xD503201F;
}

// Pointer authentication instructions (ARMv8.3-A)
constexpr bool is_pauth(uint32_t insn) {
    // HINT-based PAC/AUT instructions (system hint with CRm encoding PAC ops)
    // Mask the variable bits (op2 bits 5-7) and check the base pattern
    uint32_t hint_masked = insn & 0xFFFFF01F;
    bool is_pac_hint = (hint_masked == 0xD503201F) &&            // Base HINT pattern
                       ((insn & 0x00000FE0) >= 0x00000100) &&    // CRm:op2 in PAC/AUT range
                       ((insn & 0x00000FE0) <= 0x000003E0);
    // Data processing PAC/AUT with register operands
    return is_pac_hint || (insn & 0xFFFFC000) == 0xDAC10000;
}

constexpr bool is_autiasp(uint32_t insn) {
    return insn == 0xD50323BF;  // AUTIASP
}

constexpr bool is_autisp(uint32_t insn) {
    return insn == 0xD50323FF;  // AUTIBSP
}

// Instruction generation utilities

// MOV (wide immediate)
constexpr uint32_t make_movz(uint32_t rd, uint16_t imm, uint32_t shift = 0, bool is_64bit = true) {
    uint32_t sf = is_64bit ? 1 : 0;
    uint32_t hw = shift / 16;
    return (sf << 31) | 0x52800000 | (hw << 21) | (static_cast<uint32_t>(imm) << 5) | rd;
}

constexpr uint32_t make_movk(uint32_t rd, uint16_t imm, uint32_t shift = 0, bool is_64bit = true) {
    uint32_t sf = is_64bit ? 1 : 0;
    uint32_t hw = shift / 16;
    return (sf << 31) | 0x72800000 | (hw << 21) | (static_cast<uint32_t>(imm) << 5) | rd;
}

// Generate sequence to load 64-bit immediate into register
inline void make_mov_imm64(uint32_t *buf, uint32_t rd, uint64_t imm) {
    buf[0] = make_movz(rd, imm & 0xFFFF, 0, true);
    buf[1] = make_movk(rd, (imm >> 16) & 0xFFFF, 16, true);
    buf[2] = make_movk(rd, (imm >> 32) & 0xFFFF, 32, true);
    buf[3] = make_movk(rd, (imm >> 48) & 0xFFFF, 48, true);
}

// BR Xn
constexpr uint32_t make_br(uint32_t rn) {
    return 0xD61F0000 | (rn << 5);
}

// BLR Xn
constexpr uint32_t make_blr(uint32_t rn) {
    return 0xD63F0000 | (rn << 5);
}

// RET (Xn)
constexpr uint32_t make_ret(uint32_t rn = 30) {
    return 0xD65F0000 | (rn << 5);
}

// SVC #imm
constexpr uint32_t make_svc(uint16_t imm) {
    return 0xD4000001 | (static_cast<uint32_t>(imm) << 5);
}

// Instruction relocation support

// Check if instruction uses PC-relative addressing and needs relocation
constexpr bool needs_relocation(uint32_t insn) {
    return is_branch_imm(insn) || is_cond_branch(insn) || is_comp_branch(insn) ||
           is_test_branch(insn) || is_adr(insn) || is_adrp(insn) || is_ldr_literal(insn);
}

// Relocate instruction from old_pc to new_pc
// Returns relocated instruction, or nullopt if relocation not possible
std::optional<uint32_t> relocate(uint32_t insn, uint64_t old_pc, uint64_t new_pc);

// Follow branch chain to find final target
int32_t follow_branch(const uint8_t *img, int32_t offset);

} // namespace arm64
} // namespace kp