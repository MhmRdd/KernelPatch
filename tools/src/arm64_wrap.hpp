/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 mhmrdd. All Rights Reserved. */

/*
 * ARM64 C++ Wrapper
 *
 * Minimal C++ wrapper providing RAII and convenience methods.
 * All encoding/decoding delegated to arm64_asm.h and arm64_disasm.h.
 */

#pragma once

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

extern "C" {
#include <disasm/arm64_asm.h>
}

namespace kptools {
namespace arm64 {

// RAII wrapper for disassembler context
class Disassembler {
public:
    Disassembler(const uint8_t* code, size_t size, uint64_t address, bool big_endian = false)
        : ctx_(arm64_ctx_create(code, size, address, big_endian), arm64_ctx_destroy) {}

    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;
    Disassembler(Disassembler&&) = default;
    Disassembler& operator=(Disassembler&&) = default;

    bool valid() const { return ctx_ != nullptr; }

    bool next(arm64_insn_t& insn) {
        if (!ctx_) return false;
        return arm64_disasm_one(ctx_.get(), &insn);
    }

    std::vector<arm64_insn_t> disassemble_all() {
        std::vector<arm64_insn_t> result;
        arm64_insn_t insn;
        while (next(insn)) {
            result.push_back(insn);
        }
        return result;
    }

    static void init() {
        arm64_ctx_init(
            [](size_t size) -> void* { return std::malloc(size); },
            [](void* ptr) { std::free(ptr); }
        );
    }

private:
    std::unique_ptr<arm64_ctx_t, decltype(&arm64_ctx_destroy)> ctx_;
};

// Single instruction disassembly
inline arm64_insn_t disasm_one(const uint8_t* addr, bool big_endian = false) {
    return arm64_disasm_addr(addr, big_endian);
}

// Instruction classification helpers (use decoded instruction id)
inline bool is_branch(const arm64_insn_t& i) {
    switch (i.id) {
        case ARM64_INS_B:
        case ARM64_INS_BL:
        case ARM64_INS_BR:
        case ARM64_INS_BLR:
        case ARM64_INS_B_COND:
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
        case ARM64_INS_RET:
            return true;
        default:
            return false;
    }
}

inline bool is_cond_branch(const arm64_insn_t& i) {
    switch (i.id) {
        case ARM64_INS_B_COND:
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
            return true;
        default:
            return false;
    }
}

inline bool is_call(const arm64_insn_t& i) {
    return i.id == ARM64_INS_BL || i.id == ARM64_INS_BLR;
}

inline bool is_return(const arm64_insn_t& i) {
    return i.id == ARM64_INS_RET;
}

inline bool is_pac(const arm64_insn_t& i) {
    switch (i.id) {
        case ARM64_INS_PACIASP:
        case ARM64_INS_AUTIASP:
        case ARM64_INS_PACIAZ:
        case ARM64_INS_AUTIAZ:
        case ARM64_INS_PACIA:
        case ARM64_INS_AUTIA:
        case ARM64_INS_PACIB:
        case ARM64_INS_AUTIB:
        case ARM64_INS_PACDA:
        case ARM64_INS_AUTDA:
        case ARM64_INS_PACDB:
        case ARM64_INS_AUTDB:
        case ARM64_INS_XPACI:
        case ARM64_INS_XPACD:
            return true;
        default:
            return false;
    }
}

// Extract branch target from decoded instruction
inline uint64_t branch_target(const arm64_insn_t& i) {
    switch (i.id) {
        case ARM64_INS_B:
        case ARM64_INS_BL:
            if (i.op_count >= 1 && i.operands[0].type == ARM64_OP_IMM)
                return i.address + i.operands[0].imm;
            break;
        case ARM64_INS_B_COND:
        case ARM64_INS_CBZ:
        case ARM64_INS_CBNZ:
            if (i.op_count >= 2 && i.operands[1].type == ARM64_OP_IMM)
                return i.address + i.operands[1].imm;
            break;
        case ARM64_INS_TBZ:
        case ARM64_INS_TBNZ:
            if (i.op_count >= 3 && i.operands[2].type == ARM64_OP_IMM)
                return i.address + i.operands[2].imm;
            break;
        default:
            break;
    }
    return 0;
}

// High-level encoding with address calculation
inline uint32_t encode_branch(uint64_t from, uint64_t to) {
    return arm64_asm_b(static_cast<int64_t>(to - from));
}

inline uint32_t encode_branch_link(uint64_t from, uint64_t to) {
    return arm64_asm_bl(static_cast<int64_t>(to - from));
}

inline bool can_branch(uint64_t from, uint64_t to) {
    return arm64_asm_offset_in_range_b(static_cast<int64_t>(to - from));
}

// Generate 64-bit immediate load sequence
inline void mov_imm64(uint32_t* buf, arm64_reg_t rd, uint64_t imm) {
    buf[0] = arm64_asm_movz(rd, imm & 0xFFFF, 0);
    buf[1] = arm64_asm_movk(rd, (imm >> 16) & 0xFFFF, 16);
    buf[2] = arm64_asm_movk(rd, (imm >> 32) & 0xFFFF, 32);
    buf[3] = arm64_asm_movk(rd, (imm >> 48) & 0xFFFF, 48);
}

// Code analysis utilities
inline int64_t follow_branches(const uint8_t* data, size_t size, size_t off) {
    size_t cur = off;
    for (int n = 0; n < 100 && cur + 4 <= size; ++n) {
        arm64_insn_t i = disasm_one(data + cur, false);
        if (i.id != ARM64_INS_B) break;
        if (i.op_count < 1 || i.operands[0].type != ARM64_OP_IMM) break;
        int64_t target = static_cast<int64_t>(cur) + i.operands[0].imm;
        if (target < 0 || static_cast<size_t>(target) >= size) break;
        cur = static_cast<size_t>(target);
    }
    return static_cast<int64_t>(cur - off);
}

inline size_t skip_pac(const uint8_t* data, size_t size, size_t off) {
    while (off + 4 <= size) {
        arm64_insn_t i = disasm_one(data + off, false);
        if (!is_pac(i)) break;
        off += 4;
    }
    return off;
}

} // namespace arm64
} // namespace kptools