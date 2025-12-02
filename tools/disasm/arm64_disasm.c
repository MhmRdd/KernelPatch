/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 mhmrdd. All Rights Reserved. */

/**
 * @file arm64_disasm.c
 * @brief ARM64 Disassembler Implementation - Extended Version (Host)
 */

#include <disasm/arm64_disasm.h>
#include <stdio.h>
#include <string.h>

/* Global allocator function pointers (defined here, declared extern in header) */
arm64_alloc_fn g_arm64_alloc = NULL;
arm64_free_fn g_arm64_free = NULL;

#define BITS(v, h, l) (((v) >> (l)) & ((1u << ((h) - (l) + 1)) - 1))
#define BIT(v, n) (((v) >> (n)) & 1)
#define SEXT(v, b) (((int64_t)(v) << (64 - (b))) >> (64 - (b)))

static inline uint32_t read_u32(const uint8_t *d, bool be) {
    return be ? (d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3]) :
               (d[0] | d[1] << 8 | d[2] << 16 | d[3] << 24);
}

static inline arm64_reg_t x_reg(uint8_t r) { return r == 31 ? ARM64_REG_XZR : ARM64_REG_X0 + r; }
static inline arm64_reg_t x_reg_sp(uint8_t r) { return r == 31 ? ARM64_REG_SP : ARM64_REG_X0 + r; }
static inline arm64_reg_t w_reg(uint8_t r) { return r == 31 ? ARM64_REG_WZR : ARM64_REG_W0 + r; }
static inline arm64_reg_t w_reg_sp(uint8_t r) { return r == 31 ? ARM64_REG_WSP : ARM64_REG_W0 + r; }
static inline arm64_reg_t v_reg(uint8_t r) { return ARM64_REG_V0 + r; }
static inline arm64_reg_t d_reg(uint8_t r) { return ARM64_REG_D0 + r; }
static inline arm64_reg_t s_reg(uint8_t r) { return ARM64_REG_S0 + r; }

/* System register decoding helper */
static arm64_sysreg_t decode_sysreg(uint32_t op) {
    static const struct { uint32_t key; arm64_sysreg_t reg; } sysregs[] = {
        {0x33420, ARM64_SYSREG_NZCV}, {0x30412, ARM64_SYSREG_TPIDR_EL0}, {0x30d03, ARM64_SYSREG_TPIDRRO_EL0},
        {0x30d04, ARM64_SYSREG_TPIDR_EL1}, {0x30410, ARM64_SYSREG_SP_EL0}, {0x30400, ARM64_SYSREG_SPSR_EL1},
        {0x30401, ARM64_SYSREG_ELR_EL1}, {0x30100, ARM64_SYSREG_SCTLR_EL1}, {0x30101, ARM64_SYSREG_ACTLR_EL1},
        {0x30102, ARM64_SYSREG_CPACR_EL1}, {0x30200, ARM64_SYSREG_TTBR0_EL1}, {0x30201, ARM64_SYSREG_TTBR1_EL1},
        {0x30202, ARM64_SYSREG_TCR_EL1}, {0x30520, ARM64_SYSREG_ESR_EL1}, {0x30600, ARM64_SYSREG_FAR_EL1},
        {0x30a20, ARM64_SYSREG_MAIR_EL1}, {0x30c00, ARM64_SYSREG_VBAR_EL1}, {0x30d01, ARM64_SYSREG_CONTEXTIDR_EL1},
        {0x30e10, ARM64_SYSREG_CNTKCTL_EL1}, {0x33e00, ARM64_SYSREG_CNTFRQ_EL0}, {0x33e01, ARM64_SYSREG_CNTPCT_EL0},
        {0x33e02, ARM64_SYSREG_CNTVCT_EL0}, {0x33e21, ARM64_SYSREG_CNTP_CTL_EL0}, {0x33e22, ARM64_SYSREG_CNTP_CVAL_EL0},
        {0x33e31, ARM64_SYSREG_CNTV_CTL_EL0}, {0x33e32, ARM64_SYSREG_CNTV_CVAL_EL0}, {0x33421, ARM64_SYSREG_DAIF},
        {0x30460, ARM64_SYSREG_ICC_PMR_EL1}, {0x34d02, ARM64_SYSREG_TPIDR_EL2}
    };
    uint32_t key = (BITS(op, 18, 16) << 12) | (BITS(op, 15, 12) << 8) | (BITS(op, 11, 8) << 4) | BITS(op, 7, 5);
    if (BITS(op, 20, 19) != 3) return ARM64_SYSREG_UNKNOWN;
    for (size_t i = 0; i < sizeof(sysregs)/sizeof(sysregs[0]); i++)
        if (sysregs[i].key == key) return sysregs[i].reg;
    return ARM64_SYSREG_UNKNOWN;
}

/* Decode logical immediate */
static bool decode_log_imm(uint32_t n, uint32_t imms, uint32_t immr, bool is_64, uint64_t *res) {
    uint32_t comb = (n << 6) | (~imms & 0x3f);
    int len = -1;
    for (int i = 6; i >= 0; i--) if (comb & (1u << i)) { len = i; break; }
    if (len < 0 || (!is_64 && len >= 6)) return false;

    uint32_t esize = 1u << len, emask = esize - 1;
    uint32_t s = imms & emask, r = immr & emask;
    if (s == emask) return false;

    uint64_t welem = (1ULL << (s + 1)) - 1;
    if (r != 0) {
        if (esize == 64) welem = (welem >> r) | (welem << (64 - r));
        else {
            uint64_t bot = welem & ((1ULL << r) - 1);
            welem = ((welem >> r) | (bot << (esize - r))) & ((1ULL << esize) - 1);
        }
    }

    *res = welem;
    while (esize < (is_64 ? 64u : 32u)) { *res |= *res << esize; esize *= 2; }
    if (!is_64) *res &= 0xFFFFFFFF;
    return true;
}

typedef bool (*decoder_fn)(uint32_t, arm64_insn_t*);

static bool dec_branch(uint32_t op, arm64_insn_t *i) {
    if (op == 0xd65f03c0) { i->id = ARM64_INS_RET; return true; }
    if ((op & 0xfffffc1f) == 0xd61f0000) {
        i->id = ARM64_INS_BR; i->op_count = 1;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 9, 5))};
        return true;
    }
    if ((op & 0xfffffc1f) == 0xd63f0000) {
        i->id = ARM64_INS_BLR; i->op_count = 1;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 9, 5))};
        return true;
    }
    if (BITS(op, 31, 24) == 0x54) {
        i->id = ARM64_INS_B_COND; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_COND, .cc = BITS(op, 3, 0)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = SEXT(BITS(op, 23, 5), 19) << 2};
        return true;
    }
    if (BITS(op, 31, 26) == 0b000101 || BITS(op, 31, 26) == 0b100101) {
        i->id = BITS(op, 31, 26) == 0b000101 ? ARM64_INS_B : ARM64_INS_BL;
        i->op_count = 1;
        i->operands[0] = (arm64_operand_t){ARM64_OP_IMM, .imm = SEXT(BITS(op, 25, 0), 26) << 2};
        return true;
    }
    // CBZ/CBNZ - handle both 32-bit and 64-bit variants
    if ((BITS(op, 30, 24) & 0x7E) == 0x34) {
        i->id = BIT(op, 24) ? ARM64_INS_CBNZ : ARM64_INS_CBZ; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = SEXT(BITS(op, 23, 5), 19) << 2};
        return true;
    }
    // TBZ/TBNZ - handle both W and X variants
    if ((BITS(op, 30, 24) & 0x7E) == 0x36) {
        i->id = BIT(op, 24) ? ARM64_INS_TBNZ : ARM64_INS_TBZ; i->op_count = 3;
        uint8_t bit = (BIT(op, 31) << 5) | BITS(op, 23, 19);
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = bit};
        i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = SEXT(BITS(op, 18, 5), 14) << 2};
        return true;
    }
    return false;
}

static bool dec_system(uint32_t op, arm64_insn_t *i) {
    const struct { uint32_t op; arm64_ins_t id; } sys[] = {
        {0xd503201f, ARM64_INS_NOP}, {0xd503229f, ARM64_INS_CSDB}, {0xd5033fdf, ARM64_INS_ISB},
        {0xd503233f, ARM64_INS_PACIASP}, {0xd50323bf, ARM64_INS_AUTIASP},
        {0xd503231f, ARM64_INS_PACIAZ}, {0xd503239f, ARM64_INS_AUTIAZ},
        {0xd50320bf, ARM64_INS_SEVL}, {0xd503205f, ARM64_INS_WFE}, {0xd503203f, ARM64_INS_YIELD},
    };
    for (size_t j = 0; j < sizeof(sys)/sizeof(sys[0]); j++)
        if (op == sys[j].op) { i->id = sys[j].id; return true; }

    if ((op & 0xFFFFFF3F) == 0xD503241F) { i->id = ARM64_INS_BTI; return true; }

    // Barrier instructions
    if ((op & 0xfffff01f) == 0xd503301f) {
        uint8_t op2 = BITS(op, 7, 5);
        uint8_t crm = BITS(op, 11, 8);  // Barrier scope
        if (op2 == 4) {
            i->id = ARM64_INS_DSB;
            i->op_count = 1;
            i->operands[0] = (arm64_operand_t){ARM64_OP_IMM, .imm = crm};
            return true;
        }
        else if (op2 == 5) {
            i->id = ARM64_INS_DMB;
            i->op_count = 1;
            i->operands[0] = (arm64_operand_t){ARM64_OP_IMM, .imm = crm};
            return true;
        }
    }

    // MRS/MSR - Enhanced with proper system register decoding
    if ((op & 0xFFF00000) == 0xD5300000 || (op & 0xFFF00000) == 0xD5100000) {
        bool is_mrs = (op & 0xFFF00000) == 0xD5300000;
        arm64_sysreg_t sysreg = decode_sysreg(op);

        i->id = is_mrs ? ARM64_INS_MRS : ARM64_INS_MSR;
        i->op_count = 2;

        if (is_mrs) {
            // MRS Xt, <sysreg>
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 4, 0))};
            i->operands[1] = (arm64_operand_t){ARM64_OP_SYSREG, .sysreg = sysreg};
        } else {
            // MSR <sysreg>, Xt
            i->operands[0] = (arm64_operand_t){ARM64_OP_SYSREG, .sysreg = sysreg};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 4, 0))};
        }
        return true;
    }

    if ((op & 0xffe0001f) == 0xd4000001 || (op & 0xffe0001f) == 0xd4200000) {
        i->id = (op & 0xffe0001f) == 0xd4000001 ? ARM64_INS_SVC : ARM64_INS_BRK;
        i->op_count = 1;
        i->operands[0] = (arm64_operand_t){ARM64_OP_IMM, .imm = BITS(op, 20, 5)};
        return true;
    }

    if ((op & 0xfffffc1f) == 0xdac10000) {
        i->id = BIT(op, 10) ? ARM64_INS_AUTIA : ARM64_INS_PACIA;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 9, 5))};
        return true;
    }

    return false;
}

/* NEW: Bitfield operations decoder */
static bool dec_bitfield(uint32_t op, arm64_insn_t *i) {
    // Bitfield: bits[31:23] = xx1100110
    if (BITS(op, 28, 23) == 0x26) {
        bool is_64 = BIT(op, 31);
        bool n = BIT(op, 22);
        uint8_t opc = BITS(op, 30, 29);
        uint8_t immr = BITS(op, 21, 16);
        uint8_t imms = BITS(op, 15, 10);
        uint8_t rn = BITS(op, 9, 5);
        uint8_t rd = BITS(op, 4, 0);

        // N must match sf
        if (is_64 != n) return false;

        // Check for SXTW alias: SBFM Xd, Wn, #0, #31 (opc=0, sf=1, immr=0, imms=31)
        if (opc == 0 && is_64 && immr == 0 && imms == 31) {
            i->id = ARM64_INS_SXTW;
            i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = w_reg(rn)};  // Source is 32-bit
            return true;
        }

        // Check for UBFM aliases (opc=2)
        if (opc == 2) {
            uint32_t datasize = is_64 ? 64 : 32;
            uint32_t max_imms = datasize - 1;

            // LSR alias: UBFM Wd, Wn, #shift, #(datasize-1)
            if (imms == max_imms) {
                i->id = ARM64_INS_LSR_IMM;
                i->op_count = 3;
                i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
                i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
                i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = immr};
                return true;
            }

            // LSL alias: UBFM Wd, Wn, #(-shift MOD datasize), #(datasize-1-shift)
            // Calculate potential shift from the pattern
            uint32_t shift = (datasize - immr) % datasize;
            if (imms == (datasize - 1 - shift) && shift != 0) {
                i->id = ARM64_INS_LSL_IMM;
                i->op_count = 3;
                i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
                i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
                i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = shift};
                return true;
            }
        }

        // SBFM, BFM, UBFM
        const arm64_ins_t ids[] = {ARM64_INS_SBFM, ARM64_INS_BFM, ARM64_INS_UBFM};
        i->id = ids[opc];
        i->op_count = 4;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = immr};
        i->operands[3] = (arm64_operand_t){ARM64_OP_IMM, .imm = imms};
        return true;
    }
    return false;
}

static bool dec_data_imm(uint32_t op, arm64_insn_t *i) {
    if (BITS(op, 28, 23) == 0b100101) {
        uint8_t opc = BITS(op, 30, 29), rd = BITS(op, 4, 0), hw = BITS(op, 22, 21);
        uint64_t imm = (uint64_t)BITS(op, 20, 5) << (hw * 16);
        i->id = opc == 0 ? ARM64_INS_MOVN : (opc == 2 ? ARM64_INS_MOVZ : ARM64_INS_MOVK);
        i->op_count = opc == 3 && hw > 0 ? 3 : 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rd) : w_reg(rd)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = imm};
        if (opc == 3 && hw > 0) i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = hw * 16};
        return true;
    }
    if (BITS(op, 28, 24) == 0x11) {
        bool is_64 = BIT(op, 31), is_sub = BIT(op, 30), sf = BIT(op, 29);
        bool sh = BIT(op, 22);  // shift bit
        uint8_t rd = BITS(op, 4, 0), rn = BITS(op, 9, 5);
        uint32_t imm12 = BITS(op, 21, 10);
        if (sf && rd == 31) {
            i->id = is_sub ? ARM64_INS_CMP_IMM : ARM64_INS_CMN_IMM; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rn) : w_reg_sp(rn)};
            if (sh) {
                i->operands[1] = (arm64_operand_t){ARM64_OP_IMM_SHIFT, .imm_shift = {imm12, 12}};
            } else {
                i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = imm12};
            }
        } else if (!is_sub && !sf && imm12 == 0 && rn == 31) {
            i->id = ARM64_INS_MOV_REG; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rd) : w_reg_sp(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = ARM64_REG_SP};
        } else {
            // Check for flag-setting variants (S bit set)
            if (sf) {
                i->id = is_sub ? ARM64_INS_SUBS_IMM : ARM64_INS_ADDS_IMM;
            } else {
                i->id = is_sub ? ARM64_INS_SUB_IMM : ARM64_INS_ADD_IMM;
            }
            i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rd) : w_reg_sp(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rn) : w_reg_sp(rn)};
            if (sh) {
                i->operands[2] = (arm64_operand_t){ARM64_OP_IMM_SHIFT, .imm_shift = {imm12, 12}};
            } else {
                i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = imm12};
            }
        }
        return true;
    }
    if (BITS(op, 28, 23) == 0x24) {
        uint64_t val;
        if (!decode_log_imm(BIT(op, 22), BITS(op, 15, 10), BITS(op, 21, 16), BIT(op, 31), &val)) return false;
        uint8_t opc = BITS(op, 30, 29), rd = BITS(op, 4, 0), rn = BITS(op, 9, 5);
        if (opc == 3 && rd == 31) {
            i->id = ARM64_INS_TST_IMM; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rn) : w_reg(rn)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = val};
        } else {
            // Handle flag-setting variants for logical immediate instructions
            if (opc == 0) {
                i->id = ARM64_INS_AND_IMM;
            } else if (opc == 1) {
                i->id = ARM64_INS_ORR_IMM;
            } else if (opc == 2) {
                i->id = ARM64_INS_EOR_IMM;
            } else if (opc == 3) {
                i->id = ARM64_INS_ANDS_IMM;  // ANDS with flags
            } else {
                i->id = ARM64_INS_AND_IMM;  // fallback
            }
            i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rd) : w_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rn) : w_reg(rn)};
            i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = val};
        }
        return true;
    }
    if ((BITS(op, 28, 23) & 0x3E) == 0x26 && BIT(op, 31) == BIT(op, 22)) {
        uint8_t rd = BITS(op, 4, 0), rn = BITS(op, 9, 5), rm = BITS(op, 20, 16), imms = BITS(op, 15, 10);
        if (rn == rm) {
            i->id = ARM64_INS_ROR_IMM; i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rd) : w_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rn) : w_reg(rn)};
            i->operands[2] = (arm64_operand_t){ARM64_OP_IMM, .imm = imms};
            return true;
        }
    }
    return false;
}

static bool dec_data_reg(uint32_t op, arm64_insn_t *i) {
    if ((op & 0x7FE0FFE0) == 0x2A0003E0 || (op & 0xFFE0FFE0) == 0xAA0003E0) {
        i->id = ARM64_INS_MOV_REG; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 20, 16)) : w_reg(BITS(op, 20, 16))};
        return true;
    }

    // NEW: ADC/SBC (Add/Subtract with carry)
    if ((op & 0x1fe00000) == 0x1a000000) {
        bool is_64 = BIT(op, 31);
        bool is_sub = BIT(op, 30);
        bool set_flags = BIT(op, 29);
        uint8_t rm = BITS(op, 20, 16);
        uint8_t rn = BITS(op, 9, 5);
        uint8_t rd = BITS(op, 4, 0);

        // NGC alias: SBC Xd, XZR, Xm (rn==31)
        if (is_sub && !set_flags && rn == 31) {
            i->id = ARM64_INS_NGC;
            i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
            return true;
        }

        i->id = is_sub ? (set_flags ? ARM64_INS_SBCS : ARM64_INS_SBC) :
                        (set_flags ? ARM64_INS_ADCS : ARM64_INS_ADC);
        i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
        return true;
    }

    if ((op & 0x1fe00000) == 0x1ac00000) {
        uint8_t op2 = BITS(op, 15, 10);
        const arm64_ins_t shift_ids[] = {ARM64_INS_LSL_REG, ARM64_INS_LSR_REG, ARM64_INS_ASR_REG, ARM64_INS_ROR_REG};
        if (op2 >= 0x08 && op2 <= 0x0b) {
            i->id = shift_ids[op2 - 0x08]; i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 9, 5)) : w_reg(BITS(op, 9, 5))};
            i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 20, 16)) : w_reg(BITS(op, 20, 16))};
            return true;
        }
    }
    if (BITS(op, 28, 24) == 0x0B) {
        uint8_t rd = BITS(op, 4, 0), rn = BITS(op, 9, 5), rm = BITS(op, 20, 16);
        bool is_64 = BIT(op, 31), is_sub = BIT(op, 30), sf = BIT(op, 29);

        // Check if this is extended register (bit[21] = 1) or shifted register (bit[21] = 0)
        bool is_extended = BIT(op, 21);

        if (is_extended) {
            // Extended register encoding: option[15:13], imm3[12:10]
            uint8_t option = BITS(op, 15, 13);  // extend type
            uint8_t imm3 = BITS(op, 12, 10);   // shift amount

            if (sf && rd == 31) {
                i->id = is_sub ? ARM64_INS_CMP_REG : ARM64_INS_CMN_REG; i->op_count = 2;
                i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rn) : w_reg_sp(rn)};

                // Check if third operand has extend
                if (option != 0 || imm3 != 0) {
                    // Choose register width based on extend type
                    arm64_reg_t rm_reg = (option == 2 || option == 6) ? w_reg(rm) : (is_64 ? x_reg(rm) : w_reg(rm));
                    i->operands[1] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                        .reg = rm_reg,
                        .extend_type = option,
                        .shift = imm3
                    }};
                } else {
                    i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
                }
            } else {
                // Check for flag-setting variants (S bit set)
                if (sf) {
                    i->id = is_sub ? ARM64_INS_SUBS_REG : ARM64_INS_ADDS_REG;
                } else {
                    i->id = is_sub ? ARM64_INS_SUB_REG : ARM64_INS_ADD_REG;
                }
                i->op_count = 3;
                i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rd) : w_reg_sp(rd)};
                i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg_sp(rn) : w_reg_sp(rn)};

                // Check if third operand has extend
                if (option != 0 || imm3 != 0) {
                    // Choose register width based on extend type
                    arm64_reg_t rm_reg = (option == 2 || option == 6) ? w_reg(rm) : (is_64 ? x_reg(rm) : w_reg(rm));
                    i->operands[2] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                        .reg = rm_reg,
                        .extend_type = option,
                        .shift = imm3
                    }};
                } else {
                    i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
                }
            }
        } else {
            // Shifted register encoding: shift[23:22], imm6[15:10]
            // NOTE: In shifted register, Rn=31 means XZR (not SP like in extended register)
            // Shift types: 0=LSL, 1=LSR, 2=ASR - use indices 8,9,10 for shift names
            uint8_t shift_type = BITS(op, 23, 22);
            uint8_t imm6 = BITS(op, 15, 10);
            uint8_t shift_ext = 8 + shift_type;  // Map to lsl(8), lsr(9), asr(10)

            if (sf && rd == 31) {
                i->id = is_sub ? ARM64_INS_CMP_REG : ARM64_INS_CMN_REG; i->op_count = 2;
                i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
                if (shift_type != 0 || imm6 != 0) {
                    i->operands[1] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                        .reg = is_64 ? x_reg(rm) : w_reg(rm),
                        .extend_type = shift_ext,
                        .shift = imm6
                    }};
                } else {
                    i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
                }
            } else {
                if (sf) {
                    i->id = is_sub ? ARM64_INS_SUBS_REG : ARM64_INS_ADDS_REG;
                } else {
                    i->id = is_sub ? ARM64_INS_SUB_REG : ARM64_INS_ADD_REG;
                }
                i->op_count = 3;
                i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
                i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
                if (shift_type != 0 || imm6 != 0) {
                    i->operands[2] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                        .reg = is_64 ? x_reg(rm) : w_reg(rm),
                        .extend_type = shift_ext,
                        .shift = imm6
                    }};
                } else {
                    i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
                }
            }
        }
        return true;
    }

    // NEW: MADD/MSUB/SMADDL/etc (Multiply-accumulate)
    if ((op & 0x1f000000) == 0x1b000000) {
        bool is_64 = BIT(op, 31);
        uint8_t rm = BITS(op, 20, 16);
        uint8_t ra = BITS(op, 14, 10);
        uint8_t rn = BITS(op, 9, 5);
        uint8_t rd = BITS(op, 4, 0);
        bool o0 = BIT(op, 15);

        // MUL/MNEG aliases (ra == 31)
        if (ra == 31) {
            i->id = o0 ? ARM64_INS_MNEG : ARM64_INS_MUL;
            i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
            i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
            return true;
        }

        i->id = o0 ? ARM64_INS_MSUB : ARM64_INS_MADD;
        i->op_count = 4;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rd) : w_reg(rd)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rn) : w_reg(rn)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rm) : w_reg(rm)};
        i->operands[3] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(ra) : w_reg(ra)};
        return true;
    }

    if ((op & 0x1fe0fc00) == 0x1ac00800 || (op & 0x1fe0fc00) == 0x1ac00c00) {
        i->id = (op & 0x1fe0fc00) == 0x1ac00800 ? ARM64_INS_UDIV : ARM64_INS_SDIV; i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 9, 5)) : w_reg(BITS(op, 9, 5))};
        i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 20, 16)) : w_reg(BITS(op, 20, 16))};
        return true;
    }
    if (BITS(op, 28, 24) == 0x0A) {
        uint8_t opc = BITS(op, 30, 29), rd = BITS(op, 4, 0), rn = BITS(op, 9, 5), rm = BITS(op, 20, 16);
        uint8_t shift_type = BITS(op, 23, 22);  // shift type
        uint8_t imm6 = BITS(op, 15, 10);       // shift amount

        if (opc == 3 && rd == 31) {
            i->id = ARM64_INS_TST_REG; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rn) : w_reg(rn)};

            // Check if second operand has shift
            if (shift_type != 0 || imm6 != 0) {
                i->operands[1] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                    .reg = BIT(op, 31) ? x_reg(rm) : w_reg(rm),
                    .extend_type = shift_type == 0 ? 3 : shift_type,  // LSL=3 for logical shift
                    .shift = imm6
                }};
            } else {
                i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rm) : w_reg(rm)};
            }
        } else if (opc == 3 && rd != 31) {
            // ANDS register variant (opc=3, rd≠31)
            i->id = ARM64_INS_ANDS_REG;
            i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rd) : w_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rn) : w_reg(rn)};

            // Check if third operand has shift
            if (shift_type != 0 || imm6 != 0) {
                i->operands[2] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                    .reg = BIT(op, 31) ? x_reg(rm) : w_reg(rm),
                    .extend_type = shift_type == 0 ? 3 : shift_type,  // LSL=3 for logical shift
                    .shift = imm6
                }};
            } else {
                i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rm) : w_reg(rm)};
            }
        } else {
            const arm64_ins_t log_ops[] = {ARM64_INS_AND_REG, ARM64_INS_ORR_REG, ARM64_INS_EOR_REG, ARM64_INS_AND_REG};
            i->id = log_ops[opc];
            i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rd) : w_reg(rd)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rn) : w_reg(rn)};

            // Check if third operand has shift
            if (shift_type != 0 || imm6 != 0) {
                i->operands[2] = (arm64_operand_t){ARM64_OP_REG_EXT, .reg_ext = {
                    .reg = BIT(op, 31) ? x_reg(rm) : w_reg(rm),
                    .extend_type = shift_type == 0 ? 3 : shift_type,  // LSL=3 for logical shift
                    .shift = imm6
                }};
            } else {
                i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rm) : w_reg(rm)};
            }
        }
        return true;
    }
    return false;
}

static bool dec_ldst(uint32_t op, arm64_insn_t *i) {
    // LDAR (Load Acquire Register) - 32-bit: 88dffdxx pattern
    if ((op & 0xffffff00) == 0x88dffd00) {
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_LDAR;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = w_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // LDAPR (Load Acquire RCpc Register) - More specific pattern
    // Pattern: bits[31:21] = 10111000101 (0x5C5 or 0x7C5) AND Rs=31 AND opc=12
    if (((op & 0xffe00000) == 0xb8a00000 || (op & 0xffe00000) == 0xf8a00000) &&
        BITS(op, 20, 16) == 31 && BITS(op, 15, 12) == 12) {
        bool is_64 = BIT(op, 30);  // Fixed: bit 30 determines size for load/store instructions
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_LDAPR;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rt) : w_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // PRFM (Prefetch Memory) - FIXED: Much more specific patterns
    // PRFM immediate: bits[31:22] = 1111100110 (0x3E6) - distinct from LDR/STR
    if ((op & 0xffc00000) == 0xf9800000) {
        uint8_t prfop = BITS(op, 4, 0);  // Prefetch operation
        uint8_t rn = BITS(op, 9, 5);
        uint32_t imm12 = BITS(op, 21, 10);

        i->id = ARM64_INS_PRFM;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_IMM, .imm = prfop};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn), .disp = imm12 << 3}};
        return true;
    }
    // PRFM register: bits[31:21] = 11111000101 (0x7C5), bits[11:10] = 10
    if ((op & 0xffe00c00) == 0xf8a00800) {
        uint8_t prfop = BITS(op, 4, 0);  // Prefetch operation
        uint8_t rn = BITS(op, 9, 5);
        uint8_t rm = BITS(op, 20, 16);
        uint8_t opt = BITS(op, 15, 13);
        uint8_t S = BIT(op, 12);

        i->id = ARM64_INS_PRFM;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_IMM, .imm = prfop};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn),
            .index = (opt == 2 || opt == 3) ? w_reg(rm) : x_reg(rm),
            .extend_type = opt, .shift = S ? 3 : 0}};
        return true;
    }

    // LDRSW (Load Register Signed Word) - MUST be checked before generic load/store patterns
    // Patterns: 0xb9800000 (immediate), 0xb8800000 (pre/post), 0xb8a00000 (register)
    if ((op & 0xffc00000) == 0xb9800000) {
        // LDRSW immediate offset (unsigned)
        uint8_t rt = BITS(op, 4, 0), rn = BITS(op, 9, 5);
        uint32_t imm12 = BITS(op, 21, 10);
        i->id = ARM64_INS_LDRSW; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn), .disp = imm12 << 2}};
        return true;
    }
    if ((op & 0xffc00c00) == 0xb8800000) {
        // LDRSW with pre/post-indexed or unscaled immediate
        uint8_t rt = BITS(op, 4, 0), rn = BITS(op, 9, 5), op2 = BITS(op, 11, 10);
        int32_t imm9 = SEXT(BITS(op, 20, 12), 9);
        i->id = ARM64_INS_LDRSW; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn), .disp = imm9,
            .pre_indexed = op2 == 3, .post_indexed = op2 == 1}};
        return true;
    }
    if ((op & 0xffe00c00) == 0xb8a00800) {
        // LDRSW with register offset
        uint8_t rt = BITS(op, 4, 0), rn = BITS(op, 9, 5), rm = BITS(op, 20, 16);
        uint8_t opt = BITS(op, 15, 13), S = BIT(op, 12);
        i->id = ARM64_INS_LDRSW; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn),
            .index = (opt == 2 || opt == 3) ? w_reg(rm) : x_reg(rm),
            .extend_type = opt, .shift = S ? 2 : 0}};
        return true;
    }

    // Load/Store Pair - bits[31:25] should be xx10100
    if (((op >> 25) & 0x3F) == 0x14 || ((op >> 25) & 0x3F) == 0x34) {
        uint8_t rt = BITS(op, 4, 0), rt2 = BITS(op, 14, 10), rn = BITS(op, 9, 5);
        i->id = BIT(op, 22) ? ARM64_INS_LDP : ARM64_INS_STP; i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rt) : w_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(rt2) : w_reg(rt2)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn),
            .disp = SEXT(BITS(op, 21, 15), 7) << (BIT(op, 31) ? 3 : 2),
            .pre_indexed = BITS(op, 24, 23) == 3, .post_indexed = BITS(op, 24, 23) == 1}};
        return true;
    }
    if ((BITS(op, 31, 24) & 0x3B) == 0x39) {
        uint8_t size = BITS(op, 31, 30), rt = BITS(op, 4, 0), rn = BITS(op, 9, 5);
        const arm64_ins_t ids[] = {ARM64_INS_LDRB, ARM64_INS_LDRH, ARM64_INS_LDR_IMM, ARM64_INS_LDR_IMM,
                                   ARM64_INS_STRB, ARM64_INS_STRH, ARM64_INS_STR_IMM, ARM64_INS_STR_IMM};
        i->id = ids[size + (BIT(op, 22) ? 0 : 4)]; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = size == 3 ? x_reg(rt) : w_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn), .disp = BITS(op, 21, 10) << size}};
        return true;
    }
    if ((BITS(op, 31, 24) & 0x3B) == 0x38) {
        uint8_t size = BITS(op, 31, 30), rt = BITS(op, 4, 0), rn = BITS(op, 9, 5), op2 = BITS(op, 11, 10);
        int32_t imm9 = SEXT(BITS(op, 20, 12), 9);
        if (op2 == 1 || op2 == 3) {
            const arm64_ins_t ids[] = {ARM64_INS_LDR_POST, ARM64_INS_LDR_PRE, ARM64_INS_STR_POST, ARM64_INS_STR_PRE};
            i->id = ids[(BIT(op, 22) ? 0 : 2) + (op2 == 3 ? 1 : 0)]; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = size == 3 ? x_reg(rt) : w_reg(rt)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn), .disp = imm9,
                .pre_indexed = op2 == 3, .post_indexed = op2 == 1}};
            return true;
        }
        if (op2 == 0) {
            i->id = BIT(op, 22) ? ARM64_INS_LDUR : ARM64_INS_STUR; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = size == 3 ? x_reg(rt) : w_reg(rt)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn), .disp = imm9}};
            return true;
        }
        if (BIT(op, 21) && op2 == 2) {
            uint8_t rm = BITS(op, 20, 16), opt = BITS(op, 15, 13), S = BIT(op, 12);
            i->id = BIT(op, 22) ? ARM64_INS_LDR_REG : ARM64_INS_STR_REG; i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = size == 3 ? x_reg(rt) : w_reg(rt)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn),
                .index = (opt == 2 || opt == 6) ? w_reg(rm) : x_reg(rm),
                .extend_type = opt, .shift = S ? size : 0}};
            return true;
        }
    }


    return false;
}

/* COMPLETELY FIXED: Atomic operations decoder */
static bool dec_atomic(uint32_t op, arm64_insn_t *i) {
    // The instruction pattern requires fixed values in bits [29:23], [21], and [14:10].
    // This new check combines them into a single, more robust mask and comparison.
    // Mask:  0x3FA07C00 -> checks bits [29:23], [21], and [14:10]
    // Value: 0x08007C00 -> expects pattern 0010000...0... and ...011111...
    if ((op & 0x3FA07C00) == 0x08007C00) {
        bool is_load = BIT(op, 22);
        bool acquire_release = BIT(op, 15);
        bool is_64 = (BIT(op, 31) && BIT(op, 30)); // A more robust check for 64-bit

        if (is_load) {
            // LDXR/LDAXR: Rs field (bits 20-16) must be 11111
            if (BITS(op, 20, 16) != 0x1f) return false;

            i->id = acquire_release ? ARM64_INS_LDAXR : ARM64_INS_LDXR;
            i->op_count = 2;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
            i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(BITS(op, 9, 5))}};
        } else {
            // STXR/STLXR
            i->id = acquire_release ? ARM64_INS_STLXR : ARM64_INS_STXR;
            i->op_count = 3;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = w_reg(BITS(op, 20, 16))};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
            i->operands[2] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(BITS(op, 9, 5))}};
        }
        return true;
    }

    return false;
}

/* ARMv8.1 LSE Atomic operations and Load/Store Release/Acquire */
static bool dec_atomic_lse(uint32_t op, arm64_insn_t *i) {
    // CASA (Compare and Swap Atomic) - 0x88eb7d02
    if ((op & 0xffe0fc00) == 0x88e07c00) {
        bool is_64 = BIT(op, 30);
        uint8_t rs = BITS(op, 20, 16);
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_CASA;
        i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rs) : w_reg(rs)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rt) : w_reg(rt)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // CAS (Compare and Swap) - 0x88ad7d02
    if ((op & 0xffe0fc00) == 0x88a07c00) {
        bool is_64 = BIT(op, 30);
        uint8_t rs = BITS(op, 20, 16);
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_CAS;
        i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rs) : w_reg(rs)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rt) : w_reg(rt)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }


    // STLRB (Store Release Register Byte) - 0x089ffdxx
    if ((op & 0xffffff00) == 0x089ffd00) {
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_STLRB;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = w_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // STLR (Store Release Register) - 32-bit: 0x889ffdxx, 64-bit: 0xc89ffdxx
    // Note: mask 0xbfffff00 clears bit 30, so single check matches both variants
    if ((op & 0xbfffff00) == 0x889ffd00) {
        bool is_64 = BIT(op, 30);
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_STLR;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rt) : w_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // STADD (Store Add) - 0xb82b013f
    if ((op & 0xffe0fc00) == 0xb8200000) {
        bool is_64 = BIT(op, 30);
        uint8_t rs = BITS(op, 20, 16);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_STADD;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rs) : w_reg(rs)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // SWPH (Atomic swap halfword) - bits[31:21] = 01111000001
    if ((op & 0xffe00000) == 0x78200000) {
        uint8_t rs = BITS(op, 20, 16);
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_SWPA;
        i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = w_reg(rs)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = w_reg(rt)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    // LDSETA (Load-Add Set Acquire) - bits[31:21] = 10111000101 AND Rs≠31 (not LDAPR)
    if ((op & 0xffe00000) == 0xb8a00000 && BITS(op, 20, 16) != 31) {
        bool is_64 = BIT(op, 30);
        uint8_t rs = BITS(op, 20, 16);
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = ARM64_INS_LDSETA;
        i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rs) : w_reg(rs)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = is_64 ? x_reg(rt) : w_reg(rt)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    return false;
}

/* FIXED: SIMD/FP decoder */
static bool dec_simd(uint32_t op, arm64_insn_t *i) {
    // Scalar FP arithmetic: bits[31:24] = 0x1e, bits[23:22] = type (00=S, 01=D)
    // BUGFIX: Added "&& BIT(op, 11)" to make this check more specific to 3-register
    // arithmetic instructions, preventing it from incorrectly matching FMOV, FCVT, FCMP, etc.
    if (BITS(op, 31, 24) == 0x1e && BITS(op, 21, 21) == 1 && BIT(op, 11)) {
        uint8_t type = BITS(op, 23, 22);
        uint8_t rm = BITS(op, 20, 16);
        uint8_t opcode = BITS(op, 15, 12);
        uint8_t rn = BITS(op, 9, 5);
        uint8_t rd = BITS(op, 4, 0);

        arm64_reg_t (*reg_fn)(uint8_t) = type == 0 ? s_reg : (type == 1 ? d_reg : NULL);
        if (!reg_fn) return false;

        // Decode opcode
        if (opcode == 0x2) {        // FADD
            i->id = ARM64_INS_FADD;
        } else if (opcode == 0x3) { // FSUB
            i->id = ARM64_INS_FSUB;
        } else if (opcode == 0x0) { // FMUL
            i->id = ARM64_INS_FMUL;
        } else if (opcode == 0x1) { // FDIV
            i->id = ARM64_INS_FDIV;
        } else {
            return false;
        }

        i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(rd)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(rn)};
        i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(rm)};
        return true;
    }

    // FMOV (register) - bits[15:10] = 000000
    if ((op & 0xff20fc00) == 0x1e204000) {
        uint8_t type = BITS(op, 23, 22);
        i->id = ARM64_INS_FMOV; i->op_count = 2;
        arm64_reg_t (*reg_fn)(uint8_t) = type == 0 ? s_reg : d_reg;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(BITS(op, 9, 5))};
        return true;
    }

    // FCVT - bits[15:10] = 000100 or 000101
    if ((op & 0xff20fc00) == 0x1e224000 || (op & 0xff20fc00) == 0x1e614000) {
        i->id = ARM64_INS_FCVT;
        i->op_count = 2;
        // Determine source/dest types from bits
        bool src_double = BITS(op, 23, 22) == 1;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = src_double ? s_reg(BITS(op, 4, 0)) : d_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = src_double ? d_reg(BITS(op, 9, 5)) : s_reg(BITS(op, 9, 5))};
        return true;
    }

    // FCMP
    if ((op & 0xff20fc1f) == 0x1e202000) {
        uint8_t type = BITS(op, 23, 22);
        uint8_t rm = BITS(op, 20, 16);
        uint8_t rn = BITS(op, 9, 5);
        uint8_t opcode2 = BITS(op, 4, 0);

        if (opcode2 == 0) {
            i->id = ARM64_INS_FCMP;
            i->op_count = 2;
            arm64_reg_t (*reg_fn)(uint8_t) = type == 0 ? s_reg : d_reg;
            i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(rn)};
            i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = reg_fn(rm)};
            return true;
        }
    }

    // MOVI (vector immediate)
    if ((op & 0xbff89c00) == 0x0f000400) {
        i->id = ARM64_INS_MOVI; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = v_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = (BITS(op, 18, 16) << 5) | BITS(op, 9, 5)};
        return true;
    }

    // ADD (vector)
    if ((op & 0xbf20fc00) == 0x0e208400) {
        i->id = ARM64_INS_ADD_VEC; i->op_count = 3;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = v_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = v_reg(BITS(op, 9, 5))};
        i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = v_reg(BITS(op, 20, 16))};
        return true;
    }

    return false;
}

/* NEW: Advanced SIMD load/store single structure */
static bool dec_advsimd_ldst(uint32_t op, arm64_insn_t *i) {
    // LD1/ST1 single structure: 0x0c407c00 pattern
    // bits[31:24] = 0x0c or 0x4c, bits[21] = L (load=1)
    if ((op & 0xbfff0000) == 0x0c400000 || (op & 0xbfff0000) == 0x4c400000 ||
        (op & 0xbfff0000) == 0x0c000000 || (op & 0xbfff0000) == 0x4c000000) {
        bool is_load = BIT(op, 22);
        uint8_t rt = BITS(op, 4, 0);
        uint8_t rn = BITS(op, 9, 5);

        i->id = is_load ? ARM64_INS_LD1 : ARM64_INS_ST1;
        i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = v_reg(rt)};
        i->operands[1] = (arm64_operand_t){ARM64_OP_MEM, .mem = {.base = x_reg_sp(rn)}};
        return true;
    }

    return false;
}

static bool dec_pcrel(uint32_t op, arm64_insn_t *i) {
    if ((op & 0x9F000000) == 0x90000000 || (op & 0x9F000000) == 0x10000000) {
        int64_t imm = SEXT((BITS(op, 23, 5) << 2) | BITS(op, 30, 29), 21);
        i->id = (op & 0x9F000000) == 0x90000000 ? ARM64_INS_ADRP : ARM64_INS_ADR; i->op_count = 2;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = x_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_IMM, .imm = i->id == ARM64_INS_ADRP ? ((i->address & ~0xFFFLL) + (imm << 12)) : imm};
        return true;
    }
    return false;
}

static bool dec_condsel(uint32_t op, arm64_insn_t *i) {
    if ((op & 0x1FE00000) == 0x1A800000) {
        uint8_t op_val = BIT(op, 30), op2 = BITS(op, 11, 10);
        const arm64_ins_t ids[] = {ARM64_INS_CSEL, ARM64_INS_CSINC, ARM64_INS_CSINV, ARM64_INS_CSNEG};
        int idx = op_val * 2 + (op2 == 1 ? 1 : (op2 == 0 ? 0 : -1));
        if (idx < 0 || idx >= 4) return false;
        i->id = ids[idx]; i->op_count = 4;
        i->operands[0] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 4, 0)) : w_reg(BITS(op, 4, 0))};
        i->operands[1] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 9, 5)) : w_reg(BITS(op, 9, 5))};
        i->operands[2] = (arm64_operand_t){ARM64_OP_REG, .reg = BIT(op, 31) ? x_reg(BITS(op, 20, 16)) : w_reg(BITS(op, 20, 16))};
        i->operands[3] = (arm64_operand_t){ARM64_OP_COND, .cc = BITS(op, 15, 12)};
        return true;
    }
    return false;
}

void arm64_ctx_init(arm64_alloc_fn alloc_fn, arm64_free_fn free_fn)
{
    if (!alloc_fn || !free_fn) {
        return;
    }

    g_arm64_alloc = alloc_fn;
    g_arm64_free = free_fn;
}

/* API Implementation */
arm64_ctx_t *arm64_ctx_create(const uint8_t *code, size_t size, uint64_t address, bool big_endian) {
    if (!code || !size) return NULL;
    arm64_ctx_t *ctx = g_arm64_alloc(sizeof(arm64_ctx_t));
    if (!ctx) return NULL;
    *ctx = (arm64_ctx_t){code, size, 0, address, big_endian};
    return ctx;
}

void arm64_ctx_destroy(arm64_ctx_t *ctx) { g_arm64_free(ctx); }

bool arm64_disasm_one(arm64_ctx_t *ctx, arm64_insn_t *insn) {
    if (!ctx || !insn || ctx->pos + 4 > ctx->size) return false;
    memset(insn, 0, sizeof(arm64_insn_t));
    insn->opcode = read_u32(ctx->code + ctx->pos, ctx->big_endian);
    insn->address = ctx->address + ctx->pos;

    decoder_fn decoders[] = {dec_branch, dec_system, dec_pcrel, dec_condsel, dec_atomic,
                             dec_advsimd_ldst, dec_simd, dec_atomic_lse, dec_ldst, dec_bitfield, dec_data_imm, dec_data_reg};

    for (size_t i = 0; i < sizeof(decoders)/sizeof(decoders[0]); i++) {
        if (decoders[i](insn->opcode, insn)) {
            ctx->pos += 4;
            return true;
        }
    }

    insn->id = ARM64_INS_INVALID;
    ctx->pos += 4;
    return false;
}

arm64_insn_t arm64_disasm_addr(const uint8_t *addr, bool big_endian) {
    arm64_insn_t insn = {0};

    if (!addr) {
        insn.id = ARM64_INS_INVALID;
        return insn;
    }

    insn.opcode = read_u32(addr, big_endian);
    insn.address = (uint64_t)addr;

    decoder_fn decoders[] = {dec_branch, dec_system, dec_pcrel, dec_condsel, dec_atomic,
                             dec_advsimd_ldst, dec_simd, dec_atomic_lse, dec_ldst, dec_bitfield, dec_data_imm, dec_data_reg};

    for (size_t i = 0; i < sizeof(decoders)/sizeof(decoders[0]); i++) {
        if (decoders[i](insn.opcode, &insn)) {
            return insn;
        }
    }

    insn.id = ARM64_INS_INVALID;
    return insn;
}

const char *arm64_reg_name(arm64_reg_t reg) {
    static const char *names[] = {
        "none", "x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29","x30","xzr","sp",
        "w0","w1","w2","w3","w4","w5","w6","w7","w8","w9","w10","w11","w12","w13","w14","w15",
        "w16","w17","w18","w19","w20","w21","w22","w23","w24","w25","w26","w27","w28","w29","w30","wzr","wsp",
        "v0","v1","v2","v3","v4","v5","v6","v7","v8","v9","v10","v11","v12","v13","v14","v15",
        "v16","v17","v18","v19","v20","v21","v22","v23","v24","v25","v26","v27","v28","v29","v30","v31",
        "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","d10","d11","d12","d13","d14","d15",
        "d16","d17","d18","d19","d20","d21","d22","d23","d24","d25","d26","d27","d28","d29","d30","d31",
        "s0","s1","s2","s3","s4","s5","s6","s7","s8","s9","s10","s11","s12","s13","s14","s15",
        "s16","s17","s18","s19","s20","s21","s22","s23","s24","s25","s26","s27","s28","s29","s30","s31"
    };
    return reg < sizeof(names)/sizeof(names[0]) ? names[reg] : "?";
}

const char *arm64_cc_name(arm64_cc_t cc) {
    static const char *names[] = {"eq","ne","hs","lo","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"};
    return cc < 16 ? names[cc] : "?";
}

const char *arm64_prfop_name(uint8_t prfop) {
    // PRFM operation encoding: [TYPE][TARGET][POLICY]
    // TYPE: bits[4:3] - 00=PLD, 01=PLI, 10=PST, 11=reserved
    // TARGET: bits[2:1] - 00=L1, 01=L2, 10=L3, 11=reserved
    // POLICY: bit[0] - 0=KEEP, 1=STRM
    static const char *names[32] = {
        "pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
        "pldl3keep", "pldl3strm", "#6", "#7",
        "plil1keep", "plil1strm", "plil2keep", "plil2strm",
        "plil3keep", "plil3strm", "#14", "#15",
        "pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
        "pstl3keep", "pstl3strm", "#22", "#23",
        "#24", "#25", "#26", "#27", "#28", "#29", "#30", "#31"
    };
    return prfop < 32 ? names[prfop] : "?";
}

const char *arm64_barrier_name(uint8_t crm) {
    // Barrier scope encoding in CRm field [11:8]
    switch (crm) {
        case 0b0010: return "oshst";
        case 0b0011: return "osh";
        case 0b0110: return "nshst";
        case 0b0111: return "nsh";
        case 0b1010: return "ishst";
        case 0b1011: return "ish";
        case 0b1110: return "st";
        case 0b1111: return "sy";
        default: return "";  // Default - no scope shown
    }
}

static const char *arm64_extend_name(uint8_t extend_type) {
    // 0-7: extend types, 8-10: shift types for shifted register instructions
    static const char *extend_names[] = {"uxtb", "uxth", "uxtw", "lsl", "sxtb", "sxth", "sxtw", "sxtx",
                                         "lsl", "lsr", "asr"};
    return extend_type < 11 ? extend_names[extend_type] : "";
}

const char *arm64_sysreg_name(arm64_sysreg_t sysreg) {
    static const char* const sysreg_names[] = {
        [ARM64_SYSREG_NZCV] = "nzcv", [ARM64_SYSREG_FPCR] = "fpcr", [ARM64_SYSREG_FPSR] = "fpsr",
        [ARM64_SYSREG_TPIDR_EL0] = "tpidr_el0", [ARM64_SYSREG_TPIDRRO_EL0] = "tpidrro_el0",
        [ARM64_SYSREG_TPIDR_EL1] = "tpidr_el1", [ARM64_SYSREG_SP_EL0] = "sp_el0", [ARM64_SYSREG_SPSR_EL1] = "spsr_el1",
        [ARM64_SYSREG_ELR_EL1] = "elr_el1", [ARM64_SYSREG_SCTLR_EL1] = "sctlr_el1", [ARM64_SYSREG_ACTLR_EL1] = "actlr_el1",
        [ARM64_SYSREG_CPACR_EL1] = "cpacr_el1", [ARM64_SYSREG_TTBR0_EL1] = "ttbr0_el1", [ARM64_SYSREG_TTBR1_EL1] = "ttbr1_el1",
        [ARM64_SYSREG_TCR_EL1] = "tcr_el1", [ARM64_SYSREG_ESR_EL1] = "esr_el1", [ARM64_SYSREG_FAR_EL1] = "far_el1",
        [ARM64_SYSREG_MAIR_EL1] = "mair_el1", [ARM64_SYSREG_VBAR_EL1] = "vbar_el1", [ARM64_SYSREG_CONTEXTIDR_EL1] = "contextidr_el1",
        [ARM64_SYSREG_CNTKCTL_EL1] = "cntkctl_el1", [ARM64_SYSREG_CNTFRQ_EL0] = "cntfrq_el0", [ARM64_SYSREG_CNTPCT_EL0] = "cntpct_el0",
        [ARM64_SYSREG_CNTVCT_EL0] = "cntvct_el0", [ARM64_SYSREG_CNTP_CTL_EL0] = "cntp_ctl_el0", [ARM64_SYSREG_CNTP_CVAL_EL0] = "cntp_cval_el0",
        [ARM64_SYSREG_CNTV_CTL_EL0] = "cntv_ctl_el0", [ARM64_SYSREG_CNTV_CVAL_EL0] = "cntv_cval_el0", [ARM64_SYSREG_DAIF] = "daif",
        [ARM64_SYSREG_ICC_PMR_EL1] = "icc_pmr_el1", [ARM64_SYSREG_TPIDR_EL2] = "tpidr_el2"
    };
    return (sysreg < sizeof(sysreg_names)/sizeof(sysreg_names[0]) && sysreg_names[sysreg]) ? sysreg_names[sysreg] : "unknown";
}

void arm64_log_insn(const arm64_insn_t *i) {
    char insn_str[256] = {0};
    char *p = insn_str;
    char *end = insn_str + sizeof(insn_str);
    #define APP(...) p += snprintf(p, end > p ? end - p : 0, __VA_ARGS__)

    const char *mnem = NULL;
    bool skip = false;

    switch (i->id) {
        case ARM64_INS_ADD_IMM: case ARM64_INS_ADD_REG:
            if (i->op_count == 3 && ((i->operands[0].reg == ARM64_REG_SP && i->operands[2].type == ARM64_OP_IMM && !i->operands[2].imm) ||
                                     (i->operands[1].reg == ARM64_REG_SP && i->operands[2].type == ARM64_OP_IMM && !i->operands[2].imm))) {
                APP("mov\t%s, %s", arm64_reg_name(i->operands[0].reg),
                    i->operands[0].reg == ARM64_REG_SP ? arm64_reg_name(i->operands[1].reg) : "sp");
                skip = true;
            } else mnem = "add";
            break;
        case ARM64_INS_SUB_IMM: case ARM64_INS_SUB_REG: mnem = "sub"; break;
        case ARM64_INS_ADDS_IMM: case ARM64_INS_ADDS_REG: mnem = "adds"; break;
        case ARM64_INS_SUBS_IMM: case ARM64_INS_SUBS_REG: mnem = "subs"; break;
        case ARM64_INS_CMP_IMM: case ARM64_INS_CMP_REG: mnem = "cmp"; break;
        case ARM64_INS_CMN_IMM: case ARM64_INS_CMN_REG: mnem = "cmn"; break;
        case ARM64_INS_MUL: mnem = "mul"; break;
        case ARM64_INS_MADD: mnem = "madd"; break;
        case ARM64_INS_MSUB: mnem = "msub"; break;
        case ARM64_INS_MNEG: mnem = "mneg"; break;
        case ARM64_INS_UDIV: mnem = "udiv"; break;
        case ARM64_INS_SDIV: mnem = "sdiv"; break;
        case ARM64_INS_ADC: mnem = "adc"; break;
        case ARM64_INS_SBC: mnem = "sbc"; break;
        case ARM64_INS_ADCS: mnem = "adcs"; break;
        case ARM64_INS_SBCS: mnem = "sbcs"; break;
        case ARM64_INS_AND_REG: case ARM64_INS_AND_IMM: mnem = "and"; break;
        case ARM64_INS_ANDS_REG: case ARM64_INS_ANDS_IMM: mnem = "ands"; break;
        case ARM64_INS_TST_REG: case ARM64_INS_TST_IMM: mnem = "tst"; break;
        case ARM64_INS_ORR_REG: case ARM64_INS_ORR_IMM: mnem = "orr"; break;
        case ARM64_INS_EOR_REG: case ARM64_INS_EOR_IMM: mnem = "eor"; break;
        case ARM64_INS_LSL_REG: case ARM64_INS_LSL_IMM: mnem = "lsl"; break;
        case ARM64_INS_LSR_REG: case ARM64_INS_LSR_IMM: mnem = "lsr"; break;
        case ARM64_INS_ASR_REG: mnem = "asr"; break;
        case ARM64_INS_ROR_REG: case ARM64_INS_ROR_IMM: mnem = "ror"; break;
        case ARM64_INS_MOV_REG: mnem = "mov"; break;
        case ARM64_INS_MOVZ:
            pr_info("0x%llx: %08x mov\t%s, #0x%llx", (unsigned long long)i->address, i->opcode,
                    arm64_reg_name(i->operands[0].reg), (unsigned long long)i->operands[1].imm);
            return;
        case ARM64_INS_MOVN:
            pr_info("0x%llx: %08x mov\t%s, #0x%llx", (unsigned long long)i->address, i->opcode,
                    arm64_reg_name(i->operands[0].reg), (unsigned long long)~i->operands[1].imm);
            return;
        case ARM64_INS_MOVK:
            APP("movk\t%s, #0x%llx", arm64_reg_name(i->operands[0].reg), (unsigned long long)i->operands[1].imm);
            if (i->op_count == 3) APP(", lsl #%d", (int)i->operands[2].imm);
            pr_info("0x%llx: %08x %s", (unsigned long long)i->address, i->opcode, insn_str);
            return;
        case ARM64_INS_SBFM: mnem = "sbfm"; break;
        case ARM64_INS_BFM: mnem = "bfm"; break;
        case ARM64_INS_UBFM: mnem = "ubfm"; break;
        case ARM64_INS_SXTW: mnem = "sxtw"; break;
        case ARM64_INS_B: mnem = "b"; break;
        case ARM64_INS_BL: mnem = "bl"; break;
        case ARM64_INS_BR: mnem = "br"; break;
        case ARM64_INS_BLR: mnem = "blr"; break;
        case ARM64_INS_B_COND:
            pr_info("0x%llx: %08x b.%s\t0x%llx", (unsigned long long)i->address, i->opcode,
                    arm64_cc_name(i->operands[0].cc), (unsigned long long)(i->address + i->operands[1].imm));
            return;
        case ARM64_INS_CBZ: mnem = "cbz"; break;
        case ARM64_INS_CBNZ: mnem = "cbnz"; break;
        case ARM64_INS_TBZ: case ARM64_INS_TBNZ:
            pr_info("0x%llx: %08x %s\t%s, #%lld, 0x%llx", (unsigned long long)i->address, i->opcode,
                    i->id == ARM64_INS_TBZ ? "tbz" : "tbnz",
                    arm64_reg_name(i->operands[0].reg), (long long)i->operands[1].imm,
                    (unsigned long long)(i->address + i->operands[2].imm));
            return;
        case ARM64_INS_LDR_IMM: case ARM64_INS_LDR_POST: case ARM64_INS_LDR_PRE: case ARM64_INS_LDR_REG: mnem = "ldr"; break;
        case ARM64_INS_STR_IMM: case ARM64_INS_STR_POST: case ARM64_INS_STR_PRE: case ARM64_INS_STR_REG: mnem = "str"; break;
        case ARM64_INS_LDRB: mnem = "ldrb"; break;
        case ARM64_INS_STRB: mnem = "strb"; break;
        case ARM64_INS_LDRH: mnem = "ldrh"; break;
        case ARM64_INS_STRH: mnem = "strh"; break;
        case ARM64_INS_LDRSW: mnem = "ldrsw"; break;
        case ARM64_INS_LDP: mnem = "ldp"; break;
        case ARM64_INS_STP: mnem = "stp"; break;
        case ARM64_INS_LDUR: mnem = "ldur"; break;
        case ARM64_INS_STUR: mnem = "stur"; break;
        case ARM64_INS_PRFM: mnem = "prfm"; break;
        case ARM64_INS_LDXR: mnem = "ldxr"; break;
        case ARM64_INS_STXR: mnem = "stxr"; break;
        case ARM64_INS_LDAXR: mnem = "ldaxr"; break;
        case ARM64_INS_STLXR: mnem = "stlxr"; break;
        case ARM64_INS_LDAR: mnem = "ldar"; break;
        case ARM64_INS_LDAPR: mnem = "ldapr"; break;
        case ARM64_INS_STLR: mnem = "stlr"; break;
        case ARM64_INS_STLRB: mnem = "stlrb"; break;
        case ARM64_INS_STADD: mnem = "stadd"; break;
        case ARM64_INS_LDSETA: mnem = "ldseta"; break;
        case ARM64_INS_SWPA: mnem = "swph"; break;
        case ARM64_INS_CASA: mnem = "casa"; break;
        case ARM64_INS_CAS: mnem = "cas"; break;
        case ARM64_INS_NOP: pr_info("0x%llx: %08x nop", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_RET: pr_info("0x%llx: %08x ret", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_ISB: pr_info("0x%llx: %08x isb", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_DSB: mnem = "dsb"; break;
        case ARM64_INS_DMB: mnem = "dmb"; break;
        case ARM64_INS_SEVL: pr_info("0x%llx: %08x sevl", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_WFE: pr_info("0x%llx: %08x wfe", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_YIELD: pr_info("0x%llx: %08x yield", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_CSDB: pr_info("0x%llx: %08x csdb", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_BTI: pr_info("0x%llx: %08x bti\tj", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_PACIASP: pr_info("0x%llx: %08x paciasp", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_AUTIASP: pr_info("0x%llx: %08x autiasp", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_PACIAZ: pr_info("0x%llx: %08x paciaz", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_AUTIAZ: pr_info("0x%llx: %08x autiaz", (unsigned long long)i->address, i->opcode); return;
        case ARM64_INS_PACIA: mnem = "pacia"; break;
        case ARM64_INS_AUTIA: mnem = "autia"; break;
        case ARM64_INS_SVC: mnem = "svc"; break;
        case ARM64_INS_BRK: mnem = "brk"; break;
        case ARM64_INS_MRS: mnem = "mrs"; break;
        case ARM64_INS_MSR: mnem = "msr"; break;
        case ARM64_INS_ADRP:
            pr_info("0x%llx: %08x adrp\t%s, 0x%llx", (unsigned long long)i->address, i->opcode,
                    arm64_reg_name(i->operands[0].reg), (unsigned long long)i->operands[1].imm);
            return;
        case ARM64_INS_ADR:
            pr_info("0x%llx: %08x adr\t%s, 0x%llx", (unsigned long long)i->address, i->opcode,
                    arm64_reg_name(i->operands[0].reg), (unsigned long long)(i->address + i->operands[1].imm));
            return;
        case ARM64_INS_NGC: mnem = "ngc"; break;
        case ARM64_INS_LD1: mnem = "ld1"; break;
		case ARM64_INS_ST1: mnem = "st1"; break;
        case ARM64_INS_CSEL: case ARM64_INS_CSINC: case ARM64_INS_CSINV: case ARM64_INS_CSNEG: {
            const char *csn[] = {"csel", "csinc", "csinv", "csneg"};
            pr_info("0x%llx: %08x %s\t%s, %s, %s, %s", (unsigned long long)i->address, i->opcode,
                    csn[i->id - ARM64_INS_CSEL], arm64_reg_name(i->operands[0].reg),
                    arm64_reg_name(i->operands[1].reg), arm64_reg_name(i->operands[2].reg),
                    arm64_cc_name(i->operands[3].cc));
            return;
        }
        case ARM64_INS_FADD: mnem = "fadd"; break;
        case ARM64_INS_FSUB: mnem = "fsub"; break;
        case ARM64_INS_FMUL: mnem = "fmul"; break;
        case ARM64_INS_FDIV: mnem = "fdiv"; break;
        case ARM64_INS_FMOV: mnem = "fmov"; break;
        case ARM64_INS_FCMP: mnem = "fcmp"; break;
        case ARM64_INS_MOVI: mnem = "movi"; break;
        case ARM64_INS_ADD_VEC: mnem = "add"; break;
        default:
            pr_info("0x%llx: %08x .inst\t0x%08x", (unsigned long long)i->address, i->opcode, i->opcode);
            return;
    }

    if (skip) {
        pr_info("0x%llx: %s", (unsigned long long)i->address, insn_str);
        return;
    }

    if (mnem) APP("%s", mnem);
    if (i->op_count) APP("\t");

    for (int j = 0; j < i->op_count; j++) {
        const arm64_operand_t *op = &i->operands[j];
        if (op->type == ARM64_OP_COND) continue;

        switch (op->type) {
        	case ARM64_OP_INVALID:
		        // Should not happen
		        break;
		    case ARM64_OP_COND:
		        // Already handled - skip
		        break;
            case ARM64_OP_REG: APP("%s", arm64_reg_name(op->reg)); break;
            case ARM64_OP_REG_EXT:
                APP("%s", arm64_reg_name(op->reg_ext.reg));
                // Add extend/shift information
                if (op->reg_ext.extend_type != 0 || op->reg_ext.shift != 0) {
                    const char *extend_name = arm64_extend_name(op->reg_ext.extend_type);
                    if (strlen(extend_name) > 0) APP(", %s", extend_name);
                    if (op->reg_ext.shift > 0) APP(" #%d", op->reg_ext.shift);
                }
                break;
            case ARM64_OP_IMM:
                if (i->id >= ARM64_INS_B && i->id <= ARM64_INS_TBNZ)
                    APP("0x%llx", (unsigned long long)(i->address + op->imm));
                else if (i->id == ARM64_INS_PRFM && j == 0)
                    APP("%s", arm64_prfop_name((uint8_t)op->imm));
                else if ((i->id == ARM64_INS_DMB || i->id == ARM64_INS_DSB) && j == 0) {
                    const char *barrier_scope = arm64_barrier_name((uint8_t)op->imm);
                    if (strlen(barrier_scope) > 0)
                        APP("%s", barrier_scope);
                    else
                        APP("#0x%llx", (unsigned long long)op->imm);
                }
                else
                    APP("#0x%llx", (unsigned long long)op->imm);
                break;
            case ARM64_OP_IMM_SHIFT:
                APP("#0x%llx, lsl #%d", (unsigned long long)op->imm_shift.imm, op->imm_shift.shift);
                break;
            case ARM64_OP_MEM:
                APP("[%s", arm64_reg_name(op->mem.base));
                if (op->mem.index) {
                    APP(", %s", arm64_reg_name(op->mem.index));
                    const char *extend_name = arm64_extend_name(op->mem.extend_type);
                    if (strlen(extend_name) > 0 && !(op->mem.extend_type == 3 && !op->mem.shift)) {
                        APP(", %s", extend_name);
                    }
                    if (op->mem.shift) APP(" #%d", op->mem.shift);
                } else if (op->mem.disp && !op->mem.post_indexed) {
                    APP(", #%lld", (long long)op->mem.disp);
                }
                APP("]");
                if (op->mem.post_indexed) APP(", #%lld", (long long)op->mem.disp);
                if (op->mem.pre_indexed) APP("!");
                break;
            case ARM64_OP_SYSREG: APP("%s", arm64_sysreg_name(op->sysreg)); break;
        }
        if (j < i->op_count - 1 && i->operands[j + 1].type != ARM64_OP_COND) APP(", ");
    }

    pr_info("0x%llx: %08x %s", (unsigned long long)i->address, i->opcode, insn_str);
    #undef APP
}