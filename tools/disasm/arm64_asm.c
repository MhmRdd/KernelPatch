/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 mhmrdd. All Rights Reserved. */

/**
 * @file arm64_asm.c
 * @brief ARM64 Assembler Implementation - Reverse of arm64_disasm.c
 */

#include <disasm/arm64_asm.h>
#include <string.h>

/* Bit manipulation macros - reverse of BITS/BIT in arm64_disasm.c */
#define SET_BITS(val, h, l) (((val) & ((1u << ((h) - (l) + 1)) - 1)) << (l))
#define SET_BIT(val, n) (((val) & 1) << (n))

/* Register classification helpers - reverse of x_reg/w_reg in arm64_disasm.c */
bool arm64_asm_is_x_reg(arm64_reg_t reg) {
    return (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X30) ||
           reg == ARM64_REG_XZR || reg == ARM64_REG_SP;
}

bool arm64_asm_is_w_reg(arm64_reg_t reg) {
    return (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
           reg == ARM64_REG_WZR || reg == ARM64_REG_WSP;
}

static __unused bool is_v_reg(arm64_reg_t reg) {
    return reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31;
}

static __unused bool is_d_reg(arm64_reg_t reg) {
    return reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31;
}

static __unused bool is_s_reg(arm64_reg_t reg) {
    return reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31;
}

/* Extract register number - reverse of x_reg/w_reg/v_reg/d_reg/s_reg */
uint8_t arm64_asm_reg_num(arm64_reg_t reg) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X30) return reg - ARM64_REG_X0;
    if (reg == ARM64_REG_XZR || reg == ARM64_REG_WZR) return 31;
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return 31;
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return reg - ARM64_REG_W0;
    if (reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) return reg - ARM64_REG_V0;
    if (reg >= ARM64_REG_D0 && reg <= ARM64_REG_D31) return reg - ARM64_REG_D0;
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) return reg - ARM64_REG_S0;
    return 0;
}

/* Range check helpers */
bool arm64_asm_offset_in_range_b(int64_t offset) {
    return offset >= -(128 * 1024 * 1024) && offset < (128 * 1024 * 1024) && (offset & 3) == 0;
}

bool arm64_asm_offset_in_range_bcond(int64_t offset) {
    return offset >= -(1 * 1024 * 1024) && offset < (1 * 1024 * 1024) && (offset & 3) == 0;
}

bool arm64_asm_offset_in_range_tbz(int64_t offset) {
    return offset >= -(32 * 1024) && offset < (32 * 1024) && (offset & 3) == 0;
}

bool arm64_asm_offset_in_range_adr(int64_t offset) {
    return offset >= -(1 * 1024 * 1024) && offset < (1 * 1024 * 1024);
}

bool arm64_asm_offset_in_range_adrp(int64_t offset) {
    return offset >= -(4LL * 1024 * 1024 * 1024) && offset < (4LL * 1024 * 1024 * 1024);
}

/* System register encoding - reverse of decode_sysreg in arm64_disasm.c */
uint32_t arm64_asm_encode_sysreg(arm64_sysreg_t sysreg) {
    static const struct { arm64_sysreg_t reg; uint32_t key; } sysregs[] = {
        {ARM64_SYSREG_NZCV, 0x33420}, {ARM64_SYSREG_TPIDR_EL0, 0x30412}, {ARM64_SYSREG_TPIDRRO_EL0, 0x30d03},
        {ARM64_SYSREG_TPIDR_EL1, 0x30d04}, {ARM64_SYSREG_SP_EL0, 0x30410}, {ARM64_SYSREG_SPSR_EL1, 0x30400},
        {ARM64_SYSREG_ELR_EL1, 0x30401}, {ARM64_SYSREG_SCTLR_EL1, 0x30100}, {ARM64_SYSREG_ACTLR_EL1, 0x30101},
        {ARM64_SYSREG_CPACR_EL1, 0x30102}, {ARM64_SYSREG_TTBR0_EL1, 0x30200}, {ARM64_SYSREG_TTBR1_EL1, 0x30201},
        {ARM64_SYSREG_TCR_EL1, 0x30202}, {ARM64_SYSREG_ESR_EL1, 0x30520}, {ARM64_SYSREG_FAR_EL1, 0x30600},
        {ARM64_SYSREG_MAIR_EL1, 0x30a20}, {ARM64_SYSREG_VBAR_EL1, 0x30c00}, {ARM64_SYSREG_CONTEXTIDR_EL1, 0x30d01},
        {ARM64_SYSREG_CNTKCTL_EL1, 0x30e10}, {ARM64_SYSREG_CNTFRQ_EL0, 0x33e00}, {ARM64_SYSREG_CNTPCT_EL0, 0x33e01},
        {ARM64_SYSREG_CNTVCT_EL0, 0x33e02}, {ARM64_SYSREG_CNTP_CTL_EL0, 0x33e21}, {ARM64_SYSREG_CNTP_CVAL_EL0, 0x33e22},
        {ARM64_SYSREG_CNTV_CTL_EL0, 0x33e31}, {ARM64_SYSREG_CNTV_CVAL_EL0, 0x33e32}, {ARM64_SYSREG_DAIF, 0x33421},
        {ARM64_SYSREG_ICC_PMR_EL1, 0x30460}, {ARM64_SYSREG_TPIDR_EL2, 0x34d02}
    };
    for (size_t i = 0; i < sizeof(sysregs)/sizeof(sysregs[0]); i++) {
        if (sysregs[i].reg == sysreg) {
            uint32_t key = sysregs[i].key;
            /* Reconstruct op encoding from key: op0=3, op1=key[16:12], crn=key[11:8], crm=key[7:4], op2=key[3:0] */
            return SET_BITS(3, 20, 19) |
                   SET_BITS((key >> 12) & 7, 18, 16) |
                   SET_BITS((key >> 8) & 0xf, 15, 12) |
                   SET_BITS((key >> 4) & 0xf, 11, 8) |
                   SET_BITS(key & 0xf, 7, 5);
        }
    }
    return 0;
}

/* Logical immediate encoding - reverse of decode_log_imm in arm64_disasm.c */
bool arm64_asm_encode_log_imm(uint64_t val, bool is_64, uint8_t *n, uint8_t *imms, uint8_t *immr) {
    if (val == 0 || val == (is_64 ? ~0ULL : 0xFFFFFFFFULL)) return false;
    if (!is_64) val &= 0xFFFFFFFF;

    /* Try all possible element sizes */
    for (int len = is_64 ? 6 : 5; len >= 1; len--) {
        uint32_t esize = 1u << len;
        uint64_t emask = (1ULL << esize) - 1;

        /* Extract first element */
        uint64_t elem = val & emask;

        /* Check if pattern repeats */
        bool valid = true;
        for (uint32_t i = esize; i < (is_64 ? 64u : 32u); i += esize) {
            if (((val >> i) & emask) != elem) { valid = false; break; }
        }
        if (!valid) continue;

        /* Count ones in element */
        int ones = 0;
        for (uint32_t i = 0; i < esize; i++) if (elem & (1ULL << i)) ones++;

        /* Find rotation: element should be contiguous ones */
        for (uint32_t r = 0; r < esize; r++) {
            uint64_t rotated = ((elem >> r) | (elem << (esize - r))) & emask;
            /* Check if rotated is contiguous ones at bottom */
            uint64_t s_val = rotated;
            int count = 0;
            while (s_val & 1) { count++; s_val >>= 1; }
            if (count == ones && s_val == 0) {
                *n = (len == 6) ? 1 : 0;
                *imms = (~(esize - 1) & 0x3f) | (ones - 1);
                *immr = r;
                return true;
            }
        }
    }
    return false;
}

/* ========== Branch Instructions - reverse of dec_branch ========== */

uint32_t arm64_asm_b(int64_t offset) {
    /* B imm26: 000101 imm26 */
    uint32_t imm26 = (uint32_t)((offset >> 2) & 0x03FFFFFF);
    return 0x14000000 | imm26;
}

uint32_t arm64_asm_bl(int64_t offset) {
    /* BL imm26: 100101 imm26 */
    uint32_t imm26 = (uint32_t)((offset >> 2) & 0x03FFFFFF);
    return 0x94000000 | imm26;
}

uint32_t arm64_asm_b_cond(arm64_cc_t cc, int64_t offset) {
    /* B.cond imm19: 01010100 imm19 0 cond */
    uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
    return 0x54000000 | SET_BITS(imm19, 23, 5) | (cc & 0xf);
}

uint32_t arm64_asm_br(arm64_reg_t rn) {
    /* BR Xn: 1101011 0000 11111 000000 Rn 00000 */
    return 0xD61F0000 | SET_BITS(arm64_asm_reg_num(rn), 9, 5);
}

uint32_t arm64_asm_blr(arm64_reg_t rn) {
    /* BLR Xn: 1101011 0001 11111 000000 Rn 00000 */
    return 0xD63F0000 | SET_BITS(arm64_asm_reg_num(rn), 9, 5);
}

uint32_t arm64_asm_ret(arm64_reg_t rn) {
    /* RET Xn: 1101011 0010 11111 000000 Rn 00000 */
    if (rn == ARM64_REG_NONE) rn = ARM64_REG_X30;
    return 0xD65F0000 | SET_BITS(arm64_asm_reg_num(rn), 9, 5);
}

uint32_t arm64_asm_cbz(arm64_reg_t rt, int64_t offset) {
    /* CBZ Rt, imm19: sf 011010 0 imm19 Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
    return SET_BIT(is_64, 31) | 0x34000000 | SET_BITS(imm19, 23, 5) | arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_cbnz(arm64_reg_t rt, int64_t offset) {
    /* CBNZ Rt, imm19: sf 011010 1 imm19 Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint32_t imm19 = (uint32_t)((offset >> 2) & 0x7FFFF);
    return SET_BIT(is_64, 31) | 0x35000000 | SET_BITS(imm19, 23, 5) | arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_tbz(arm64_reg_t rt, uint8_t bit, int64_t offset) {
    /* TBZ Rt, #bit, imm14: b5 011011 0 b40 imm14 Rt */
    uint32_t imm14 = (uint32_t)((offset >> 2) & 0x3FFF);
    return SET_BIT(bit >> 5, 31) | 0x36000000 | SET_BITS(bit & 0x1f, 23, 19) |
           SET_BITS(imm14, 18, 5) | arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_tbnz(arm64_reg_t rt, uint8_t bit, int64_t offset) {
    /* TBNZ Rt, #bit, imm14: b5 011011 1 b40 imm14 Rt */
    uint32_t imm14 = (uint32_t)((offset >> 2) & 0x3FFF);
    return SET_BIT(bit >> 5, 31) | 0x37000000 | SET_BITS(bit & 0x1f, 23, 19) |
           SET_BITS(imm14, 18, 5) | arm64_asm_reg_num(rt);
}

/* ========== System Instructions - reverse of dec_system ========== */

uint32_t arm64_asm_nop(void) {
    return 0xD503201F;
}

uint32_t arm64_asm_svc(uint16_t imm) {
    /* SVC #imm16: 11010100 000 imm16 00001 */
    return 0xD4000001 | SET_BITS(imm, 20, 5);
}

uint32_t arm64_asm_brk(uint16_t imm) {
    /* BRK #imm16: 11010100 001 imm16 00000 */
    return 0xD4200000 | SET_BITS(imm, 20, 5);
}

uint32_t arm64_asm_hvc(uint16_t imm) {
    /* HVC #imm16: 11010100 000 imm16 00010 */
    return 0xD4000002 | SET_BITS(imm, 20, 5);
}

uint32_t arm64_asm_smc(uint16_t imm) {
    /* SMC #imm16: 11010100 000 imm16 00011 */
    return 0xD4000003 | SET_BITS(imm, 20, 5);
}

uint32_t arm64_asm_mrs(arm64_reg_t rt, arm64_sysreg_t sysreg) {
    /* MRS Xt, <sysreg>: 1101010100 1 1 op0 op1 crn crm op2 Rt */
    return 0xD5300000 | arm64_asm_encode_sysreg(sysreg) | arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_msr(arm64_sysreg_t sysreg, arm64_reg_t rt) {
    /* MSR <sysreg>, Xt: 1101010100 0 1 op0 op1 crn crm op2 Rt */
    return 0xD5100000 | arm64_asm_encode_sysreg(sysreg) | arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_isb(void) {
    return 0xD5033FDF;
}

uint32_t arm64_asm_dsb(uint8_t option) {
    /* DSB <option>: 1101010100 0 00 011 0011 CRm 1 00 11111 */
    return 0xD503309F | SET_BITS(option, 11, 8);
}

uint32_t arm64_asm_dmb(uint8_t option) {
    /* DMB <option>: 1101010100 0 00 011 0011 CRm 1 01 11111 */
    return 0xD50330BF | SET_BITS(option, 11, 8);
}

/* ========== Hint Instructions ========== */

uint32_t arm64_asm_yield(void) {
    return 0xD503203F;
}

uint32_t arm64_asm_wfe(void) {
    return 0xD503205F;
}

uint32_t arm64_asm_wfi(void) {
    return 0xD503207F;
}

uint32_t arm64_asm_sev(void) {
    return 0xD503209F;
}

uint32_t arm64_asm_sevl(void) {
    return 0xD50320BF;
}

uint32_t arm64_asm_csdb(void) {
    return 0xD503229F;
}

uint32_t arm64_asm_bti(uint8_t targets) {
    /* BTI <targets>: 1101010100 0 00 011 0010 0100 000 11111 */
    /* targets: 0=none, 1=c, 2=j, 3=jc */
    return 0xD503241F | SET_BITS(targets, 7, 6);
}

/* ========== PAC Instructions ========== */

uint32_t arm64_asm_paciasp(void) {
    return 0xD503233F;
}

uint32_t arm64_asm_autiasp(void) {
    return 0xD50323BF;
}

uint32_t arm64_asm_paciaz(void) {
    return 0xD503231F;
}

uint32_t arm64_asm_autiaz(void) {
    return 0xD503239F;
}

uint32_t arm64_asm_pacibsp(void) {
    return 0xD503237F;
}

uint32_t arm64_asm_autibsp(void) {
    return 0xD50323FF;
}

/* ========== Data Processing Immediate - reverse of dec_data_imm ========== */

uint32_t arm64_asm_movz(arm64_reg_t rd, uint16_t imm, uint8_t shift) {
    /* MOVZ: sf 10 100101 hw imm16 Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint8_t hw = shift / 16;
    return SET_BIT(is_64, 31) | 0x52800000 | SET_BITS(hw, 22, 21) |
           SET_BITS(imm, 20, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_movn(arm64_reg_t rd, uint16_t imm, uint8_t shift) {
    /* MOVN: sf 00 100101 hw imm16 Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint8_t hw = shift / 16;
    return SET_BIT(is_64, 31) | 0x12800000 | SET_BITS(hw, 22, 21) |
           SET_BITS(imm, 20, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_movk(arm64_reg_t rd, uint16_t imm, uint8_t shift) {
    /* MOVK: sf 11 100101 hw imm16 Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint8_t hw = shift / 16;
    return SET_BIT(is_64, 31) | 0x72800000 | SET_BITS(hw, 22, 21) |
           SET_BITS(imm, 20, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_add_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift) {
    /* ADD imm: sf 0 0 10001 sh imm12 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x11000000 | SET_BIT(shift, 22) |
           SET_BITS(imm12 & 0xfff, 21, 10) | SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_sub_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift) {
    /* SUB imm: sf 1 0 10001 sh imm12 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x51000000 | SET_BIT(shift, 22) |
           SET_BITS(imm12 & 0xfff, 21, 10) | SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_adds_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift) {
    /* ADDS imm: sf 0 1 10001 sh imm12 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x31000000 | SET_BIT(shift, 22) |
           SET_BITS(imm12 & 0xfff, 21, 10) | SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_subs_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift) {
    /* SUBS imm: sf 1 1 10001 sh imm12 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x71000000 | SET_BIT(shift, 22) |
           SET_BITS(imm12 & 0xfff, 21, 10) | SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_cmp_imm(arm64_reg_t rn, uint32_t imm12, bool shift) {
    /* CMP imm = SUBS XZR/WZR, Rn, imm */
    bool is_64 = arm64_asm_is_x_reg(rn);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_subs_imm(zr, rn, imm12, shift);
}

uint32_t arm64_asm_cmn_imm(arm64_reg_t rn, uint32_t imm12, bool shift) {
    /* CMN imm = ADDS XZR/WZR, Rn, imm */
    bool is_64 = arm64_asm_is_x_reg(rn);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_adds_imm(zr, rn, imm12, shift);
}

/* ========== Logical Immediate - reverse of decode_log_imm ========== */

static uint32_t log_imm_base(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm, uint8_t opc) {
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint8_t n, imms, immr;
    if (!arm64_asm_encode_log_imm(imm, is_64, &n, &imms, &immr)) return 0;
    return SET_BIT(is_64, 31) | SET_BITS(opc, 30, 29) | 0x12000000 |
           SET_BIT(n, 22) | SET_BITS(immr, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_and_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm) {
    return log_imm_base(rd, rn, imm, 0);  /* opc=00 */
}

uint32_t arm64_asm_orr_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm) {
    return log_imm_base(rd, rn, imm, 1);  /* opc=01 */
}

uint32_t arm64_asm_eor_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm) {
    return log_imm_base(rd, rn, imm, 2);  /* opc=10 */
}

uint32_t arm64_asm_ands_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm) {
    return log_imm_base(rd, rn, imm, 3);  /* opc=11 */
}

uint32_t arm64_asm_tst_imm(arm64_reg_t rn, uint64_t imm) {
    /* TST imm = ANDS XZR/WZR, Rn, imm */
    bool is_64 = arm64_asm_is_x_reg(rn);
    return arm64_asm_ands_imm(is_64 ? ARM64_REG_XZR : ARM64_REG_WZR, rn, imm);
}

/* ========== Bitfield Operations - reverse of dec_bitfield ========== */

uint32_t arm64_asm_sbfm(arm64_reg_t rd, arm64_reg_t rn, uint8_t immr, uint8_t imms) {
    /* SBFM: sf 00 100110 N immr imms Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x13000000 |
           SET_BITS(immr, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_bfm(arm64_reg_t rd, arm64_reg_t rn, uint8_t immr, uint8_t imms) {
    /* BFM: sf 01 100110 N immr imms Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x33000000 |
           SET_BITS(immr, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_ubfm(arm64_reg_t rd, arm64_reg_t rn, uint8_t immr, uint8_t imms) {
    /* UBFM: sf 10 100110 N immr imms Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x53000000 |
           SET_BITS(immr, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_sxtw(arm64_reg_t rd, arm64_reg_t rn) {
    /* SXTW Xd, Wn = SBFM Xd, Wn, #0, #31 */
    return arm64_asm_sbfm(rd, rn, 0, 31);
}

uint32_t arm64_asm_ror_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift) {
    /* ROR imm = EXTR Rd, Rn, Rn, #shift */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x13800000 |
           SET_BITS(arm64_asm_reg_num(rn), 20, 16) |
           SET_BITS(shift, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

/* ========== Data Processing Register - reverse of dec_data_reg ========== */

uint32_t arm64_asm_add_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ADD reg (shifted): sf 0 0 01011 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x0B000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_sub_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* SUB reg (shifted): sf 1 0 01011 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x4B000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_adds_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ADDS reg: sf 0 1 01011 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x2B000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_subs_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* SUBS reg: sf 1 1 01011 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x6B000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_cmp_reg(arm64_reg_t rn, arm64_reg_t rm) {
    /* CMP reg = SUBS XZR/WZR, Rn, Rm */
    bool is_64 = arm64_asm_is_x_reg(rn);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_subs_reg(zr, rn, rm);
}

uint32_t arm64_asm_cmn_reg(arm64_reg_t rn, arm64_reg_t rm) {
    /* CMN reg = ADDS XZR/WZR, Rn, Rm */
    bool is_64 = arm64_asm_is_x_reg(rn);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_adds_reg(zr, rn, rm);
}

uint32_t arm64_asm_and_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* AND reg: sf 00 01010 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x0A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_orr_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ORR reg: sf 01 01010 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x2A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_eor_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* EOR reg: sf 10 01010 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x4A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_ands_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ANDS reg: sf 11 01010 shift 0 Rm imm6 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x6A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_tst_reg(arm64_reg_t rn, arm64_reg_t rm) {
    /* TST reg = ANDS XZR/WZR, Rn, Rm */
    bool is_64 = arm64_asm_is_x_reg(rn);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_ands_reg(zr, rn, rm);
}

uint32_t arm64_asm_mov_reg(arm64_reg_t rd, arm64_reg_t rm) {
    /* MOV reg = ORR Rd, XZR, Rm */
    bool is_64 = arm64_asm_is_x_reg(rd);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_orr_reg(rd, zr, rm);
}

/* ========== Multiply/Divide ========== */

uint32_t arm64_asm_mul(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* MUL = MADD Rd, Rn, Rm, XZR */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return arm64_asm_madd(rd, rn, rm, is_64 ? ARM64_REG_XZR : ARM64_REG_WZR);
}

uint32_t arm64_asm_madd(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_reg_t ra) {
    /* MADD: sf 00 11011 000 Rm 0 Ra Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1B000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(ra), 14, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_msub(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_reg_t ra) {
    /* MSUB: sf 00 11011 000 Rm 1 Ra Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1B008000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(ra), 14, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_udiv(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* UDIV: sf 0 0 11010110 Rm 00001 0 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1AC00800 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_sdiv(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* SDIV: sf 0 0 11010110 Rm 00001 1 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1AC00C00 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

/* ========== Add/Subtract with Carry ========== */

uint32_t arm64_asm_adc(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ADC: sf 0 0 11010000 Rm 000000 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_sbc(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* SBC: sf 1 0 11010000 Rm 000000 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x5A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_adcs(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ADCS: sf 0 1 11010000 Rm 000000 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x3A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_sbcs(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* SBCS: sf 1 1 11010000 Rm 000000 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x7A000000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_ngc(arm64_reg_t rd, arm64_reg_t rm) {
    /* NGC = SBC Rd, XZR, Rm */
    bool is_64 = arm64_asm_is_x_reg(rd);
    arm64_reg_t zr = is_64 ? ARM64_REG_XZR : ARM64_REG_WZR;
    return arm64_asm_sbc(rd, zr, rm);
}

/* ========== Shifts - reverse of dec_bitfield ========== */

uint32_t arm64_asm_lsl_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift) {
    /* LSL imm = UBFM Rd, Rn, #(-shift MOD datasize), #(datasize-1-shift) */
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint32_t datasize = is_64 ? 64 : 32;
    uint32_t immr = (datasize - shift) % datasize;
    uint32_t imms = datasize - 1 - shift;
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x53000000 |
           SET_BITS(immr, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_lsr_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift) {
    /* LSR imm = UBFM Rd, Rn, #shift, #(datasize-1) */
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint32_t datasize = is_64 ? 64 : 32;
    uint32_t imms = datasize - 1;
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x53000000 |
           SET_BITS(shift, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_asr_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift) {
    /* ASR imm = SBFM Rd, Rn, #shift, #(datasize-1) */
    bool is_64 = arm64_asm_is_x_reg(rd);
    uint32_t datasize = is_64 ? 64 : 32;
    uint32_t imms = datasize - 1;
    return SET_BIT(is_64, 31) | SET_BIT(is_64, 22) | 0x13000000 |
           SET_BITS(shift, 21, 16) | SET_BITS(imms, 15, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) | arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_lsl_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* LSL reg: sf 0 0 11010110 Rm 0010 00 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1AC02000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_lsr_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* LSR reg: sf 0 0 11010110 Rm 0010 01 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1AC02400 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_asr_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ASR reg: sf 0 0 11010110 Rm 0010 10 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1AC02800 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_ror_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm) {
    /* ROR reg: sf 0 0 11010110 Rm 0010 11 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1AC02C00 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

/* ========== Load/Store - reverse of dec_ldst ========== */

uint32_t arm64_asm_ldr_imm(arm64_reg_t rt, arm64_reg_t rn, int64_t offset) {
    /* LDR (unsigned offset): size 11 1 00 1 01 imm12 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    uint32_t imm12 = (uint32_t)(offset >> size) & 0xFFF;
    return SET_BITS(size, 31, 30) | 0x39400000 |
           SET_BITS(imm12, 21, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_str_imm(arm64_reg_t rt, arm64_reg_t rn, int64_t offset) {
    /* STR (unsigned offset): size 11 1 00 1 00 imm12 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    uint32_t imm12 = (uint32_t)(offset >> size) & 0xFFF;
    return SET_BITS(size, 31, 30) | 0x39000000 |
           SET_BITS(imm12, 21, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_ldr_reg(arm64_reg_t rt, arm64_reg_t rn, arm64_reg_t rm) {
    /* LDR (register): size 11 1 00 0 01 1 Rm option S 10 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    return SET_BITS(size, 31, 30) | 0x38600800 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(3, 15, 13) |  /* option=LSL */
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_str_reg(arm64_reg_t rt, arm64_reg_t rn, arm64_reg_t rm) {
    /* STR (register): size 11 1 00 0 00 1 Rm option S 10 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    return SET_BITS(size, 31, 30) | 0x38200800 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(3, 15, 13) |  /* option=LSL */
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_ldp(arm64_reg_t rt, arm64_reg_t rt2, arm64_reg_t rn, int64_t offset) {
    /* LDP: opc 10 1 0 0 01 1 imm7 Rt2 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t scale = is_64 ? 3 : 2;
    uint32_t imm7 = (uint32_t)(offset >> scale) & 0x7F;
    return SET_BIT(is_64, 31) | 0x29400000 |
           SET_BITS(imm7, 21, 15) |
           SET_BITS(arm64_asm_reg_num(rt2), 14, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_stp(arm64_reg_t rt, arm64_reg_t rt2, arm64_reg_t rn, int64_t offset) {
    /* STP: opc 10 1 0 0 01 0 imm7 Rt2 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t scale = is_64 ? 3 : 2;
    uint32_t imm7 = (uint32_t)(offset >> scale) & 0x7F;
    return SET_BIT(is_64, 31) | 0x29000000 |
           SET_BITS(imm7, 21, 15) |
           SET_BITS(arm64_asm_reg_num(rt2), 14, 10) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_ldr_pre(arm64_reg_t rt, arm64_reg_t rn, int64_t offset) {
    /* LDR (pre-index): size 11 1 00 0 01 0 imm9 11 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    uint32_t imm9 = (uint32_t)offset & 0x1FF;
    return SET_BITS(size, 31, 30) | 0x38400C00 |
           SET_BITS(imm9, 20, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_str_pre(arm64_reg_t rt, arm64_reg_t rn, int64_t offset) {
    /* STR (pre-index): size 11 1 00 0 00 0 imm9 11 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    uint32_t imm9 = (uint32_t)offset & 0x1FF;
    return SET_BITS(size, 31, 30) | 0x38000C00 |
           SET_BITS(imm9, 20, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_ldr_post(arm64_reg_t rt, arm64_reg_t rn, int64_t offset) {
    /* LDR (post-index): size 11 1 00 0 01 0 imm9 01 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    uint32_t imm9 = (uint32_t)offset & 0x1FF;
    return SET_BITS(size, 31, 30) | 0x38400400 |
           SET_BITS(imm9, 20, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_str_post(arm64_reg_t rt, arm64_reg_t rn, int64_t offset) {
    /* STR (post-index): size 11 1 00 0 00 0 imm9 01 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    uint8_t size = is_64 ? 3 : 2;
    uint32_t imm9 = (uint32_t)offset & 0x1FF;
    return SET_BITS(size, 31, 30) | 0x38000400 |
           SET_BITS(imm9, 20, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

/* ========== PC-relative - reverse of dec_pcrel ========== */

uint32_t arm64_asm_adr(arm64_reg_t rd, int64_t offset) {
    /* ADR: 0 immlo 1 0000 immhi Rd */
    uint32_t imm = (uint32_t)offset & 0x1FFFFF;
    return 0x10000000 |
           SET_BITS(imm >> 2, 23, 5) |
           SET_BITS(imm & 3, 30, 29) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_adrp(arm64_reg_t rd, int64_t offset) {
    /* ADRP: 1 immlo 1 0000 immhi Rd */
    uint32_t imm = (uint32_t)(offset >> 12) & 0x1FFFFF;
    return 0x90000000 |
           SET_BITS(imm >> 2, 23, 5) |
           SET_BITS(imm & 3, 30, 29) |
           arm64_asm_reg_num(rd);
}

/* ========== Conditional Select - reverse of dec_condsel ========== */

uint32_t arm64_asm_csel(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc) {
    /* CSEL: sf 0 0 11010100 Rm cond 0 0 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1A800000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(cc, 15, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_csinc(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc) {
    /* CSINC: sf 0 0 11010100 Rm cond 0 1 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x1A800400 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(cc, 15, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_csinv(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc) {
    /* CSINV: sf 1 0 11010100 Rm cond 0 0 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x5A800000 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(cc, 15, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

uint32_t arm64_asm_csneg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc) {
    /* CSNEG: sf 1 0 11010100 Rm cond 0 1 Rn Rd */
    bool is_64 = arm64_asm_is_x_reg(rd);
    return SET_BIT(is_64, 31) | 0x5A800400 |
           SET_BITS(arm64_asm_reg_num(rm), 20, 16) |
           SET_BITS(cc, 15, 12) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rd);
}

/* ========== Atomics - reverse of dec_atomic ========== */

uint32_t arm64_asm_ldxr(arm64_reg_t rt, arm64_reg_t rn) {
    /* LDXR: size 001000 0 1 0 11111 0 11111 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    return SET_BITS(is_64 ? 3 : 2, 31, 30) | 0x08407C00 |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_stxr(arm64_reg_t rs, arm64_reg_t rt, arm64_reg_t rn) {
    /* STXR: size 001000 0 0 0 Rs 0 11111 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    return SET_BITS(is_64 ? 3 : 2, 31, 30) | 0x08007C00 |
           SET_BITS(arm64_asm_reg_num(rs), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_ldaxr(arm64_reg_t rt, arm64_reg_t rn) {
    /* LDAXR: size 001000 0 1 0 11111 1 11111 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    return SET_BITS(is_64 ? 3 : 2, 31, 30) | 0x0840FC00 |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_stlxr(arm64_reg_t rs, arm64_reg_t rt, arm64_reg_t rn) {
    /* STLXR: size 001000 0 0 0 Rs 1 11111 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    return SET_BITS(is_64 ? 3 : 2, 31, 30) | 0x0800FC00 |
           SET_BITS(arm64_asm_reg_num(rs), 20, 16) |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_ldar(arm64_reg_t rt, arm64_reg_t rn) {
    /* LDAR: size 001000 1 1 0 11111 1 11111 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    return SET_BITS(is_64 ? 3 : 2, 31, 30) | 0x08DFFC00 |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

uint32_t arm64_asm_stlr(arm64_reg_t rt, arm64_reg_t rn) {
    /* STLR: size 001000 1 0 0 11111 1 11111 Rn Rt */
    bool is_64 = arm64_asm_is_x_reg(rt);
    return SET_BITS(is_64 ? 3 : 2, 31, 30) | 0x089FFC00 |
           SET_BITS(arm64_asm_reg_num(rn), 9, 5) |
           arm64_asm_reg_num(rt);
}

/* ========== Encode from arm64_insn_t structure ========== */

arm64_asm_err_t arm64_asm_insn(const arm64_insn_t *insn, uint32_t *out) {
    if (!insn || !out) return ARM64_ASM_ERR_INVALID_INSN;

    switch (insn->id) {
        /* Branch */
        case ARM64_INS_B:
            *out = arm64_asm_b(insn->operands[0].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_BL:
            *out = arm64_asm_bl(insn->operands[0].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_B_COND:
            *out = arm64_asm_b_cond(insn->operands[0].cc, insn->operands[1].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_BR:
            *out = arm64_asm_br(insn->operands[0].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_BLR:
            *out = arm64_asm_blr(insn->operands[0].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_RET:
            *out = arm64_asm_ret(insn->op_count ? insn->operands[0].reg : ARM64_REG_X30);
            return ARM64_ASM_OK;
        case ARM64_INS_CBZ:
            *out = arm64_asm_cbz(insn->operands[0].reg, insn->operands[1].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_CBNZ:
            *out = arm64_asm_cbnz(insn->operands[0].reg, insn->operands[1].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_TBZ:
            *out = arm64_asm_tbz(insn->operands[0].reg, (uint8_t)insn->operands[1].imm, insn->operands[2].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_TBNZ:
            *out = arm64_asm_tbnz(insn->operands[0].reg, (uint8_t)insn->operands[1].imm, insn->operands[2].imm);
            return ARM64_ASM_OK;

        /* System */
        case ARM64_INS_NOP:
            *out = arm64_asm_nop();
            return ARM64_ASM_OK;
        case ARM64_INS_SVC:
            *out = arm64_asm_svc((uint16_t)insn->operands[0].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_BRK:
            *out = arm64_asm_brk((uint16_t)insn->operands[0].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_MRS:
            *out = arm64_asm_mrs(insn->operands[0].reg, insn->operands[1].sysreg);
            return ARM64_ASM_OK;
        case ARM64_INS_MSR:
            *out = arm64_asm_msr(insn->operands[0].sysreg, insn->operands[1].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_ISB:
            *out = arm64_asm_isb();
            return ARM64_ASM_OK;
        case ARM64_INS_DSB:
            *out = arm64_asm_dsb((uint8_t)insn->operands[0].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_DMB:
            *out = arm64_asm_dmb((uint8_t)insn->operands[0].imm);
            return ARM64_ASM_OK;

        /* PAC */
        case ARM64_INS_PACIASP:
            *out = arm64_asm_paciasp();
            return ARM64_ASM_OK;
        case ARM64_INS_AUTIASP:
            *out = arm64_asm_autiasp();
            return ARM64_ASM_OK;
        case ARM64_INS_PACIAZ:
            *out = arm64_asm_paciaz();
            return ARM64_ASM_OK;
        case ARM64_INS_AUTIAZ:
            *out = arm64_asm_autiaz();
            return ARM64_ASM_OK;

        /* Data processing */
        case ARM64_INS_MOV_REG:
            *out = arm64_asm_mov_reg(insn->operands[0].reg, insn->operands[1].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_MOVZ:
            *out = arm64_asm_movz(insn->operands[0].reg, (uint16_t)insn->operands[1].imm, 0);
            return ARM64_ASM_OK;
        case ARM64_INS_MOVN:
            *out = arm64_asm_movn(insn->operands[0].reg, (uint16_t)insn->operands[1].imm, 0);
            return ARM64_ASM_OK;
        case ARM64_INS_MOVK:
            *out = arm64_asm_movk(insn->operands[0].reg, (uint16_t)insn->operands[1].imm,
                                  insn->op_count >= 3 ? (uint8_t)insn->operands[2].imm : 0);
            return ARM64_ASM_OK;
        case ARM64_INS_ADD_IMM:
            *out = arm64_asm_add_imm(insn->operands[0].reg, insn->operands[1].reg,
                                     (uint32_t)insn->operands[2].imm, false);
            return ARM64_ASM_OK;
        case ARM64_INS_SUB_IMM:
            *out = arm64_asm_sub_imm(insn->operands[0].reg, insn->operands[1].reg,
                                     (uint32_t)insn->operands[2].imm, false);
            return ARM64_ASM_OK;
        case ARM64_INS_ADD_REG:
            *out = arm64_asm_add_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_SUB_REG:
            *out = arm64_asm_sub_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_AND_REG:
            *out = arm64_asm_and_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_ORR_REG:
            *out = arm64_asm_orr_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_EOR_REG:
            *out = arm64_asm_eor_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_MUL:
            *out = arm64_asm_mul(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_MADD:
            *out = arm64_asm_madd(insn->operands[0].reg, insn->operands[1].reg,
                                  insn->operands[2].reg, insn->operands[3].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_MSUB:
            *out = arm64_asm_msub(insn->operands[0].reg, insn->operands[1].reg,
                                  insn->operands[2].reg, insn->operands[3].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_UDIV:
            *out = arm64_asm_udiv(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_SDIV:
            *out = arm64_asm_sdiv(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;

        /* Shifts */
        case ARM64_INS_LSL_IMM:
            *out = arm64_asm_lsl_imm(insn->operands[0].reg, insn->operands[1].reg, (uint8_t)insn->operands[2].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_LSR_IMM:
            *out = arm64_asm_lsr_imm(insn->operands[0].reg, insn->operands[1].reg, (uint8_t)insn->operands[2].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_LSL_REG:
            *out = arm64_asm_lsl_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_LSR_REG:
            *out = arm64_asm_lsr_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;
        case ARM64_INS_ASR_REG:
            *out = arm64_asm_asr_reg(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].reg);
            return ARM64_ASM_OK;

        /* PC-relative */
        case ARM64_INS_ADR:
            *out = arm64_asm_adr(insn->operands[0].reg, insn->operands[1].imm);
            return ARM64_ASM_OK;
        case ARM64_INS_ADRP:
            *out = arm64_asm_adrp(insn->operands[0].reg, insn->operands[1].imm);
            return ARM64_ASM_OK;

        /* Conditional select */
        case ARM64_INS_CSEL:
            *out = arm64_asm_csel(insn->operands[0].reg, insn->operands[1].reg,
                                  insn->operands[2].reg, insn->operands[3].cc);
            return ARM64_ASM_OK;
        case ARM64_INS_CSINC:
            *out = arm64_asm_csinc(insn->operands[0].reg, insn->operands[1].reg,
                                   insn->operands[2].reg, insn->operands[3].cc);
            return ARM64_ASM_OK;
        case ARM64_INS_CSINV:
            *out = arm64_asm_csinv(insn->operands[0].reg, insn->operands[1].reg,
                                   insn->operands[2].reg, insn->operands[3].cc);
            return ARM64_ASM_OK;
        case ARM64_INS_CSNEG:
            *out = arm64_asm_csneg(insn->operands[0].reg, insn->operands[1].reg,
                                   insn->operands[2].reg, insn->operands[3].cc);
            return ARM64_ASM_OK;

        /* Atomics */
        case ARM64_INS_LDXR:
            *out = arm64_asm_ldxr(insn->operands[0].reg, insn->operands[1].mem.base);
            return ARM64_ASM_OK;
        case ARM64_INS_STXR:
            *out = arm64_asm_stxr(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].mem.base);
            return ARM64_ASM_OK;
        case ARM64_INS_LDAXR:
            *out = arm64_asm_ldaxr(insn->operands[0].reg, insn->operands[1].mem.base);
            return ARM64_ASM_OK;
        case ARM64_INS_STLXR:
            *out = arm64_asm_stlxr(insn->operands[0].reg, insn->operands[1].reg, insn->operands[2].mem.base);
            return ARM64_ASM_OK;
        case ARM64_INS_LDAR:
            *out = arm64_asm_ldar(insn->operands[0].reg, insn->operands[1].mem.base);
            return ARM64_ASM_OK;
        case ARM64_INS_STLR:
            *out = arm64_asm_stlr(insn->operands[0].reg, insn->operands[1].mem.base);
            return ARM64_ASM_OK;

        default:
            return ARM64_ASM_ERR_UNSUPPORTED;
    }
}