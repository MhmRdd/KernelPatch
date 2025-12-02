/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 mhmrdd. All Rights Reserved. */

/*
 * ARM64 Assembler Library
 *
 * Lightweight ARM64 instruction encoding - reverse of arm64_disasm.
 * Imports types from arm64_disasm.h to avoid duplication.
 */

#ifndef ARM64_ASM_H
#define ARM64_ASM_H

#include "arm64_disasm.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Assembler result codes */
typedef enum {
    ARM64_ASM_OK = 0,
    ARM64_ASM_ERR_INVALID_INSN,
    ARM64_ASM_ERR_INVALID_OPERAND,
    ARM64_ASM_ERR_INVALID_REG,
    ARM64_ASM_ERR_OFFSET_RANGE,
    ARM64_ASM_ERR_IMM_RANGE,
    ARM64_ASM_ERR_ALIGN,
    ARM64_ASM_ERR_UNSUPPORTED
} arm64_asm_err_t;

/* Encode from arm64_insn_t structure */
arm64_asm_err_t arm64_asm_insn(const arm64_insn_t *insn, uint32_t *out);

/* Branch instructions */
uint32_t arm64_asm_b(int64_t offset);
uint32_t arm64_asm_bl(int64_t offset);
uint32_t arm64_asm_b_cond(arm64_cc_t cc, int64_t offset);
uint32_t arm64_asm_br(arm64_reg_t rn);
uint32_t arm64_asm_blr(arm64_reg_t rn);
uint32_t arm64_asm_ret(arm64_reg_t rn);
uint32_t arm64_asm_cbz(arm64_reg_t rt, int64_t offset);
uint32_t arm64_asm_cbnz(arm64_reg_t rt, int64_t offset);
uint32_t arm64_asm_tbz(arm64_reg_t rt, uint8_t bit, int64_t offset);
uint32_t arm64_asm_tbnz(arm64_reg_t rt, uint8_t bit, int64_t offset);

/* System instructions */
uint32_t arm64_asm_nop(void);
uint32_t arm64_asm_svc(uint16_t imm);
uint32_t arm64_asm_brk(uint16_t imm);
uint32_t arm64_asm_hvc(uint16_t imm);
uint32_t arm64_asm_smc(uint16_t imm);
uint32_t arm64_asm_mrs(arm64_reg_t rt, arm64_sysreg_t sysreg);
uint32_t arm64_asm_msr(arm64_sysreg_t sysreg, arm64_reg_t rt);
uint32_t arm64_asm_isb(void);
uint32_t arm64_asm_dsb(uint8_t option);
uint32_t arm64_asm_dmb(uint8_t option);

/* Hint instructions */
uint32_t arm64_asm_yield(void);
uint32_t arm64_asm_wfe(void);
uint32_t arm64_asm_wfi(void);
uint32_t arm64_asm_sev(void);
uint32_t arm64_asm_sevl(void);
uint32_t arm64_asm_csdb(void);
uint32_t arm64_asm_bti(uint8_t targets);

/* PAC instructions */
uint32_t arm64_asm_paciasp(void);
uint32_t arm64_asm_autiasp(void);
uint32_t arm64_asm_paciaz(void);
uint32_t arm64_asm_autiaz(void);
uint32_t arm64_asm_pacibsp(void);
uint32_t arm64_asm_autibsp(void);

/* Data processing - immediate */
uint32_t arm64_asm_movz(arm64_reg_t rd, uint16_t imm, uint8_t shift);
uint32_t arm64_asm_movn(arm64_reg_t rd, uint16_t imm, uint8_t shift);
uint32_t arm64_asm_movk(arm64_reg_t rd, uint16_t imm, uint8_t shift);
uint32_t arm64_asm_add_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift);
uint32_t arm64_asm_sub_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift);
uint32_t arm64_asm_adds_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift);
uint32_t arm64_asm_subs_imm(arm64_reg_t rd, arm64_reg_t rn, uint32_t imm12, bool shift);
uint32_t arm64_asm_cmp_imm(arm64_reg_t rn, uint32_t imm12, bool shift);
uint32_t arm64_asm_cmn_imm(arm64_reg_t rn, uint32_t imm12, bool shift);

/* Logical immediate - uses arm64_asm_encode_log_imm internally */
uint32_t arm64_asm_and_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm);
uint32_t arm64_asm_orr_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm);
uint32_t arm64_asm_eor_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm);
uint32_t arm64_asm_ands_imm(arm64_reg_t rd, arm64_reg_t rn, uint64_t imm);
uint32_t arm64_asm_tst_imm(arm64_reg_t rn, uint64_t imm);

/* Bitfield operations */
uint32_t arm64_asm_sbfm(arm64_reg_t rd, arm64_reg_t rn, uint8_t immr, uint8_t imms);
uint32_t arm64_asm_bfm(arm64_reg_t rd, arm64_reg_t rn, uint8_t immr, uint8_t imms);
uint32_t arm64_asm_ubfm(arm64_reg_t rd, arm64_reg_t rn, uint8_t immr, uint8_t imms);
uint32_t arm64_asm_sxtw(arm64_reg_t rd, arm64_reg_t rn);
uint32_t arm64_asm_ror_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift);

/* Data processing - register */
uint32_t arm64_asm_add_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_sub_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_adds_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_subs_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_cmp_reg(arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_cmn_reg(arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_and_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_orr_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_eor_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_ands_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_tst_reg(arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_mov_reg(arm64_reg_t rd, arm64_reg_t rm);

/* Add/Subtract with carry */
uint32_t arm64_asm_adc(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_sbc(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_adcs(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_sbcs(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_ngc(arm64_reg_t rd, arm64_reg_t rm);

/* Multiply/divide */
uint32_t arm64_asm_mul(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_madd(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_reg_t ra);
uint32_t arm64_asm_msub(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_reg_t ra);
uint32_t arm64_asm_udiv(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_sdiv(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);

/* Shifts */
uint32_t arm64_asm_lsl_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift);
uint32_t arm64_asm_lsr_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift);
uint32_t arm64_asm_asr_imm(arm64_reg_t rd, arm64_reg_t rn, uint8_t shift);
uint32_t arm64_asm_lsl_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_lsr_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_asr_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_ror_reg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm);

/* Load/store */
uint32_t arm64_asm_ldr_imm(arm64_reg_t rt, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_str_imm(arm64_reg_t rt, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_ldr_reg(arm64_reg_t rt, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_str_reg(arm64_reg_t rt, arm64_reg_t rn, arm64_reg_t rm);
uint32_t arm64_asm_ldp(arm64_reg_t rt, arm64_reg_t rt2, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_stp(arm64_reg_t rt, arm64_reg_t rt2, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_ldr_pre(arm64_reg_t rt, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_str_pre(arm64_reg_t rt, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_ldr_post(arm64_reg_t rt, arm64_reg_t rn, int64_t offset);
uint32_t arm64_asm_str_post(arm64_reg_t rt, arm64_reg_t rn, int64_t offset);

/* PC-relative */
uint32_t arm64_asm_adr(arm64_reg_t rd, int64_t offset);
uint32_t arm64_asm_adrp(arm64_reg_t rd, int64_t offset);

/* Conditional select */
uint32_t arm64_asm_csel(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc);
uint32_t arm64_asm_csinc(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc);
uint32_t arm64_asm_csinv(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc);
uint32_t arm64_asm_csneg(arm64_reg_t rd, arm64_reg_t rn, arm64_reg_t rm, arm64_cc_t cc);

/* Atomics */
uint32_t arm64_asm_ldxr(arm64_reg_t rt, arm64_reg_t rn);
uint32_t arm64_asm_stxr(arm64_reg_t rs, arm64_reg_t rt, arm64_reg_t rn);
uint32_t arm64_asm_ldaxr(arm64_reg_t rt, arm64_reg_t rn);
uint32_t arm64_asm_stlxr(arm64_reg_t rs, arm64_reg_t rt, arm64_reg_t rn);
uint32_t arm64_asm_ldar(arm64_reg_t rt, arm64_reg_t rn);
uint32_t arm64_asm_stlr(arm64_reg_t rt, arm64_reg_t rn);

/* Utility functions */
bool arm64_asm_is_x_reg(arm64_reg_t reg);
bool arm64_asm_is_w_reg(arm64_reg_t reg);
uint8_t arm64_asm_reg_num(arm64_reg_t reg);
bool arm64_asm_offset_in_range_b(int64_t offset);
bool arm64_asm_offset_in_range_bcond(int64_t offset);
bool arm64_asm_offset_in_range_tbz(int64_t offset);
bool arm64_asm_offset_in_range_adr(int64_t offset);
bool arm64_asm_offset_in_range_adrp(int64_t offset);

/* Encode logical immediate - reverse of decode_log_imm */
bool arm64_asm_encode_log_imm(uint64_t val, bool is_64, uint8_t *n, uint8_t *imms, uint8_t *immr);

/* System register encoding - reverse of decode_sysreg */
uint32_t arm64_asm_encode_sysreg(arm64_sysreg_t sysreg);

#ifdef __cplusplus
}
#endif

#endif /* ARM64_ASM_H */