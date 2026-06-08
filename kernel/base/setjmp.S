/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 *
 * Minimal freestanding setjmp/longjmp for AArch64, used by the vendored puff.c
 * inflate. Only the callee-saved general registers, frame pointer, link
 * register and stack pointer are preserved. The engine is built with
 * -mgeneral-regs-only, so there are no callee-saved SIMD/FP registers.
 *
 * jmp_buf layout (uint64_t[16]):
 *   [0..1] x19 x20  [2..3] x21 x22  [4..5] x23 x24
 *   [6..7] x25 x26  [8..9] x27 x28  [10] x29  [11] x30  [12] sp
 */

.text

.align 2
.global setjmp
.type setjmp, %function
setjmp:
    stp x19, x20, [x0, #0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x1, sp
    str x1, [x0, #96]
    mov x0, #0
    ret

.align 2
.global longjmp
.type longjmp, %function
longjmp:
    ldp x19, x20, [x0, #0]
    ldp x21, x22, [x0, #16]
    ldp x23, x24, [x0, #32]
    ldp x25, x26, [x0, #48]
    ldp x27, x28, [x0, #64]
    ldp x29, x30, [x0, #80]
    ldr x2, [x0, #96]
    mov sp, x2
    // setjmp() must observe a non-zero result when resumed via longjmp(),
    // so a val of 0 is promoted to 1
    cmp w1, #0
    csinc w0, w1, wzr, ne
    ret
