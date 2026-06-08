/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 */

#ifndef _KP_SETJMP_H_
#define _KP_SETJMP_H_

#include <stdint.h>

// AArch64 callee-saved registers x19-x28, x29 (fp), x30 (lr) and sp give 13
// slots, padded to 16 for alignment.
typedef uint64_t jmp_buf[16];

int setjmp(jmp_buf env) __attribute__((returns_twice));
void longjmp(jmp_buf env, int val) __attribute__((noreturn));

#endif
