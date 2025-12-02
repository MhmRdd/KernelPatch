/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2025 mhmrdd. All Rights Reserved. */

/*
 * Host compatibility layer for ARM64 disassembler.
 * Provides standard library types when building for host tools.
 */

#ifndef ARM64_DISASM_COMPAT_H
#define ARM64_DISASM_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standard type definitions */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

/* Compiler hints */
#ifndef __unused
#define __unused __attribute__((unused))
#endif

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* Array size */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* Min/max (C only - C++ uses std::min/max) */
#ifndef __cplusplus
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#endif

/* Logging - disabled by default for library use */
#ifndef DISASM_NO_LOGGING
#include <stdio.h>
#define pr_info(fmt, ...)  fprintf(stderr, "[INFO] " fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) fprintf(stderr, "[DEBUG] " fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)  fprintf(stderr, "[WARN] " fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)   fprintf(stderr, "[ERROR] " fmt, ##__VA_ARGS__)
#define printk(fmt, ...)   fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define pr_info(fmt, ...)
#define pr_debug(fmt, ...)
#define pr_warn(fmt, ...)
#define pr_err(fmt, ...)
#define printk(fmt, ...)
#endif

/* Format specifiers */
#ifdef _WIN32
#define PRIx64 "llx"
#define PRId64 "lld"
#else
#include <inttypes.h>
#endif

/* Kernel section symbols - not available on host */
#define _text          0
#define _etext         0
#define __start_rodata 0
#define __end_rodata   0

#ifdef __cplusplus
}
#endif

#endif /* ARM64_DISASM_COMPAT_H */