/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_KPMODULE_H_
#define _KP_KPMODULE_H_

#include <stdbool.h>

#define KPM_INFO(name, info, limit)                                 \
    _Static_assert(sizeof(info) <= limit, "Info string too long");  \
    static const char __kpm_info_##name[] __attribute__((__used__)) \
    __attribute__((section(".kpm.info"), unused, aligned(1))) = #name "=" info

#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 32
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define KPM_ARGS_LEN 1024

#define KPM_NAME(x) KPM_INFO(name, x, KPM_NAME_LEN)
#define KPM_VERSION(x) KPM_INFO(version, x, KPM_VERSION_LEN)
#define KPM_LICENSE(x) KPM_INFO(license, x, KPM_LICENSE_LEN)
#define KPM_AUTHOR(x) KPM_INFO(author, x, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(x) KPM_INFO(description, x, KPM_DESCRIPTION_LEN)

typedef long (*mod_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*mod_ctl0call_t)(const char *ctl_args, char *__user out_msg, int outlen);
typedef long (*mod_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*mod_exitcall_t)(void *reserved);

#define KPM_INIT(fn) \
    static mod_initcall_t __kpm_initcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.init"))) = fn

#define KPM_CTL0(fn) \
    static mod_ctl0call_t __kpm_ctlmodule_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.ctl0"))) = fn

#define KPM_CTL1(fn) \
    static mod_ctl1call_t __kpm_ctlmodule_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.ctl1"))) = fn

#define KPM_EXIT(fn) \
    static mod_exitcall_t __kpm_exitcall_##fn __attribute__((__used__)) __attribute__((__section__(".kpm.exit"))) = fn

/*
 * CONFIG_IKCONFIG resolution. kpm_kconfig_get() returns the option value
 * (string options unquoted) or NULL when unset/absent/no-ikconfig. The typed
 * wrappers are KPM-side. The KPM_KCONFIG_* macros take an unquoted option name.
 */
const char *kpm_kconfig_get(const char *key);

enum
{
    KPM_KCONFIG_N = 0,
    KPM_KCONFIG_M = 1,
    KPM_KCONFIG_Y = 2,
};

static inline int kpm_kconfig_tristate(const char *key)
{
    const char *v = kpm_kconfig_get(key);
    if (v && v[0] == 'y' && !v[1]) return KPM_KCONFIG_Y;
    if (v && v[0] == 'm' && !v[1]) return KPM_KCONFIG_M;
    return KPM_KCONFIG_N;
}

static inline bool kpm_kconfig_bool(const char *key)
{
    const char *v = kpm_kconfig_get(key);
    return v && v[0] == 'y' && !v[1];
}

static inline bool kpm_kconfig_int(const char *key, long *out)
{
    const char *v = kpm_kconfig_get(key);
    if (!v || !out) return false;
    bool neg = false;
    long n = 0;
    if (*v == '-') {
        neg = true;
        v++;
    } else if (*v == '+') {
        v++;
    }
    if (!*v) return false;
    for (; *v; v++) {
        if (*v < '0' || *v > '9') return false;
        n = n * 10 + (*v - '0');
    }
    *out = neg ? -n : n;
    return true;
}

static inline bool kpm_kconfig_hex(const char *key, unsigned long *out)
{
    const char *v = kpm_kconfig_get(key);
    if (!v || !out) return false;
    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) v += 2;
    if (!*v) return false;
    unsigned long n = 0;
    for (; *v; v++) {
        unsigned int d;
        if (*v >= '0' && *v <= '9')
            d = *v - '0';
        else if (*v >= 'a' && *v <= 'f')
            d = *v - 'a' + 10;
        else if (*v >= 'A' && *v <= 'F')
            d = *v - 'A' + 10;
        else
            return false;
        n = (n << 4) | d;
    }
    *out = n;
    return true;
}

#define KPM_KCONFIG_GET(key) kpm_kconfig_get(#key)
#define KPM_KCONFIG_BOOL(key) kpm_kconfig_bool(#key)
#define KPM_KCONFIG_TRISTATE(key) kpm_kconfig_tristate(#key)
#define KPM_KCONFIG_INT(key, out) kpm_kconfig_int(#key, out)
#define KPM_KCONFIG_HEX(key, out) kpm_kconfig_hex(#key, out)

#endif
