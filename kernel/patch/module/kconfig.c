/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 */

#include <compiler.h>
#include <log.h>
#include <baselib.h>
#include <kpmalloc.h>
#include <kpmodule.h>
#include <puff.h>
#include <symbol.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "kconfig.h"

const void *kp_kconfig_data = 0;
unsigned long kp_kconfig_data_size = 0;

#define KCONFIG_MAX_SIZE (8u << 20)

struct kconfig_entry
{
    struct list_head list;
    char *value; // NULL if absent
    char key[];
};

static struct list_head kconfig_cache;
static spinlock_t kconfig_lock;

void kpm_kconfig_init(void)
{
    INIT_LIST_HEAD(&kconfig_cache);
    spin_lock_init(&kconfig_lock);
}

static const unsigned char *gz_deflate_start(const unsigned char *gz, unsigned long gz_len, unsigned long *deflate_len,
                                             unsigned long *isize)
{
    if (gz_len < 18) return 0;
    if (gz[0] != 0x1f || gz[1] != 0x8b || gz[2] != 8) return 0;

    unsigned int flg = gz[3];
    unsigned long pos = 10;

    if (flg & 0x04) { // FEXTRA
        if (pos + 2 > gz_len) return 0;
        unsigned int xlen = gz[pos] | (gz[pos + 1] << 8);
        pos += 2 + xlen;
    }
    if (flg & 0x08) { // FNAME
        while (pos < gz_len && gz[pos]) pos++;
        pos++;
    }
    if (flg & 0x10) { // FCOMMENT
        while (pos < gz_len && gz[pos]) pos++;
        pos++;
    }
    if (flg & 0x02) pos += 2; // FHCRC

    if (pos + 8 > gz_len) return 0;

    *isize = (unsigned long)gz[gz_len - 4] | ((unsigned long)gz[gz_len - 3] << 8) |
             ((unsigned long)gz[gz_len - 2] << 16) | ((unsigned long)gz[gz_len - 1] << 24);
    *deflate_len = gz_len - 8 - pos;
    return gz + pos;
}

static char *kconfig_decompress(unsigned long *out_len)
{
    if (!kp_kconfig_data || !kp_kconfig_data_size) return 0;

    unsigned long deflate_len = 0, isize = 0;
    const unsigned char *src =
        gz_deflate_start((const unsigned char *)kp_kconfig_data, kp_kconfig_data_size, &deflate_len, &isize);
    if (!src) {
        logkfe("ikconfig: malformed gzip header\n");
        return 0;
    }
    if (!isize || isize > KCONFIG_MAX_SIZE) {
        logkfe("ikconfig: bad uncompressed size %lx\n", isize);
        return 0;
    }

    char *out = (char *)vmalloc(isize + 1);
    if (!out) return 0;

    unsigned long dlen = isize, slen = deflate_len;
    int rc = puff((unsigned char *)out, &dlen, src, &slen);
    if (rc) {
        logkfe("ikconfig: inflate failed %d\n", rc);
        vfree(out);
        return 0;
    }

    out[dlen] = '\0';
    *out_len = dlen;
    return out;
}

static int kconfig_find(const char *text, unsigned long text_len, const char *key, unsigned long klen, const char **val,
                        unsigned long *val_len)
{
    const char *p = text;
    const char *end = text + text_len;

    while (p < end) {
        const char *nl = (const char *)lib_memchr(p, '\n', end - p);
        const char *line_end = nl ? nl : end;

        if ((unsigned long)(line_end - p) > klen && !lib_strncmp(p, key, klen) && p[klen] == '=') {
            *val = p + klen + 1;
            *val_len = line_end - (p + klen + 1);
            return 1;
        }
        p = nl ? nl + 1 : end;
    }
    return 0;
}

// both cache helpers run under kconfig_lock
static struct kconfig_entry *cache_find(const char *key)
{
    struct kconfig_entry *e;
    list_for_each_entry(e, &kconfig_cache, list)
    {
        if (!lib_strcmp(e->key, key)) return e;
    }
    return 0;
}

static struct kconfig_entry *cache_add(const char *key, unsigned long klen, const char *val, unsigned long vlen)
{
    unsigned long need = sizeof(struct kconfig_entry) + klen + 1 + (val ? vlen + 1 : 0);
    struct kconfig_entry *e = (struct kconfig_entry *)kp_malloc(need);
    if (!e) return 0;

    lib_memcpy(e->key, key, klen);
    e->key[klen] = '\0';
    if (val) {
        e->value = e->key + klen + 1;
        if (vlen) lib_memcpy(e->value, val, vlen);
        e->value[vlen] = '\0';
    } else {
        e->value = 0;
    }
    list_add_tail(&e->list, &kconfig_cache);
    return e;
}

const char *kpm_kconfig_get(const char *key)
{
    if (!key || !key[0]) return 0;
    if (!kp_kconfig_data || !kp_kconfig_data_size) return 0;

    struct kconfig_entry *e;

    spin_lock(&kconfig_lock);
    e = cache_find(key);
    spin_unlock(&kconfig_lock);
    if (e) return e->value;

    unsigned long tlen = 0;
    char *text = kconfig_decompress(&tlen);
    if (!text) return 0; // do not cache, allow a later retry

    const char *val = 0;
    unsigned long vlen = 0;
    int found = kconfig_find(text, tlen, key, lib_strlen(key), &val, &vlen);
    if (found && vlen >= 2 && val[0] == '"' && val[vlen - 1] == '"') { // unquote string values
        val++;
        vlen -= 2;
    }

    unsigned long klen = lib_strlen(key);
    spin_lock(&kconfig_lock);
    e = cache_find(key);
    if (!e) e = cache_add(key, klen, found ? val : 0, found ? vlen : 0);
    spin_unlock(&kconfig_lock);

    vfree(text);
    return e ? e->value : 0;
}
KP_EXPORT_SYMBOL(kpm_kconfig_get);
