/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 *
 * kpstore: KernelPatch's self-contained diagnostics ring. Always-on capture of
 * KernelPatch/KPM logs and crash records, independent of the platform console
 * and of pstore/ramoops. This is the in-RAM tier.
 */

#include <ktypes.h>
#include <stdarg.h>
#include <linux/spinlock.h>
#include <log.h>

#include "kpstore.h"

extern int (*vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);

#define KPSTORE_RING_SIZE (64 * 1024)
#define KPSTORE_LINE_MAX 512

static char kpstore_ring[KPSTORE_RING_SIZE];
static unsigned int kpstore_pos;
static bool kpstore_wrapped;
static spinlock_t kpstore_lock;

void kpstore_init(void)
{
    spin_lock_init(&kpstore_lock);
    kpstore_pos = 0;
    kpstore_wrapped = false;
}

// caller holds kpstore_lock
static void ring_write(const char *s, int n)
{
    for (int i = 0; i < n; i++) {
        kpstore_ring[kpstore_pos++] = s[i];
        if (kpstore_pos >= KPSTORE_RING_SIZE) {
            kpstore_pos = 0;
            kpstore_wrapped = true;
        }
    }
}

void kpstore_vlog(const char *fmt, va_list args)
{
    char line[KPSTORE_LINE_MAX];
    int n;

    if (!vsnprintf) return;
    n = vsnprintf(line, sizeof(line), fmt, args);
    if (n <= 0) return;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;

    unsigned long flags = spin_lock_irqsave(&kpstore_lock);
    ring_write(line, n);
    spin_unlock_irqrestore(&kpstore_lock, flags);

    if (printk) printk("%s", line);
}

void kpstore_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    kpstore_vlog(fmt, args);
    va_end(args);
}

int kpstore_read(char *buf, int size)
{
    if (size <= 0) return 0;

    unsigned long flags = spin_lock_irqsave(&kpstore_lock);

    int total = kpstore_wrapped ? KPSTORE_RING_SIZE : (int)kpstore_pos;
    int start = kpstore_wrapped ? (int)kpstore_pos : 0;
    int out = 0;
    for (int i = 0; i < total && out < size - 1; i++)
        buf[out++] = kpstore_ring[(start + i) % KPSTORE_RING_SIZE];
    buf[out] = '\0';

    spin_unlock_irqrestore(&kpstore_lock, flags);
    return out;
}
