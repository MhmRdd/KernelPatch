/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 */

#ifndef _KP_KPSTORE_H_
#define _KP_KPSTORE_H_

#include <stdarg.h>

struct pt_regs;

void kpstore_init(void);

void kpstore_log(const char *fmt, ...);
void kpstore_vlog(const char *fmt, va_list args);

// copy the ring oldest-to-newest into buf, returns bytes written (NUL terminated)
int kpstore_read(char *buf, int size);

// register the die/panic notifiers, call once after symbol resolution
void kpstore_crash_init(void);

// build a tombstone for reason/regs into the ring and console (regs may be null)
void kpstore_tombstone(const char *reason, struct pt_regs *regs);

// copy the most recent crash tombstone record into buf, returns bytes written
int kpstore_record_read(char *buf, int size);

// expose the crash record buffer + its current length (for the readback supercall)
const char *kpstore_record_data(int *len);

// reserve the persistent (cross-reboot) region, call early at paging_init
void kpstore_persist_reserve(void);

// newest persisted record (level 0), decompressed (null if none)
const char *kpstore_persist_data(int *len);

// k-th newest persisted record (0 = newest), decompressed into a shared buffer
const char *kpstore_persist_read(int level, int *len);

// number of valid persisted records
int kpstore_persist_count(void);

// erase the k-th newest record, or all if level < 0, returns count erased
int kpstore_persist_erase(int level);

#endif
