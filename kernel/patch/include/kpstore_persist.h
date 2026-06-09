/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 *
 * On-DRAM layout of the kpstore persistent crash store. Shared by the engine
 * (writer/reader) and kptools (which sizes and locates the reserved region).
 *
 * Layout in the reserved region:
 *   [region_hdr | pad to KPSTORE_HDR_SIZE] [slot 0] [slot 1] ... [slot N-1]
 * Each slot is a header followed by an LZ4 (or raw) payload. Tombstones are
 * written round-robin; the per-slot sequence is monotonic and lives in the
 * region, so it survives reboots and orders slots newest-first.
 */

#ifndef _KP_KPSTORE_PERSIST_H_
#define _KP_KPSTORE_PERSIST_H_

#include <stdint.h>

#define KPSTORE_PERSIST_VERSION 1

#define KPSTORE_REGION_MAGIC 0x4b505352u // "KPSR"
#define KPSTORE_SLOT_MAGIC 0x4b505353u   // "KPSS"

#define KPSTORE_SLOT_SIZE 0x20000u // 128 KB stored per slot
#define KPSTORE_SLOT_COUNT 8       // levels 0..7, bump for more history
#define KPSTORE_HDR_SIZE 0x1000u // region header area, keeps slots aligned

#define KPSTORE_REGION_SIZE (KPSTORE_HDR_SIZE + KPSTORE_SLOT_COUNT * KPSTORE_SLOT_SIZE)

#define KPSTORE_F_LZ4 0x1u // slot payload is LZ4-compressed

typedef struct
{
    uint32_t magic;
    uint32_t version;
    uint32_t slot_size;
    uint32_t slot_count;
    uint64_t seq; // next sequence number to assign
    uint32_t sum; // checksum over the fields above
    uint32_t resv;
} kpstore_region_hdr_t;

typedef struct
{
    uint32_t magic;
    uint32_t flags;
    uint64_t seq;      // sequence of this slot, 0 if empty
    uint32_t orig_len; // uncompressed length
    uint32_t comp_len; // stored length (compressed or raw)
    uint32_t sum;      // checksum over the stored payload bytes
    uint32_t resv;
} kpstore_slot_hdr_t;

#define KPSTORE_SLOT_PAYLOAD (KPSTORE_SLOT_SIZE - (uint32_t)sizeof(kpstore_slot_hdr_t))

#endif
