/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 *
 * Minimal self-contained LZ4 block (de)compressor for the kpstore crash path.
 * No allocation, no locks, no kernel symbols, so it is safe to run from a
 * panic context and works identically across every supported kernel.
 */

#ifndef _KP_KPLZ4_H_
#define _KP_KPLZ4_H_

#define KPLZ4_HASHLOG 14
#define KPLZ4_WORKSPACE_SIZE ((1 << KPLZ4_HASHLOG) * (int)sizeof(unsigned int))

// compress slen bytes of src into dst (capacity dcap), returns compressed
// length or 0 if it did not fit. workspace must be >= KPLZ4_WORKSPACE_SIZE
int kp_lz4_compress(const void *src, int slen, void *dst, int dcap, void *workspace);

// decompress into dst (capacity dcap), returns decompressed length or -1
int kp_lz4_decompress(const void *src, int slen, void *dst, int dcap);

#endif
