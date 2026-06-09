/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 *
 * Minimal LZ4 block format (de)compressor, see kplz4.h. Self-contained so it
 * can run from a panic context. Standard LZ4 block layout: a token byte split
 * into a literal-length nibble and a match-length nibble, optional extended
 * lengths as a run of 0xff bytes, the literals, then a 2-byte little-endian
 * back offset for the match.
 */

#include "kplz4.h"

#define KPLZ4_MINMATCH 4
#define KPLZ4_MFLIMIT 12
#define KPLZ4_LASTLITERALS 5
#define KPLZ4_MAXOFF 65535

static unsigned int rd32(const unsigned char *p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned int kplz4_hash(unsigned int v)
{
    return (v * 2654435761u) >> (32 - KPLZ4_HASHLOG);
}

int kp_lz4_compress(const void *src_, int slen, void *dst_, int dcap, void *workspace)
{
    const unsigned char *src = (const unsigned char *)src_;
    unsigned char *dst = (unsigned char *)dst_;
    unsigned int *table = (unsigned int *)workspace;

    const unsigned char *ip = src;
    const unsigned char *anchor = src;
    const unsigned char *const iend = src + slen;
    const unsigned char *const mflimit = iend - KPLZ4_MFLIMIT;
    const unsigned char *const matchlimit = iend - KPLZ4_LASTLITERALS;
    unsigned char *op = dst;
    unsigned char *const oend = dst + dcap;

    if (slen < 0 || dcap < 0) return 0;

    for (int i = 0; i < (1 << KPLZ4_HASHLOG); i++) table[i] = 0;

    if (slen >= KPLZ4_MFLIMIT + 1) {
        while (ip < mflimit) {
            unsigned int seq = rd32(ip);
            unsigned int h = kplz4_hash(seq);
            unsigned int pos = table[h];
            table[h] = (unsigned int)(ip - src) + 1;

            const unsigned char *ref = src + (pos ? pos - 1 : 0);
            if (!pos || (ip - ref) > KPLZ4_MAXOFF || rd32(ref) != seq) {
                ip++;
                continue;
            }

            const unsigned char *m = ip + KPLZ4_MINMATCH;
            const unsigned char *r = ref + KPLZ4_MINMATCH;
            while (m < matchlimit && *m == *r) {
                m++;
                r++;
            }

            int litlen = (int)(ip - anchor);
            int matchlen = (int)(m - ip) - KPLZ4_MINMATCH;
            unsigned int offset = (unsigned int)(ip - ref);

            // token + extended literal length
            unsigned char *token = op;
            if (op >= oend) return 0;
            *op++ = (unsigned char)((litlen >= 15 ? 15 : litlen) << 4);
            if (litlen >= 15) {
                int l = litlen - 15;
                while (l >= 255) {
                    if (op >= oend) return 0;
                    *op++ = 255;
                    l -= 255;
                }
                if (op >= oend) return 0;
                *op++ = (unsigned char)l;
            }
            if (op + litlen > oend) return 0;
            for (int i = 0; i < litlen; i++) op[i] = anchor[i];
            op += litlen;

            // offset (little endian)
            if (op + 2 > oend) return 0;
            *op++ = (unsigned char)(offset & 0xff);
            *op++ = (unsigned char)((offset >> 8) & 0xff);

            // extended match length
            if (matchlen >= 15) {
                *token |= 15;
                int l = matchlen - 15;
                while (l >= 255) {
                    if (op >= oend) return 0;
                    *op++ = 255;
                    l -= 255;
                }
                if (op >= oend) return 0;
                *op++ = (unsigned char)l;
            } else {
                *token |= (unsigned char)matchlen;
            }

            ip = m;
            anchor = m;
        }
    }

    // trailing literals
    {
        int litlen = (int)(iend - anchor);
        if (op >= oend) return 0;
        *op++ = (unsigned char)((litlen >= 15 ? 15 : litlen) << 4);
        if (litlen >= 15) {
            int l = litlen - 15;
            while (l >= 255) {
                if (op >= oend) return 0;
                *op++ = 255;
                l -= 255;
            }
            if (op >= oend) return 0;
            *op++ = (unsigned char)l;
        }
        if (op + litlen > oend) return 0;
        for (int i = 0; i < litlen; i++) op[i] = anchor[i];
        op += litlen;
    }

    return (int)(op - dst);
}

int kp_lz4_decompress(const void *src_, int slen, void *dst_, int dcap)
{
    const unsigned char *src = (const unsigned char *)src_;
    unsigned char *dst = (unsigned char *)dst_;
    const unsigned char *ip = src;
    const unsigned char *const iend = src + slen;
    unsigned char *op = dst;
    unsigned char *const oend = dst + dcap;

    if (slen < 0 || dcap < 0) return -1;

    while (ip < iend) {
        unsigned int token = *ip++;
        int litlen = (int)(token >> 4);
        if (litlen == 15) {
            unsigned int s;
            do {
                if (ip >= iend) return -1;
                s = *ip++;
                litlen += (int)s;
            } while (s == 255);
        }

        if (litlen) {
            if (ip + litlen > iend || op + litlen > oend) return -1;
            for (int i = 0; i < litlen; i++) op[i] = ip[i];
            ip += litlen;
            op += litlen;
        }

        if (ip == iend) break;

        if (ip + 2 > iend) return -1;
        unsigned int offset = (unsigned int)ip[0] | ((unsigned int)ip[1] << 8);
        ip += 2;
        if (offset == 0) return -1;

        int matchlen = (int)(token & 15);
        if (matchlen == 15) {
            unsigned int s;
            do {
                if (ip >= iend) return -1;
                s = *ip++;
                matchlen += (int)s;
            } while (s == 255);
        }
        matchlen += KPLZ4_MINMATCH;

        unsigned char *match = op - offset;
        if (match < dst || op + matchlen > oend) return -1;
        for (int i = 0; i < matchlen; i++) op[i] = match[i];
        op += matchlen;
    }

    return (int)(op - dst);
}

#ifdef KPLZ4_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv)
{
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *in = malloc(n);
    if (fread(in, 1, n, f) != (size_t)n) return 2;
    fclose(f);

    int cap = (int)n + n / 200 + 64;
    unsigned char *comp = malloc(cap);
    unsigned char *out = malloc(n + 16);
    void *ws = malloc(KPLZ4_WORKSPACE_SIZE);

    int clen = kp_lz4_compress(in, (int)n, comp, cap, ws);
    if (clen <= 0) {
        printf("compress failed (clen=%d)\n", clen);
        return 1;
    }
    int dlen = kp_lz4_decompress(comp, clen, out, (int)n + 16);
    if (dlen != (int)n || memcmp(in, out, n) != 0) {
        printf("ROUND-TRIP MISMATCH dlen=%d nlen=%ld\n", dlen, n);
        return 1;
    }
    printf("OK round-trip: in=%ld comp=%d ratio=%.2fx dec=%d (identical)\n", n, clen, (double)n / clen, dlen);
    return 0;
}
#endif
