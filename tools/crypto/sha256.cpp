/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Based on Brad Conte's implementation (public domain)
 */

#include "sha256.hpp"

namespace kp {
namespace crypto {

// SHA256 round constants

static constexpr uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Helper functions

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA256 implementation

void SHA256::reset() {
    datalen_ = 0;
    bitlen_ = 0;
    state_[0] = 0x6a09e667;
    state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f;
    state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab;
    state_[7] = 0x5be0cd19;
}

void SHA256::transform(const uint8_t *data) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;

    // Prepare message schedule
    for (int i = 0; i < 16; ++i) {
        m[i] = (static_cast<uint32_t>(data[i * 4]) << 24) |
               (static_cast<uint32_t>(data[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(data[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(data[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    // Initialize working variables
    a = state_[0];
    b = state_[1];
    c = state_[2];
    d = state_[3];
    e = state_[4];
    f = state_[5];
    g = state_[6];
    h = state_[7];

    // Main loop
    for (int i = 0; i < 64; ++i) {
        t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
        t2 = ep0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update state
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void SHA256::update(const void *data, size_t len) {
    const auto *bytes = static_cast<const uint8_t *>(data);

    for (size_t i = 0; i < len; ++i) {
        data_[datalen_++] = bytes[i];
        if (datalen_ == 64) {
            transform(data_);
            bitlen_ += 512;
            datalen_ = 0;
        }
    }
}

SHA256Digest SHA256::finalize() {
    SHA256Digest hash;
    uint32_t i = datalen_;

    // Pad message
    if (datalen_ < 56) {
        data_[i++] = 0x80;
        while (i < 56) {
            data_[i++] = 0x00;
        }
    } else {
        data_[i++] = 0x80;
        while (i < 64) {
            data_[i++] = 0x00;
        }
        transform(data_);
        std::memset(data_, 0, 56);
    }

    // Append length
    bitlen_ += datalen_ * 8;
    data_[63] = static_cast<uint8_t>(bitlen_);
    data_[62] = static_cast<uint8_t>(bitlen_ >> 8);
    data_[61] = static_cast<uint8_t>(bitlen_ >> 16);
    data_[60] = static_cast<uint8_t>(bitlen_ >> 24);
    data_[59] = static_cast<uint8_t>(bitlen_ >> 32);
    data_[58] = static_cast<uint8_t>(bitlen_ >> 40);
    data_[57] = static_cast<uint8_t>(bitlen_ >> 48);
    data_[56] = static_cast<uint8_t>(bitlen_ >> 56);
    transform(data_);

    // Output big-endian
    for (int j = 0; j < 8; ++j) {
        hash[j * 4] = static_cast<uint8_t>(state_[j] >> 24);
        hash[j * 4 + 1] = static_cast<uint8_t>(state_[j] >> 16);
        hash[j * 4 + 2] = static_cast<uint8_t>(state_[j] >> 8);
        hash[j * 4 + 3] = static_cast<uint8_t>(state_[j]);
    }

    return hash;
}

SHA256Digest SHA256::hash(const void *data, size_t len) {
    SHA256 ctx;
    ctx.update(data, len);
    return ctx.finalize();
}

std::string SHA256::to_hex(const SHA256Digest &digest) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t byte : digest) {
        result += hex[byte >> 4];
        result += hex[byte & 0x0F];
    }
    return result;
}

} // namespace crypto
} // namespace kp