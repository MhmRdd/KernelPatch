/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Based on Brad Conte's implementation (public domain)
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace kp {
namespace crypto {

// SHA256 hash result size in bytes
inline constexpr size_t SHA256_DIGEST_SIZE = 32;
inline constexpr size_t SHA256_BLOCK_SIZE = 64;

// Type alias for a SHA256 digest
using SHA256Digest = std::array<uint8_t, SHA256_DIGEST_SIZE>;

// SHA256 context class

class SHA256 {
public:
    SHA256() { reset(); }

    // Reset context for new computation
    void reset();

    // Update with data
    void update(const void *data, size_t len);
    void update(std::span<const uint8_t> data) { update(data.data(), data.size()); }
    void update(std::string_view str) { update(str.data(), str.size()); }

    // Finalize and get digest
    SHA256Digest finalize();

    // One-shot hash computation
    static SHA256Digest hash(const void *data, size_t len);
    static SHA256Digest hash(std::span<const uint8_t> data) {
        return hash(data.data(), data.size());
    }
    static SHA256Digest hash(std::string_view str) {
        return hash(str.data(), str.size());
    }

    // Convert digest to hex string
    static std::string to_hex(const SHA256Digest &digest);

private:
    void transform(const uint8_t *data);

    uint8_t data_[SHA256_BLOCK_SIZE];
    uint32_t datalen_;
    uint64_t bitlen_;
    uint32_t state_[8];
};

// Convenience functions

// Hash data and return digest
inline SHA256Digest sha256(const void *data, size_t len) {
    return SHA256::hash(data, len);
}

inline SHA256Digest sha256(std::span<const uint8_t> data) {
    return SHA256::hash(data);
}

inline SHA256Digest sha256(std::string_view str) {
    return SHA256::hash(str);
}

// Hash data and return hex string
inline std::string sha256_hex(const void *data, size_t len) {
    return SHA256::to_hex(SHA256::hash(data, len));
}

inline std::string sha256_hex(std::span<const uint8_t> data) {
    return SHA256::to_hex(SHA256::hash(data));
}

inline std::string sha256_hex(std::string_view str) {
    return SHA256::to_hex(SHA256::hash(str));
}

} // namespace crypto
} // namespace kp