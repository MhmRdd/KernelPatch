/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "types.hpp"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <span>
#include <vector>

namespace kp {

class Buffer {
    std::vector<uint8_t> data_;

public:
    Buffer() = default;
    explicit Buffer(size_t size) : data_(size, 0) {}
    Buffer(size_t size, uint8_t fill) : data_(size, fill) {}
    Buffer(const void *data, size_t size) : data_(size) {
        if (data && size > 0) std::memcpy(data_.data(), data, size);
    }
    Buffer(std::span<const uint8_t> span) : data_(span.begin(), span.end()) {}

    // Data access
    uint8_t *data() { return data_.data(); }
    const uint8_t *data() const { return data_.data(); }
    char *char_data() { return reinterpret_cast<char *>(data_.data()); }
    const char *char_data() const { return reinterpret_cast<const char *>(data_.data()); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }

    // Span access
    std::span<uint8_t> span() { return data_; }
    std::span<const uint8_t> span() const { return data_; }
    std::span<uint8_t> span(size_t offset, size_t len) { return {data_.data() + offset, len}; }
    std::span<const uint8_t> span(size_t offset, size_t len) const { return {data_.data() + offset, len}; }

    // Element access
    uint8_t &operator[](size_t index) { return data_[index]; }
    const uint8_t &operator[](size_t index) const { return data_[index]; }

    // Pointer at offset
    template<typename T = void>
    T *ptr_at(size_t offset = 0) { return reinterpret_cast<T *>(data_.data() + offset); }
    template<typename T = void>
    const T *ptr_at(size_t offset = 0) const { return reinterpret_cast<const T *>(data_.data() + offset); }

    // Read/write value at offset
    template<typename T>
    T read_at(size_t offset) const {
        T value;
        std::memcpy(&value, data_.data() + offset, sizeof(T));
        return value;
    }

    template<typename T>
    void write_at(size_t offset, T value) {
        std::memcpy(data_.data() + offset, &value, sizeof(T));
    }

    // Modification
    void resize(size_t new_size) { data_.resize(new_size); }
    void resize(size_t new_size, uint8_t fill) { data_.resize(new_size, fill); }
    void reserve(size_t capacity) { data_.reserve(capacity); }
    void clear() { data_.clear(); }
    void fill(uint8_t value) { std::fill(data_.begin(), data_.end(), value); }

    // Append
    void append(const void *src, size_t len) {
        size_t old_size = data_.size();
        data_.resize(old_size + len);
        std::memcpy(data_.data() + old_size, src, len);
    }
    void append(const Buffer &other) { append(other.data(), other.size()); }

    // Pad to alignment
    void pad_to_alignment(size_t alignment, uint8_t fill = 0) {
        size_t aligned = align_up(data_.size(), alignment);
        if (aligned > data_.size()) data_.resize(aligned, fill);
    }

    // Copy from source
    void copy_from(size_t dst_offset, const void *src, size_t len) {
        if (dst_offset + len > data_.size()) data_.resize(dst_offset + len);
        std::memcpy(data_.data() + dst_offset, src, len);
    }

    // Search
    std::optional<size_t> find(const void *pattern, size_t pattern_len, size_t start = 0) const {
        if (pattern_len == 0 || start + pattern_len > data_.size()) return std::nullopt;
        auto it = std::search(data_.begin() + start, data_.end(),
                              static_cast<const uint8_t *>(pattern),
                              static_cast<const uint8_t *>(pattern) + pattern_len);
        if (it == data_.end()) return std::nullopt;
        return std::distance(data_.begin(), it);
    }

    std::optional<size_t> find(std::string_view str, size_t start = 0) const {
        return find(str.data(), str.size(), start);
    }

    // String at offset
    std::string_view string_view_at(size_t offset) const {
        const char *start = char_data() + offset;
        return {start, std::strlen(start)};
    }

    // Sub-buffer
    Buffer sub(size_t offset, size_t len) const { return {data_.data() + offset, len}; }

    // Iterators
    auto begin() { return data_.begin(); }
    auto end() { return data_.end(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }

    // File I/O
    static Result<Buffer> from_file(const std::filesystem::path &path, size_t alignment = 1);
    Result<void> to_file(const std::filesystem::path &path) const;
};

} // namespace kp