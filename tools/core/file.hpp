/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include "buffer.hpp"
#include "types.hpp"
#include <filesystem>
#include <fstream>

namespace kp {
namespace file {

inline Result<Buffer> read(const std::filesystem::path &path, size_t alignment = 1) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec))
        return Result<Buffer>::Err("File not found: " + path.string());

    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) return Result<Buffer>::Err("Failed to get file size: " + path.string());

    std::ifstream file(path, std::ios::binary);
    if (!file) return Result<Buffer>::Err("Failed to open file: " + path.string());

    size_t aligned_size = align_up(static_cast<size_t>(file_size), alignment);
    Buffer buf(aligned_size, 0);

    file.read(buf.char_data(), file_size);
    if (file.gcount() != static_cast<std::streamsize>(file_size))
        return Result<Buffer>::Err("Failed to read file: " + path.string());

    return Result<Buffer>::Ok(std::move(buf));
}

inline Result<void> write(const std::filesystem::path &path, const Buffer &buf) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) return Result<void>::Err("Failed to create file: " + path.string());
    file.write(buf.char_data(), buf.size());
    if (!file) return Result<void>::Err("Failed to write file: " + path.string());
    return Result<void>::Ok();
}

inline Result<void> write(const std::filesystem::path &path, const void *data, size_t len) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) return Result<void>::Err("Failed to create file: " + path.string());
    file.write(static_cast<const char *>(data), len);
    if (!file) return Result<void>::Err("Failed to write file: " + path.string());
    return Result<void>::Ok();
}

inline bool exists(const std::filesystem::path &path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

inline std::string basename(const std::filesystem::path &path) { return path.filename().string(); }
inline std::string stem(const std::filesystem::path &path) { return path.stem().string(); }

} // namespace file

// Buffer file I/O implementation
inline Result<Buffer> Buffer::from_file(const std::filesystem::path &path, size_t alignment) {
    return file::read(path, alignment);
}

inline Result<void> Buffer::to_file(const std::filesystem::path &path) const {
    return file::write(path, *this);
}

} // namespace kp