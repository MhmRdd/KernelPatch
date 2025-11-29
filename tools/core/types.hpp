/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>

namespace kp {

// Result<T, E> - Error handling without exceptions
struct OkTag {};
struct ErrTag {};

template<typename T, typename E = std::string>
class Result {
    union Storage {
        T ok_val;
        E err_val;
        Storage() {}
        ~Storage() {}
    } storage_;
    bool is_ok_;

    Result(OkTag, T val) : is_ok_(true) { new (&storage_.ok_val) T(std::move(val)); }
    Result(ErrTag, E err) : is_ok_(false) { new (&storage_.err_val) E(std::move(err)); }

public:
    ~Result() {
        if (is_ok_) storage_.ok_val.~T();
        else storage_.err_val.~E();
    }

    Result(const Result &other) : is_ok_(other.is_ok_) {
        if (is_ok_) new (&storage_.ok_val) T(other.storage_.ok_val);
        else new (&storage_.err_val) E(other.storage_.err_val);
    }

    Result(Result &&other) noexcept : is_ok_(other.is_ok_) {
        if (is_ok_) new (&storage_.ok_val) T(std::move(other.storage_.ok_val));
        else new (&storage_.err_val) E(std::move(other.storage_.err_val));
    }

    Result &operator=(const Result &other) {
        if (this != &other) { this->~Result(); new (this) Result(other); }
        return *this;
    }

    Result &operator=(Result &&other) noexcept {
        if (this != &other) { this->~Result(); new (this) Result(std::move(other)); }
        return *this;
    }

    static Result Ok(T val) { return Result(OkTag{}, std::move(val)); }
    static Result Err(E err) { return Result(ErrTag{}, std::move(err)); }

    bool ok() const { return is_ok_; }
    explicit operator bool() const { return is_ok_; }

    T &unwrap() & { return storage_.ok_val; }
    const T &unwrap() const & { return storage_.ok_val; }
    T &&unwrap() && { return std::move(storage_.ok_val); }
    T unwrap_or(T default_val) const { return is_ok_ ? storage_.ok_val : default_val; }

    const E &error() const & { return storage_.err_val; }
    E &&error() && { return std::move(storage_.err_val); }
};

template<typename E>
class Result<void, E> {
    std::optional<E> error_;

public:
    Result() : error_(std::nullopt) {}
    Result(E err, bool) : error_(std::move(err)) {}

    static Result Ok() { return Result(); }
    static Result Err(E err) { return Result(std::move(err), false); }

    bool ok() const { return !error_.has_value(); }
    explicit operator bool() const { return !error_.has_value(); }

    const E &error() const & { return *error_; }
    E &&error() && { return std::move(*error_); }
};

// Endianness utilities
namespace endian {

constexpr bool is_little() noexcept { return std::endian::native == std::endian::little; }
constexpr bool is_big() noexcept { return std::endian::native == std::endian::big; }

template<typename T>
constexpr T swap(T value) noexcept {
    static_assert(std::is_integral_v<T>, "swap requires integral type");
    if constexpr (sizeof(T) == 1) return value;
    else if constexpr (sizeof(T) == 2) {
        auto v = static_cast<uint16_t>(value);
        return static_cast<T>((v << 8) | (v >> 8));
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(__builtin_bswap32(static_cast<uint32_t>(value)));
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(__builtin_bswap64(static_cast<uint64_t>(value)));
    }
}

template<typename T> constexpr T to_le(T value) noexcept { return is_little() ? value : swap(value); }
template<typename T> constexpr T to_be(T value) noexcept { return is_big() ? value : swap(value); }
template<typename T> constexpr T from_le(T value) noexcept { return to_le(value); }
template<typename T> constexpr T from_be(T value) noexcept { return to_be(value); }

template<typename T>
T read_le(const void *ptr) noexcept {
    T value;
    std::memcpy(&value, ptr, sizeof(T));
    return from_le(value);
}

template<typename T>
T read_be(const void *ptr) noexcept {
    T value;
    std::memcpy(&value, ptr, sizeof(T));
    return from_be(value);
}

} // namespace endian

// Alignment utilities
template<typename T> constexpr T align_down(T value, T alignment) noexcept { return value & ~(alignment - 1); }
template<typename T> constexpr T align_up(T value, T alignment) noexcept { return (value + alignment - 1) & ~(alignment - 1); }
template<typename T> constexpr bool is_aligned(T value, T alignment) noexcept { return (value & (alignment - 1)) == 0; }

// Bit manipulation
namespace bits {

template<typename T> constexpr int popcount(T value) noexcept { return std::popcount(static_cast<std::make_unsigned_t<T>>(value)); }
template<typename T> constexpr int countr_zero(T value) noexcept { return std::countr_zero(static_cast<std::make_unsigned_t<T>>(value)); }
template<typename T> constexpr int countl_zero(T value) noexcept { return std::countl_zero(static_cast<std::make_unsigned_t<T>>(value)); }

template<typename T> constexpr int ffs(T value) noexcept { return value == 0 ? 0 : countr_zero(value) + 1; }
template<typename T> constexpr int fls(T value) noexcept { return value == 0 ? 0 : sizeof(T) * 8 - countl_zero(value); }

template<typename T>
constexpr T extract(T value, int lo, int hi) noexcept {
    int width = hi - lo + 1;
    T mask = (static_cast<T>(1) << width) - 1;
    return (value >> lo) & mask;
}

template<typename T>
constexpr T sign_extend(T value, int sign_bit) noexcept {
    T sign_mask = static_cast<T>(1) << sign_bit;
    if (value & sign_mask) {
        return value | ~((static_cast<T>(1) << (sign_bit + 1)) - 1);
    }
    return value;
}

} // namespace bits

// Common constants
inline constexpr size_t PAGE_SIZE_4K = 4096;
inline constexpr const char *KP_MAGIC = "KP1158";
inline constexpr const char *KERNEL_MAGIC = "ARM\x64";
inline constexpr size_t SUPERKEY_LEN = 64;
inline constexpr size_t ROOT_SUPERKEY_HASH_LEN = 32;
inline constexpr size_t EXTRA_NAME_LEN = 32;
inline constexpr size_t EXTRA_EVENT_LEN = 32;
inline constexpr size_t EXTRA_ARGS_LEN = 512;
inline constexpr int EXTRA_ITEM_MAX_NUM = 32;

} // namespace kp