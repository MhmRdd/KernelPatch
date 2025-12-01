/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */
/* Copyright (C) 2024 Yervant7. All Rights Reserved. */

#include "kallsyms.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cctype>

namespace ktool {

namespace {

constexpr size_t kNpos = static_cast<size_t>(-1);
constexpr uint64_t kR_AARCH64_RELATIVE = 0x403;
constexpr size_t kMinRelaCount = 1000;
// ARM64 kernel base can be 0xffff000000000000 (48-bit VA) or higher
constexpr uint64_t kMinKernelVA = 0xFFFF000000000000ULL;
constexpr uint64_t kMaxKernelVA = 0xFFFFFFFFFFFFFFFFULL;

} // namespace

uint64_t KallsymsFinder::read_int(size_t offset, int size) const {
    if (offset + size > size_) return 0;

    uint64_t value = 0;
    if (is_big_endian_) {
        for (int i = 0; i < size; ++i) {
            value = (value << 8) | data_[offset + i];
        }
    } else {
        for (int i = size - 1; i >= 0; --i) {
            value = (value << 8) | data_[offset + i];
        }
    }
    return value;
}

int64_t KallsymsFinder::read_signed_int(size_t offset, int size) const {
    uint64_t val = read_int(offset, size);
    if (size == 4 && (val & 0x80000000)) {
        return static_cast<int64_t>(val | 0xFFFFFFFF00000000ULL);
    }
    if (size == 2 && (val & 0x8000)) {
        return static_cast<int64_t>(val | 0xFFFFFFFFFFFF0000ULL);
    }
    return static_cast<int64_t>(val);
}

size_t KallsymsFinder::mem_find(const uint8_t* needle, size_t needle_len,
                                 size_t start, size_t end) const {
    if (end == 0) end = size_;
    if (start >= end || needle_len == 0 || end - start < needle_len) {
        return kNpos;
    }

    const uint8_t* pos = std::search(data_ + start, data_ + end, needle, needle + needle_len);
    if (pos == data_ + end) return kNpos;
    return pos - data_;
}

size_t KallsymsFinder::mem_rfind(const uint8_t* needle, size_t needle_len,
                                  size_t start, size_t end) const {
    if (end == 0) end = size_;
    if (start >= end || needle_len == 0 || end - start < needle_len) {
        return kNpos;
    }

    for (size_t i = end - needle_len; i >= start && i < end; --i) {
        if (std::memcmp(data_ + i, needle, needle_len) == 0) {
            return i;
        }
        if (i == 0) break;
    }
    return kNpos;
}

void KallsymsFinder::parse(const uint8_t* data, size_t size, int bit_size,
                            bool use_absolute, uint64_t base_address) {
    data_ = data;
    size_ = size;
    use_absolute_ = use_absolute;
    forced_base_address_ = base_address;

    if (bit_size == 32) {
        is_64_bits_ = false;
    } else if (bit_size == 64) {
        is_64_bits_ = true;
    }

    find_linux_banner();
    guess_architecture();

    if (is_64_bits_) {
        find_elf_relocations();
        apply_relocations();
    }

    find_token_table();
    find_token_index();
    find_markers();
    find_names();
    find_num_syms();
    find_addresses_or_offsets();
    parse_symbol_table();
}

void KallsymsFinder::find_linux_banner() {
    const uint8_t pattern[] = "Linux version ";
    constexpr size_t pattern_len = sizeof(pattern) - 1;

    size_t search_start = 0;

    while (search_start < size_) {
        size_t pos = mem_find(pattern, pattern_len, search_start);
        if (pos == kNpos) {
            break;
        }

        size_t ver_start = pos + pattern_len;
        if (ver_start >= size_ || data_[ver_start] == '%' || !std::isdigit(data_[ver_start])) {
            search_start = pos + 1;
            continue;
        }

        size_t ver_end = ver_start;
        while (ver_end < size_ && ver_end < ver_start + 100) {
            char c = static_cast<char>(data_[ver_end]);
            if (c == ' ' || c == '-' || c == '\n' || c == '\0' || c < 0x20) {
                break;
            }
            ++ver_end;
        }

        std::string version_str(reinterpret_cast<const char*>(data_ + ver_start), ver_end - ver_start);

        int major = 0, minor = 0, patch = 0;
        size_t idx = 0;

        while (idx < version_str.size() && std::isdigit(version_str[idx])) {
            major = major * 10 + (version_str[idx] - '0');
            ++idx;
        }

        if (idx < version_str.size() && version_str[idx] == '.') {
            ++idx;
        }

        while (idx < version_str.size() && std::isdigit(version_str[idx])) {
            minor = minor * 10 + (version_str[idx] - '0');
            ++idx;
        }

        if (idx < version_str.size() && version_str[idx] == '.') {
            ++idx;
        }

        while (idx < version_str.size() && std::isdigit(version_str[idx])) {
            patch = patch * 10 + (version_str[idx] - '0');
            ++idx;
        }

        if (major == 0 && minor == 0) {
            search_start = pos + 1;
            continue;
        }

        version_.major = major;
        version_.minor = minor;
        version_.patch = patch;

        size_t str_end = pos;
        while (str_end < size_ && str_end < pos + 300) {
            char c = static_cast<char>(data_[str_end]);
            if (c == '\n' || c == '\0' || c < 0x20) {
                break;
            }
            ++str_end;
        }
        version_string_ = std::string(reinterpret_cast<const char*>(data_ + pos), str_end - pos);

        std::fprintf(stderr, "[+] Version: %s\n", version_string_.c_str());
        return;
    }

    throw KallsymsNotFound("No Linux version string found in kernel image");
}

void KallsymsFinder::guess_architecture() {
    is_big_endian_ = false;

    if (version_string_.find("aarch64") != std::string::npos ||
        version_string_.find("arm64") != std::string::npos ||
        version_string_.find("x86_64") != std::string::npos) {
        is_64_bits_ = true;
    }
}

void KallsymsFinder::find_elf_relocations() {
    constexpr size_t kRelaSize = 24;

    relocations_.clear();

    // Search FORWARD from start of file (like old kptools)
    // Look for the first valid R_AARCH64_RELATIVE relocation
    size_t pos = 0;
    uint64_t kernel_base_candidate = kMaxKernelVA;

    // Find the start of relocation table by searching for valid relocation entries
    while (pos + kRelaSize <= size_) {
        uint64_t r_offset = read_int(pos, 8);
        uint64_t r_info = read_int(pos + 8, 8);

        // Check if this looks like a valid R_AARCH64_RELATIVE relocation:
        // - r_info must be 0x403
        // - r_offset must be a kernel virtual address (top 16 bits = 0xffff)
        bool is_kernel_addr = (r_offset & 0xffff000000000000ULL) == 0xffff000000000000ULL;

        if (r_info == kR_AARCH64_RELATIVE && is_kernel_addr) {
            // Found start of relocation table
            break;
        }
        pos += 8; // Search in 8-byte increments for alignment
    }

    if (pos + kRelaSize > size_) {
        return; // No relocations found
    }

    rela_start_ = pos;

    // Now collect all consecutive relocations
    while (pos + kRelaSize <= size_) {
        uint64_t r_offset = read_int(pos, 8);
        uint64_t r_info = read_int(pos + 8, 8);
        uint64_t r_addend = read_int(pos + 16, 8);

        // Allow zero entries (padding)
        if (r_offset == 0 && r_info == 0 && r_addend == 0) {
            pos += kRelaSize;
            continue;
        }

        // Validate: r_info must be R_AARCH64_RELATIVE and r_offset must be kernel address
        bool is_kernel_addr = (r_offset & 0xffff000000000000ULL) == 0xffff000000000000ULL;
        if (r_info != kR_AARCH64_RELATIVE || !is_kernel_addr) {
            break; // End of relocation table
        }

        relocations_.push_back({r_offset, r_info, r_addend});

        // Track kernel base from r_offset (the lowest page-aligned kernel address)
        if ((r_offset & 0xFFF) == 0 && r_offset < kernel_base_candidate) {
            kernel_base_candidate = r_offset;
        }

        pos += kRelaSize;
    }

    rela_end_ = pos;

    if (relocations_.size() < kMinRelaCount) {
        relocations_.clear();
        rela_start_ = 0;
        rela_end_ = 0;
        return;
    }

    // If we couldn't find a page-aligned base from r_offset, try from the lowest r_offset
    if (kernel_base_candidate == kMaxKernelVA && !relocations_.empty()) {
        // Find lowest r_offset and align it down to page boundary
        uint64_t min_offset = kMaxKernelVA;
        for (const auto& rela : relocations_) {
            if (rela.offset < min_offset) {
                min_offset = rela.offset;
            }
        }
        kernel_base_candidate = min_offset & ~0xFFFULL; // Page-align down
    }

    kernel_base_ = (forced_base_address_ != 0) ? forced_base_address_ : kernel_base_candidate;

    std::fprintf(stderr, "[+] Found relocation table at 0x%zx-0x%zx (count=%zu)\n",
                 rela_start_, rela_end_, relocations_.size());
    std::fprintf(stderr, "[+] Kernel base from relocations: 0x%llx\n",
                 static_cast<unsigned long long>(kernel_base_));
}

void KallsymsFinder::apply_relocations() {
    if (relocations_.empty() || kernel_base_ == 0 || kernel_base_ == kMaxKernelVA) {
        return;
    }

    data_copy_.assign(data_, data_ + size_);
    size_t max_offset = size_ - 8;
    int count = 0;

    for (const auto& rela : relocations_) {
        // r_offset should be >= kernel_base (it's a kernel virtual address)
        if (rela.offset < kernel_base_) {
            continue;
        }

        size_t offset = static_cast<size_t>(rela.offset - kernel_base_);
        if (offset >= max_offset) {
            continue;
        }

        uint64_t value;
        std::memcpy(&value, data_copy_.data() + offset, 8);

        // For R_AARCH64_RELATIVE: the final value should be r_addend
        // Skip if already relocated (value equals addend)
        if (value == rela.addend) {
            continue;
        }

        // Apply relocation: write r_addend to the location
        std::memcpy(data_copy_.data() + offset, &rela.addend, 8);
        ++count;
    }

    if (count > 0) {
        data_ = data_copy_.data();
        std::fprintf(stderr, "[+] Applied %d relocations\n", count);
    }
}

void KallsymsFinder::find_token_table() {
    uint8_t pattern[20] = {0};
    for (int i = 0; i < 10; ++i) {
        pattern[i * 2] = '0' + i;
        pattern[i * 2 + 1] = '\0';
    }

    std::vector<size_t> candidates;
    size_t pos = 0;

    while (pos < size_) {
        pos = mem_find(pattern, sizeof(pattern), pos + 1);
        if (pos == kNpos) break;

        size_t next = pos + sizeof(pattern);
        if (next < size_ && data_[next] == ':') {
            continue;
        }

        const uint8_t* p = data_ + next;
        const uint8_t* end = data_ + std::min(next + 200, size_);
        int zero_count = 0;

        while (p < end && zero_count < ('a' - '9' - 1)) {
            if (*p == 0) ++zero_count;
            ++p;
        }

        if (p < end && *p == 'a') {
            candidates.push_back(pos);
        }
    }

    if (candidates.empty()) {
        throw KallsymsNotFound("Could not find kallsyms_token_table");
    }

    pos = candidates[0];
    int index = '0';

    --pos;
    if (pos >= size_ || data_[pos] != 0) {
        throw KallsymsNotFound("Invalid token table structure");
    }

    for (int i = 0; i < index; ++i) {
        for (int j = 0; j < 50; ++j) {
            --pos;
            if (pos == 0) break;
            if (data_[pos] == 0 || data_[pos] > 'z') {
                break;
            }
        }
    }

    ++pos;
    if (pos % 4 != 0) {
        pos += 4 - (pos % 4);
    }

    token_table_offset_ = pos;
    std::fprintf(stderr, "[+] Found kallsyms_token_table at 0x%zx\n", pos);

    token_table_.clear();
    token_table_.reserve(256);

    const char* p = reinterpret_cast<const char*>(data_ + pos);
    for (int i = 0; i < 256; ++i) {
        token_table_.emplace_back(p);
        p += std::strlen(p) + 1;
    }
}

void KallsymsFinder::find_token_index() {
    std::vector<uint16_t> offsets;
    offsets.reserve(256);

    size_t pos = token_table_offset_;
    for (int i = 0; i < 256; ++i) {
        offsets.push_back(static_cast<uint16_t>(pos - token_table_offset_));
        while (pos < size_ && data_[pos] != 0) {
            ++pos;
        }
        ++pos;
    }

    size_t token_table_end = pos;

    constexpr size_t kIndexSize = 256 * 2;
    constexpr size_t kMaxAlignment = 256;

    std::vector<uint8_t> le_pattern(kIndexSize);
    std::vector<uint8_t> be_pattern(kIndexSize);

    for (int i = 0; i < 256; ++i) {
        le_pattern[i * 2] = offsets[i] & 0xFF;
        le_pattern[i * 2 + 1] = (offsets[i] >> 8) & 0xFF;
        be_pattern[i * 2] = (offsets[i] >> 8) & 0xFF;
        be_pattern[i * 2 + 1] = offsets[i] & 0xFF;
    }

    size_t search_end = std::min(token_table_end + kIndexSize + kMaxAlignment, size_);

    size_t le_pos = mem_find(le_pattern.data(), kIndexSize, token_table_end, search_end);
    size_t be_pos = mem_find(be_pattern.data(), kIndexSize, token_table_end, search_end);

    if (le_pos == kNpos && be_pos == kNpos) {
        throw KallsymsNotFound("Could not find kallsyms_token_index");
    }

    if (le_pos != kNpos && (be_pos == kNpos || le_pos <= be_pos)) {
        is_big_endian_ = false;
        token_index_offset_ = le_pos;
    } else {
        is_big_endian_ = true;
        token_index_offset_ = be_pos;
    }

    token_index_end_offset_ = token_index_offset_ + kIndexSize;

    std::fprintf(stderr, "[+] Found kallsyms_token_index at 0x%zx\n", token_index_offset_);
    std::fprintf(stderr, "[+] Endianness: %s\n", is_big_endian_ ? "big" : "little");
}

void KallsymsFinder::find_markers() {
    for (int elem_size : {8, 4, 2}) {
        size_t pos = token_table_offset_;

        for (int attempt = 0; attempt < 64; ++attempt) {
            uint8_t zeros[8] = {0};
            pos = mem_rfind(zeros, elem_size, 0, pos);
            if (pos == kNpos) break;

            pos -= pos % elem_size;

            uint64_t v0 = read_int(pos, elem_size);
            if (v0 != 0) continue;

            bool valid = true;
            for (int i = 1; i < 4 && valid; ++i) {
                uint64_t prev = read_int(pos + elem_size * (i - 1), elem_size);
                uint64_t curr = read_int(pos + elem_size * i, elem_size);
                if (curr <= prev + 0x200 || curr > prev + 0x40000) {
                    valid = false;
                }
            }

            if (valid) {
                markers_offset_ = pos;
                offset_table_element_size_ = elem_size;
                std::fprintf(stderr, "[+] Found kallsyms_markers at 0x%zx (elem_size=%d)\n",
                             pos, elem_size);
                return;
            }
        }
    }

    throw KallsymsNotFound("Could not find kallsyms_markers");
}

void KallsymsFinder::find_names() {
    size_t num_markers = (token_table_offset_ - markers_offset_) / offset_table_element_size_;
    num_markers = std::min(num_markers, size_t(3000));

    uint64_t last_marker = 0;
    for (size_t i = 1; i < num_markers; ++i) {
        uint64_t curr = read_int(markers_offset_ + i * offset_table_element_size_,
                                  offset_table_element_size_);
        uint64_t prev = read_int(markers_offset_ + (i - 1) * offset_table_element_size_,
                                  offset_table_element_size_);
        if (curr <= prev + 0x200 || curr > prev + 0x40000) {
            break;
        }
        last_marker = curr;
    }

    size_t pos = markers_offset_ - last_marker;
    pos += -pos % offset_table_element_size_;

    names_offset_ = pos;
}

void KallsymsFinder::find_num_syms() {
    std::vector<char> valid_types = {'A', 'B', 'D', 'R', 'T', 'V', 'W', 'G', 'I',
                                      'N', 'P', 'C', 'S', 'U', 'u', 'v', 'w', '-', '?',
                                      'a', 'b', 'd', 'r', 't'};

    std::vector<int> dp;
    size_t current_names_offset = names_offset_;

    while (true) {
        size_t pos = current_names_offset;
        if (pos >= size_ || pos >= markers_offset_) {
            throw KallsymsNotFound("Could not find kallsyms_names");
        }

        if (pos + 2 > markers_offset_) {
            current_names_offset -= 4;
            continue;
        }

        uint8_t first_len = data_[pos];
        if (first_len == 0 || first_len > 127) {
            current_names_offset -= 4;
            continue;
        }

        uint8_t first_token_idx = data_[pos + 1];
        if (first_token_idx >= token_table_.size()) {
            current_names_offset -= 4;
            continue;
        }

        char first_type = token_table_[first_token_idx][0];
        bool valid_first_type = std::find(valid_types.begin(), valid_types.end(),
                                           first_type) != valid_types.end() ||
                                 std::find(valid_types.begin(), valid_types.end(),
                                           std::toupper(first_type)) != valid_types.end();
        if (!valid_first_type) {
            current_names_offset -= 4;
            continue;
        }

        for (size_t i = dp.size(); i <= markers_offset_ - pos; ++i) {
            size_t check_pos = markers_offset_ - i;
            if (check_pos < pos) {
                dp.push_back(-1);
                continue;
            }

            uint8_t len_byte = data_[check_pos];
            int sym_size;
            if (len_byte & 0x80) {
                sym_size = (len_byte & 0x7F) | (data_[check_pos + 1] << 7);
                sym_size += 2;
            } else {
                sym_size = len_byte + 1;
            }

            if (len_byte == 0) {
                dp.push_back(i <= 256 ? 0 : -1);
            } else if (i < static_cast<size_t>(sym_size) || dp[i - sym_size] == -1) {
                dp.push_back(-1);
            } else {
                dp.push_back(dp[i - sym_size] + 1);
            }
        }

        int num_syms = dp.empty() ? 0 : dp.back();
        if (num_syms < 256) {
            current_names_offset -= 4;
            continue;
        }

        uint8_t encoded[8];
        for (int i = 0; i < offset_table_element_size_; ++i) {
            if (is_big_endian_) {
                encoded[offset_table_element_size_ - 1 - i] = (num_syms >> (i * 8)) & 0xFF;
            } else {
                encoded[i] = (num_syms >> (i * 8)) & 0xFF;
            }
        }

        size_t search_start = (pos > 276) ? pos - 276 : 0;
        size_t found = mem_rfind(encoded, offset_table_element_size_, search_start, pos);

        if (found == kNpos) {
            current_names_offset -= 4;
            continue;
        }

        num_symbols_ = num_syms;
        names_offset_ = pos;
        num_syms_offset_ = found;

        std::fprintf(stderr, "[+] Found kallsyms_names at 0x%zx (%zu symbols)\n",
                     names_offset_, num_symbols_);
        std::fprintf(stderr, "[+] Found kallsyms_num_syms at 0x%zx\n", num_syms_offset_);
        return;
    }
}

void KallsymsFinder::find_addresses_or_offsets() {
    bool likely_relative = (version_.major > 4 || (version_.major == 4 && version_.minor >= 6));

    if (use_absolute_) {
        likely_relative = false;
    }

    int address_size = is_64_bits_ ? 8 : offset_table_element_size_;
    int offset_size = std::min(4, offset_table_element_size_);

    bool new_layout = (version_.major > 6 || (version_.major == 6 && version_.minor >= 4));

    for (bool try_relative : {likely_relative, !likely_relative}) {
        size_t pos;

        if (new_layout) {
            int align_size = is_64_bits_ ? 8 : 4;
            pos = token_index_end_offset_;
            pos = (pos + align_size - 1) & ~(align_size - 1);

            if (try_relative) {
                pos += num_symbols_ * offset_size;
                pos = (pos + align_size - 1) & ~(align_size - 1);
                pos += address_size;
            } else {
                pos += num_symbols_ * address_size;
            }
        } else {
            pos = num_syms_offset_;
        }

        if (try_relative) {
            has_relative_base_ = true;

            size_t expected_offsets_size = num_symbols_ * static_cast<size_t>(offset_size);

            size_t min_offsets_start = (pos > expected_offsets_size + 256) ?
                                        pos - expected_offsets_size - 256 : 0;

            size_t search_pos = pos;
            while (search_pos >= static_cast<size_t>(address_size) &&
                   search_pos > min_offsets_start + expected_offsets_size) {
                bool all_zero = true;
                for (int i = 0; i < address_size; ++i) {
                    if (data_[search_pos - address_size + i] != 0) {
                        all_zero = false;
                        break;
                    }
                }
                if (!all_zero) break;
                search_pos -= address_size;
            }

            bool found_nonzero = (search_pos < pos);
            size_t relative_base_pos = search_pos;

            if (found_nonzero && search_pos >= static_cast<size_t>(address_size)) {
                relative_base_pos = search_pos - address_size;
                relative_base_address_ = read_int(relative_base_pos, address_size);
            } else {
                relative_base_address_ = 0;
                relative_base_pos = pos;
            }

            bool valid_relative_base = (relative_base_address_ == 0) ||
                                       (relative_base_address_ >= kMinKernelVA &&
                                        relative_base_address_ < kMaxKernelVA &&
                                        (relative_base_address_ & 0xFFF) == 0);

            if (!valid_relative_base) {
                std::fprintf(stderr, "[!] Invalid relative_base 0x%llx detected, recalculating\n",
                             static_cast<unsigned long long>(relative_base_address_));

                relative_base_address_ = 0;
                relative_base_pos = pos;
            }

            search_pos = relative_base_pos;
            while (search_pos >= static_cast<size_t>(offset_size)) {
                bool all_zero = true;
                for (int i = 0; i < offset_size; ++i) {
                    if (data_[search_pos - offset_size + i] != 0) {
                        all_zero = false;
                        break;
                    }
                }
                if (!all_zero) break;
                search_pos -= offset_size;
            }

            if (search_pos < expected_offsets_size) {
                continue;
            }

            pos = search_pos - expected_offsets_size;
            pos = pos & ~(static_cast<size_t>(offset_size) - 1);

            // Check for leading zero entries that we may have missed
            // The first few symbols often have offset 0 (for _head, _text, etc)
            while (pos >= static_cast<size_t>(offset_size)) {
                int64_t prev_val = read_signed_int(pos - offset_size, offset_size);
                // Check if the previous entry is a valid offset (0 or small positive)
                // and is less than or equal to the current first entry
                int64_t curr_first = read_signed_int(pos, offset_size);
                if (prev_val >= 0 && prev_val <= curr_first && prev_val < 0x10000) {
                    pos -= offset_size;
                } else {
                    break;
                }
            }

            if (relative_base_address_ == 0) {
                bool valid_kernel_base = !relocations_.empty() &&
                                         kernel_base_ >= kMinKernelVA &&
                                         kernel_base_ < kMaxKernelVA &&
                                         (kernel_base_ & 0xFFF) == 0;

                if (is_64_bits_ && valid_kernel_base) {
                    relative_base_address_ = kernel_base_;
                    std::fprintf(stderr, "[*] Using kernel base from relocations: 0x%llx\n",
                                 static_cast<unsigned long long>(relative_base_address_));
                } else if (is_64_bits_) {
                    relative_base_address_ = 0xffff000008080000ULL;
                    std::fprintf(stderr, "[*] Using default ARM64 kernel base: 0x%llx\n",
                                 static_cast<unsigned long long>(relative_base_address_));
                }
            }
        } else {
            has_relative_base_ = false;

            while (pos >= static_cast<size_t>(address_size)) {
                bool all_zero = true;
                for (int i = 0; i < address_size; ++i) {
                    if (data_[pos - address_size + i] != 0) {
                        all_zero = false;
                        break;
                    }
                }
                if (!all_zero) break;
                pos -= address_size;
            }

            if (pos < num_symbols_ * static_cast<size_t>(address_size)) {
                continue;
            }

            pos -= num_symbols_ * address_size;
        }

        addresses_offset_ = pos;

        std::vector<int64_t> raw_values;
        raw_values.reserve(num_symbols_);

        int negative_count = 0;

        for (size_t i = 0; i < num_symbols_; ++i) {
            int64_t val;
            if (has_relative_base_) {
                val = read_signed_int(pos + i * offset_size, offset_size);
                if (val < 0) ++negative_count;
            } else {
                val = static_cast<int64_t>(read_int(pos + i * address_size, address_size));
            }
            raw_values.push_back(val);
        }

        has_absolute_percpu_ = has_relative_base_ &&
                               (negative_count >= static_cast<int>(num_symbols_) / 2);

        symbol_addresses_.clear();
        symbol_addresses_.reserve(num_symbols_);

        int null_count = 0;

        for (size_t i = 0; i < num_symbols_; ++i) {
            int64_t val = raw_values[i];
            uint64_t addr;

            if (has_relative_base_) {
                if (has_absolute_percpu_) {
                    addr = (val < 0) ? (relative_base_address_ - 1 - val) : static_cast<uint64_t>(val);
                } else {
                    addr = static_cast<uint64_t>(val) + relative_base_address_;
                }
            } else {
                addr = static_cast<uint64_t>(val);
            }

            if (addr == 0) ++null_count;
            symbol_addresses_.push_back(addr);
        }

        if (null_count > static_cast<int>(num_symbols_) / 5) {
            continue;
        }

        std::fprintf(stderr, "[+] Found %s at 0x%zx\n",
                     has_relative_base_ ? "kallsyms_offsets" : "kallsyms_addresses",
                     addresses_offset_);
        if (has_relative_base_) {
            std::fprintf(stderr, "[+] Relative base: 0x%llx\n",
                         static_cast<unsigned long long>(relative_base_address_));
            if (has_absolute_percpu_) {
                std::fprintf(stderr, "[+] Has absolute percpu symbols\n");
            }
        }
        return;
    }

    throw KallsymsNotFound("Could not find kallsyms_addresses/offsets");
}

void KallsymsFinder::parse_symbol_table() {
    symbol_names_.clear();
    symbol_names_.reserve(num_symbols_);

    size_t pos = names_offset_;

    for (size_t i = 0; i < num_symbols_; ++i) {
        int len = data_[pos++];
        if (len & 0x80) {
            len = (len & 0x7F) | (data_[pos++] << 7);
        }

        std::string name;
        for (int j = 0; j < len; ++j) {
            uint8_t token_idx = data_[pos++];
            name += token_table_[token_idx];
        }
        symbol_names_.push_back(name);
    }

    symbols_.clear();
    symbols_.reserve(num_symbols_);

    for (size_t i = 0; i < num_symbols_; ++i) {
        Symbol sym;
        const std::string& full_name = symbol_names_[i];

        if (full_name.empty()) {
            sym.type = '?';
            sym.name = "";
        } else {
            sym.type = full_name[0];
            sym.name = full_name.substr(1);
        }

        sym.address = symbol_addresses_[i];
        sym.is_global = std::isupper(sym.type);

        symbols_.push_back(sym);
    }
}

std::optional<Symbol> KallsymsFinder::find_symbol(std::string_view name) const {
    for (const auto& sym : symbols_) {
        if (sym.name == name) {
            return sym;
        }
    }
    return std::nullopt;
}

void KallsymsFinder::for_each_symbol(const std::function<bool(const Symbol&)>& callback) const {
    for (const auto& sym : symbols_) {
        if (callback(sym)) break;
    }
}

void KallsymsFinder::print_symbols() const {
    const char* fmt = is_64_bits_ ? "%016llx %c %s\n" : "%08llx %c %s\n";

    for (const auto& sym : symbols_) {
        std::printf(fmt, static_cast<unsigned long long>(sym.address),
                    sym.type, sym.name.c_str());
    }
}

} // namespace ktool