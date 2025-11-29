/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "kallsym.hpp"
#include "../core/logging.hpp"
#include "../arm64/insn.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace kp {
namespace kernel {

// Helper: memory search (memmem equivalent)

static const uint8_t *mem_find(const uint8_t *haystack, size_t haystack_len,
                               const uint8_t *needle, size_t needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) {
        return nullptr;
    }

    const uint8_t *end = haystack + haystack_len - needle_len + 1;
    for (const uint8_t *p = haystack; p < end; ++p) {
        if (std::memcmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return nullptr;
}

// Endian-aware unpacking

uint64_t Kallsyms::uint_unpack(int32_t offset, int32_t size) const {
    if (offset < 0 || offset + size > static_cast<int32_t>(imglen_)) {
        return 0;
    }

    uint64_t value = 0;
    if (is_be_) {
        for (int i = 0; i < size; ++i) {
            value = (value << 8) | img_[offset + i];
        }
    } else {
        for (int i = size - 1; i >= 0; --i) {
            value = (value << 8) | img_[offset + i];
        }
    }
    return value;
}

int64_t Kallsyms::int_unpack(int32_t offset, int32_t size) const {
    uint64_t uval = uint_unpack(offset, size);
    // Sign extend based on size
    if (size == 4 && (uval & 0x80000000)) {
        return static_cast<int64_t>(uval | 0xFFFFFFFF00000000ULL);
    }
    return static_cast<int64_t>(uval);
}

// Size helpers

int32_t Kallsyms::get_markers_elem_size() const {
    if (markers_elem_size_) return markers_elem_size_;

    int32_t elem_size = asm_long_size_;
    if (version_.major < 4 || (version_.major == 4 && version_.minor < 20)) {
        elem_size = asm_ptr_size_;
    }
    return elem_size;
}

int32_t Kallsyms::get_num_syms_elem_size() const {
    int32_t elem_size = asm_long_size_;
    if (version_.major < 4 || (version_.major == 4 && version_.minor < 20)) {
        elem_size = asm_ptr_size_;
    }
    return elem_size;
}

// Main parse function

Result<void> Kallsyms::parse(uint8_t *img, size_t imglen) {
    img_ = img;
    imglen_ = imglen;

    // Initialize for ARM64
    asm_long_size_ = 4;
    asm_ptr_size_ = 8;

    // Step 1: Find linux banner and extract version
    auto rc = find_linux_banner();
    if (!rc) return rc;

    // Step 2: Find token table
    rc = find_token_table();
    if (!rc) return rc;

    // Step 3: Find token index
    rc = find_token_index();
    if (!rc) return rc;

    // Make a copy for potential relocation attempts
    std::vector<uint8_t> img_copy(img, img + imglen);

    // Step 4-8: Try parsing with potential relocation
    auto try_parse = [&]() -> Result<void> {
        auto r = try_find_arm64_relo_table();
        if (!r) return r;

        r = find_markers();
        if (!r) return r;

        r = find_approx_addresses_or_offsets();
        if (!r) return r;

        r = find_names();
        if (!r) return r;

        r = find_num_syms();
        if (!r) return r;

        r = correct_addresses_or_offsets();
        return r;
    };

    // First attempt
    rc = try_parse();
    if (rc) {
        return Result<void>::Ok();
    }

    // Second attempt: reset and try without relocation
    std::memcpy(img_, img_copy.data(), imglen);
    relo_applied_ = false;

    rc = try_parse();
    if (rc) {
        return Result<void>::Ok();
    }

    // Third attempt: try with default kernel base
    if (kernel_base_ != ELF64_KERNEL_MIN_VA) {
        kernel_base_ = ELF64_KERNEL_MIN_VA;
        std::memcpy(img_, img_copy.data(), imglen);
        relo_applied_ = false;

        rc = try_parse();
        if (rc) {
            return Result<void>::Ok();
        }
    }

    return Result<void>::Err("Failed to parse kallsyms");
}

// Find linux banner and extract version

Result<void> Kallsyms::find_linux_banner() {
    const char prefix[] = "Linux version ";
    size_t prefix_len = strlen(prefix);

    const uint8_t *pos = img_;
    const uint8_t *end = img_ + imglen_;
    banner_num_ = 0;

    while (pos < end - prefix_len) {
        pos = mem_find(pos + 1, end - pos - 1,
                       reinterpret_cast<const uint8_t *>(prefix), prefix_len);
        if (!pos) break;

        // Verify it looks like a version (digit.digit pattern)
        if (std::isdigit(pos[prefix_len]) && pos[prefix_len + 1] == '.') {
            banner_offsets_[banner_num_++] = static_cast<int32_t>(pos - img_);
            kp_log_info("linux_banner %d offset: 0x%x\n", banner_num_,
                        banner_offsets_[banner_num_ - 1]);
            if (banner_num_ >= 4) break;
        }
    }

    if (banner_num_ == 0) {
        return Result<void>::Err("No linux banner found");
    }

    // Parse version from the last banner
    const char *banner = reinterpret_cast<const char *>(
        img_ + banner_offsets_[banner_num_ - 1]);
    const char *ver_start = banner + prefix_len;

    char *dot = nullptr;
    version_.major = static_cast<uint8_t>(std::strtoul(ver_start, &dot, 10));
    version_.minor = static_cast<uint8_t>(std::strtoul(dot + 1, &dot, 10));
    int32_t patch = static_cast<int32_t>(std::strtoul(dot + 1, &dot, 10));
    version_.patch = (patch <= 255) ? patch : 255;

    kp_log_info("kernel version: %d.%d.%d\n",
                version_.major, version_.minor, version_.patch);
    return Result<void>::Ok();
}

// Find token table

Result<void> Kallsyms::find_token_table() {
    // Build search patterns: "0\01\02\03..." and "a\0b\0c\0..."
    char nums_syms[20] = {0};
    for (int i = 0; i < 10; ++i) {
        nums_syms[i * 2] = '0' + i;
    }

    char letters_syms[20] = {0};
    for (int i = 0; i < 10; ++i) {
        letters_syms[i * 2] = 'a' + i;
    }

    const uint8_t *pos = img_;
    const uint8_t *imgend = img_ + imglen_;
    const uint8_t *num_start = nullptr;

    while (pos < imgend) {
        num_start = mem_find(pos, imgend - pos,
                             reinterpret_cast<const uint8_t *>(nums_syms),
                             sizeof(nums_syms));
        if (!num_start) {
            return Result<void>::Err("Failed to find token table");
        }

        const uint8_t *num_end = num_start + sizeof(nums_syms);
        if (!*num_end || !*(num_end + 1)) {
            pos = num_start + 1;
            continue;
        }

        // Skip to where letters should be
        const uint8_t *letter = num_end;
        for (int i = 0; letter < imgend && i < 'a' - '9' - 1; ++letter) {
            if (!*letter) ++i;
        }

        if (letter == mem_find(letter, sizeof(letters_syms),
                               reinterpret_cast<const uint8_t *>(letters_syms),
                               sizeof(letters_syms))) {
            break;
        }

        pos = num_start + 1;
    }

    // Walk backward to find start
    pos = num_start;
    for (int i = 0; pos > img_ && i < '0' + 1; --pos) {
        if (!*pos) ++i;
    }

    int32_t offset = static_cast<int32_t>(pos + 2 - img_);
    offset = align_up(offset, 4);

    token_table_offset_ = offset;
    kp_log_info("kallsyms_token_table offset: 0x%08x\n", offset);

    // Rebuild token table pointers
    const char *p = reinterpret_cast<const char *>(img_ + token_table_offset_);
    for (int i = 0; i < KSYM_TOKEN_NUMS; ++i) {
        token_table_[i] = p;
        while (*p++) {}
    }

    return Result<void>::Ok();
}

// Find token index

Result<void> Kallsyms::find_token_index() {
    uint16_t le_index[KSYM_TOKEN_NUMS] = {0};
    uint16_t be_index[KSYM_TOKEN_NUMS] = {0};

    int32_t start = token_table_offset_;
    int32_t offset = start;

    // Build expected token index values
    for (int i = 0; i < KSYM_TOKEN_NUMS; ++i) {
        uint16_t idx = offset - start;
        le_index[i] = endian::to_le(idx);
        be_index[i] = endian::to_be(idx);
        while (img_[offset++]) {}
    }

    // Search for the index table
    const uint8_t *le_pos = mem_find(img_, imglen_,
                                     reinterpret_cast<const uint8_t *>(le_index),
                                     sizeof(le_index));
    const uint8_t *be_pos = mem_find(img_, imglen_,
                                     reinterpret_cast<const uint8_t *>(be_index),
                                     sizeof(be_index));

    if (!le_pos && !be_pos) {
        return Result<void>::Err("Failed to find token index");
    }

    is_be_ = (be_pos != nullptr);
    const uint8_t *pos = is_be_ ? be_pos : le_pos;
    token_index_offset_ = static_cast<int32_t>(pos - img_);

    kp_log_info("endian: %s\n", is_be_ ? "big" : "little");
    kp_log_info("kallsyms_token_index offset: 0x%08x\n", token_index_offset_);

    return Result<void>::Ok();
}

// Try to find and apply ARM64 relocation table

Result<void> Kallsyms::try_find_arm64_relo_table() {
    uint64_t min_va = ELF64_KERNEL_MIN_VA;
    uint64_t max_va = ELF64_KERNEL_MAX_VA;
    uint64_t kernel_va = max_va;
    int32_t cand = 0;
    int rela_num = 0;

    while (cand < static_cast<int32_t>(imglen_) - 24) {
        uint64_t r_offset = uint_unpack(cand, 8);
        uint64_t r_info = uint_unpack(cand + 8, 8);
        uint64_t r_addend = uint_unpack(cand + 16, 8);

        if ((r_offset & 0xffff000000000000ULL) == 0xffff000000000000ULL &&
            r_info == 0x403) {
            if (!(r_addend & 0xfff) && r_addend >= min_va && r_addend < kernel_va) {
                kernel_va = r_addend;
            }
            cand += 24;
            rela_num++;
        } else if (rela_num && !r_offset && !r_info && !r_addend) {
            cand += 24;
            rela_num++;
        } else {
            if (rela_num >= static_cast<int>(ARM64_RELO_MIN_NUM)) break;
            cand += 8;
            rela_num = 0;
            kernel_va = max_va;
        }
    }

    if (kernel_base_) {
        kp_log_info("arm64 relocation kernel_va: 0x%llx, override: 0x%llx\n",
                    static_cast<unsigned long long>(kernel_va),
                    static_cast<unsigned long long>(kernel_base_));
        kernel_va = kernel_base_;
    } else {
        kernel_base_ = kernel_va;
        kp_log_info("arm64 relocation kernel_va: 0x%llx\n",
                    static_cast<unsigned long long>(kernel_va));
    }

    if (rela_num < static_cast<int>(ARM64_RELO_MIN_NUM)) {
        kp_log_info("no arm64 relocation table found\n");
        return Result<void>::Ok();
    }

    int32_t cand_start = cand - 24 * rela_num;
    int32_t cand_end = cand - 24;

    // Find actual end (skip trailing zeros)
    while (cand_end > cand_start) {
        if (uint_unpack(cand_end, 8) && uint_unpack(cand_end + 8, 8) &&
            uint_unpack(cand_end + 16, 8)) {
            break;
        }
        cand_end -= 24;
    }
    cand_end += 24;

    rela_num = (cand_end - cand_start) / 24;
    kp_log_info("arm64 relocation table range: [0x%08x, 0x%08x), count: 0x%08x\n",
                cand_start, cand_end, rela_num);

    // Apply relocations
    int32_t max_offset = static_cast<int32_t>(imglen_) - 8;
    int apply_num = 0;

    for (cand = cand_start; cand < cand_end; cand += 24) {
        uint64_t r_offset = uint_unpack(cand, 8);
        uint64_t r_info = uint_unpack(cand + 8, 8);
        uint64_t r_addend = uint_unpack(cand + 16, 8);

        if (!r_offset && !r_info && !r_addend) continue;
        if (r_offset <= kernel_va || r_offset >= max_va - imglen_) continue;

        int32_t offset = static_cast<int32_t>(r_offset - kernel_va);
        if (offset < 0 || offset >= max_offset) {
            kp_log_warn("bad rela offset: 0x%llx\n",
                        static_cast<unsigned long long>(r_offset));
            continue;
        }

        uint64_t value = uint_unpack(offset, 8);
        if (value == r_addend) continue;

        // Apply relocation (little-endian)
        uint64_t new_val = value + r_addend;
        std::memcpy(img_ + offset, &new_val, 8);
        apply_num++;
    }

    kp_log_info("applied 0x%08x relocation entries\n", apply_num);
    if (apply_num) relo_applied_ = true;

    return Result<void>::Ok();
}

// Find approximate addresses array

Result<void> Kallsyms::find_approx_addresses() {
    int32_t elem_size = asm_ptr_size_;
    int64_t prev_offset = 0;
    int32_t sym_num = 0;
    int32_t cand = 0;

    for (; cand < static_cast<int32_t>(imglen_) - KSYM_MIN_NEQ_SYMS * elem_size;
         cand += elem_size) {
        uint64_t address = uint_unpack(cand, elem_size);

        if (!sym_num) {
            if (address & 0xff) continue;
            if (elem_size == 4 && (address & 0xff800000) != 0xff800000) continue;
            if (elem_size == 8 && (address & 0xffff000000000000ULL) !=
                                      0xffff000000000000ULL) continue;
            prev_offset = address;
            sym_num++;
            continue;
        }

        if (address >= static_cast<uint64_t>(prev_offset)) {
            prev_offset = address;
            if (++sym_num >= static_cast<int>(KSYM_MIN_NEQ_SYMS)) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }

    if (sym_num < static_cast<int>(KSYM_MIN_NEQ_SYMS)) {
        return Result<void>::Err("Failed to find approximate addresses");
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;
    approx_offset_ = cand;

    // Find end
    prev_offset = 0;
    for (; cand < static_cast<int32_t>(imglen_); cand += elem_size) {
        uint64_t offset = uint_unpack(cand, elem_size);
        if (offset < static_cast<uint64_t>(prev_offset)) break;
        prev_offset = offset;
    }

    approx_end_ = cand;
    has_relative_base_ = false;
    approx_num_ = (cand - approx_offset_) / elem_size;

    kp_log_info("approximate kallsyms_addresses range: [0x%08x, 0x%08x) count: 0x%08x\n",
                approx_offset_, cand, approx_num_);

    return Result<void>::Ok();
}

// Find approximate offsets array (for CONFIG_KALLSYMS_BASE_RELATIVE)

Result<void> Kallsyms::find_approx_offsets() {
    int32_t elem_size = asm_long_size_;
    int64_t prev_offset = 0;
    int32_t sym_num = 0;
    int32_t cand = 0;

    for (; cand < static_cast<int32_t>(imglen_) - KSYM_MIN_NEQ_SYMS * elem_size;
         cand += elem_size) {
        int64_t offset = int_unpack(cand, elem_size);

        if (offset == prev_offset) {
            continue;
        } else if (offset > prev_offset) {
            prev_offset = offset;
            if (++sym_num >= static_cast<int>(KSYM_MIN_NEQ_SYMS)) break;
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
    }

    if (sym_num < static_cast<int>(KSYM_MIN_NEQ_SYMS)) {
        return Result<void>::Err("Failed to find approximate offsets");
    }

    cand -= KSYM_MIN_NEQ_SYMS * elem_size;

    // Walk backward to first zero
    while (int_unpack(cand, elem_size) != 0) cand -= elem_size;

    // Count consecutive zeros
    int32_t zero_count = 0;
    while (int_unpack(cand, elem_size) == 0 && zero_count < 10) {
        cand -= elem_size;
        zero_count++;
    }
    cand += elem_size;

    approx_offset_ = cand;

    // Find end
    prev_offset = 0;
    for (; cand < static_cast<int32_t>(imglen_); cand += elem_size) {
        int64_t offset = int_unpack(cand, elem_size);
        if (offset < prev_offset) break;
        prev_offset = offset;
    }

    approx_end_ = cand;
    has_relative_base_ = true;
    approx_num_ = (cand - approx_offset_) / elem_size;

    kp_log_info("approximate kallsyms_offsets range: [0x%08x, 0x%08x) count: 0x%08x\n",
                approx_offset_, cand, approx_num_);

    return Result<void>::Ok();
}

Result<void> Kallsyms::find_approx_addresses_or_offsets() {
    // Try offsets first for kernels >= 4.6
    if (version_.major > 4 || (version_.major == 4 && version_.minor >= 6)) {
        auto rc = find_approx_offsets();
        if (rc) return rc;
    }
    return find_approx_addresses();
}

// Find markers array

Result<void> Kallsyms::find_markers_internal(int32_t elem_size) {
    int32_t cand = token_table_offset_;
    int64_t last_marker = imglen_;
    int count = 0;

    while (cand > 0x10000) {
        int64_t marker = int_unpack(cand, elem_size);
        if (last_marker > marker) {
            count++;
            if (!marker && count > static_cast<int>(KSYM_MIN_MARKER)) break;
        } else {
            count = 0;
            last_marker = imglen_;
        }
        last_marker = marker;
        cand -= elem_size;
    }

    if (count < static_cast<int>(KSYM_MIN_MARKER)) {
        return Result<void>::Err("Failed to find markers");
    }

    int32_t marker_end = cand + count * elem_size + elem_size;
    markers_offset_ = cand;
    marker_num_ = count;
    markers_elem_size_ = elem_size;

    kp_log_info("kallsyms_markers range: [0x%08x, 0x%08x), count: 0x%08x\n",
                cand, marker_end, count);

    return Result<void>::Ok();
}

Result<void> Kallsyms::find_markers() {
    int32_t elem_size = get_markers_elem_size();
    auto rc = find_markers_internal(elem_size);
    if (!rc && elem_size == 8) {
        return find_markers_internal(4);
    }
    return rc;
}

// Find names array

Result<void> Kallsyms::find_names() {
    int32_t marker_elem_size = get_markers_elem_size();
    int32_t cand = 0x4000;
    int32_t test_marker_num = -1;

    for (; cand < markers_offset_; ++cand) {
        int32_t pos = cand;
        test_marker_num = KSYM_FIND_NAMES_USED_MARKER;

        for (int32_t i = 0;; ++i) {
            int32_t len = img_[pos++];
            if (len > 0x7F) len = (len & 0x7F) + (img_[pos++] << 7);
            if (!len || len >= static_cast<int32_t>(KSYM_SYMBOL_LEN)) break;
            pos += len;
            if (pos >= markers_offset_) break;

            if (i && (i & 0xFF) == 0xFF) {
                int32_t mark_len = static_cast<int32_t>(int_unpack(
                    markers_offset_ + ((i >> 8) + 1) * marker_elem_size,
                    marker_elem_size));
                if (pos - cand != mark_len) break;
                if (!--test_marker_num) break;
            }
        }
        if (!test_marker_num) break;
    }

    if (test_marker_num) {
        return Result<void>::Err("Failed to find names");
    }

    names_offset_ = cand;
    kp_log_info("kallsyms_names offset: 0x%08x\n", cand);

    return Result<void>::Ok();
}

// Find number of symbols

Result<void> Kallsyms::find_num_syms() {
    constexpr int NSYMS_MAX_GAP = 10;

    int32_t approx_end = names_offset_;
    int32_t num_syms_elem_size = 4;

    for (int32_t cand = approx_end; cand > approx_end - 4096;
         cand -= num_syms_elem_size) {
        int nsyms = static_cast<int>(int_unpack(cand, num_syms_elem_size));
        if (!nsyms) continue;
        if (approx_num_ > nsyms && approx_num_ - nsyms > NSYMS_MAX_GAP) continue;
        if (nsyms > approx_num_ && nsyms - approx_num_ > NSYMS_MAX_GAP) continue;

        num_syms_ = nsyms;
        num_syms_offset_ = cand;
        break;
    }

    if (!num_syms_offset_ || !num_syms_) {
        num_syms_ = approx_num_ - NSYMS_MAX_GAP;
        kp_log_warn("can't find kallsyms_num_syms, using: 0x%08x\n", num_syms_);
    } else {
        kp_log_info("kallsyms_num_syms offset: 0x%08x, value: 0x%08x\n",
                    num_syms_offset_, num_syms_);
    }

    return Result<void>::Ok();
}

// Decompress symbol name

int32_t Kallsyms::decompress_symbol(int32_t &pos, char *type, std::string &name) const {
    name.clear();

    int32_t len = img_[pos++];
    if (len > 0x7F) len = (len & 0x7F) + (img_[pos++] << 7);
    if (!len || len >= static_cast<int32_t>(KSYM_SYMBOL_LEN)) return -1;

    int32_t end_pos = pos + len;

    for (int32_t i = 0; i < len; ++i) {
        int32_t tokidx = img_[pos + i];
        const char *token = token_table_[tokidx];
        if (!i && type) {
            *type = *token;
            token++;
        }
        name += token;
    }

    pos = end_pos;
    return 0;
}

// ARM64 instruction encoding classes (from Linux kernel insn.h)

enum Aarch64InsnEncodingClass {
    AARCH64_INSN_CLS_UNKNOWN = 0,  // UNALLOCATED
    AARCH64_INSN_CLS_DP_IMM,       // Data processing - immediate
    AARCH64_INSN_CLS_DP_REG,       // Data processing - register
    AARCH64_INSN_CLS_DP_FPSIMD,    // Data processing - SIMD and FP
    AARCH64_INSN_CLS_LDST,         // Loads and stores
    AARCH64_INSN_CLS_BR_SYS,       // Branch, exception generation and system instructions
};

// ARM64 special register values
static constexpr uint32_t AARCH64_INSN_SPCLREG_SP_EL0 = 0xC208;
static constexpr uint32_t AARCH64_INSN_REG_SP = 31;

// Instruction class lookup table (indexed by bits 25-28)
static const Aarch64InsnEncodingClass aarch64_insn_encoding_class[] = {
    AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN, AARCH64_INSN_CLS_UNKNOWN,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_REG,  AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_FPSIMD,
    AARCH64_INSN_CLS_DP_IMM,  AARCH64_INSN_CLS_DP_IMM,  AARCH64_INSN_CLS_BR_SYS,  AARCH64_INSN_CLS_BR_SYS,
    AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_REG,  AARCH64_INSN_CLS_LDST,    AARCH64_INSN_CLS_DP_FPSIMD,
};

static inline Aarch64InsnEncodingClass aarch64_get_insn_class(uint32_t insn) {
    return aarch64_insn_encoding_class[(insn >> 25) & 0xf];
}

static inline uint32_t aarch64_insn_extract_system_reg(uint32_t insn) {
    return (insn & 0x1FFFE0) >> 5;
}

static inline uint32_t aarch64_insn_decode_register_rn(uint32_t insn) {
    return (insn >> 5) & 0x1F;
}

// ARM64 pid_vnr verification

int Kallsyms::arm64_verify_pid_vnr(int32_t offset) {
    for (int i = 0; i < 6; ++i) {
        int32_t insn_offset = offset + i * 4;
        if (insn_offset + 4 > static_cast<int32_t>(imglen_)) break;

        uint32_t insn = static_cast<uint32_t>(uint_unpack(insn_offset, 4));
        Aarch64InsnEncodingClass enc = aarch64_get_insn_class(insn);

        if (enc == AARCH64_INSN_CLS_BR_SYS) {
            if (aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0) {
                kp_log_info("pid_vnr verfied sp_el0, insn: 0x%x\n", insn);
                current_type_ = CurrentType::SpEl0;
                return 0;
            }
        } else if (enc == AARCH64_INSN_CLS_DP_IMM) {
            uint32_t rn = aarch64_insn_decode_register_rn(insn);
            if (rn == AARCH64_INSN_REG_SP) {
                kp_log_info("pid_vnr verfied sp, insn: 0x%x\n", insn);
                current_type_ = CurrentType::Sp;
                return 0;
            }
        }
    }
    return -1;
}

// Correct addresses/offsets by banner

Result<void> Kallsyms::correct_by_banner() {
    // Find linux_banner symbol index
    int32_t pos = names_offset_;
    int32_t banner_idx = -1;
    std::string name;
    char type;

    for (int32_t i = 0; pos < markers_offset_; ++i) {
        if (decompress_symbol(pos, &type, name)) break;
        if (name == "linux_banner") {
            banner_idx = i;
            kp_log_info("names table linux_banner index: 0x%08x\n", banner_idx);
            break;
        }
    }

    if (banner_idx < 0) {
        return Result<void>::Err("No linux_banner in names table");
    }

    symbol_banner_idx_ = -1;

    int32_t elem_size = has_relative_base_ ? get_offsets_elem_size()
                                           : get_addresses_elem_size();

    // Try each banner offset
    for (int i = 0; i < banner_num_; ++i) {
        int32_t target_offset = banner_offsets_[i];
        pos = approx_offset_;
        int32_t end = pos + 4096 + elem_size;

        for (; pos < end; pos += elem_size) {
            uint64_t base = uint_unpack(pos, elem_size);
            int32_t offset = static_cast<int32_t>(
                uint_unpack(pos + banner_idx * elem_size, elem_size) - base);
            if (offset == target_offset) break;
        }

        if (pos < end) {
            symbol_banner_idx_ = i;
            kp_log_info("linux_banner index: %d\n", i);
            break;
        }
    }

    if (symbol_banner_idx_ < 0) {
        return Result<void>::Err("Failed to correct addresses/offsets by banner");
    }

    if (has_relative_base_) {
        offsets_offset_ = pos;
        kp_log_info("kallsyms_offsets offset: 0x%08x\n", pos);
    } else {
        addresses_offset_ = pos;
        kp_log_info("kallsyms_addresses offset: 0x%08x\n", pos);
        kernel_base_ = uint_unpack(addresses_offset_, elem_size);
        kp_log_info("kernel base address: 0x%llx\n",
                    static_cast<unsigned long long>(kernel_base_));
    }

    // Verify with pid_vnr if possible
    auto pid_offset = get_offset("pid_vnr");
    if (pid_offset) {
        if (arm64_verify_pid_vnr(*pid_offset)) {
            kp_log_warn("pid_vnr verification failed\n");
        }
    }

    return Result<void>::Ok();
}

// Correct addresses/offsets

Result<void> Kallsyms::correct_addresses_or_offsets() {
    auto rc = correct_by_banner();
    if (rc) {
        is_kallsyms_all_ = true;
        return rc;
    }

    is_kallsyms_all_ = false;
    kp_log_warn("no linux_banner, CONFIG_KALLSYMS_ALL=n\n");

    // Fall back to vectors-based correction (simplified)
    return Result<void>::Err("CONFIG_KALLSYMS_ALL=n not fully supported");
}

// Public API implementations

std::optional<int32_t> Kallsyms::get_offset(std::string_view name) const {
    auto sym = get_symbol(name);
    if (sym) return sym->offset;
    return std::nullopt;
}

std::optional<Symbol> Kallsyms::get_symbol(std::string_view name) const {
    int32_t pos = names_offset_;
    std::string decomp;
    char type;

    for (int32_t i = 0; i < num_syms_; ++i) {
        decomp.clear();
        int32_t p = pos;
        if (const_cast<Kallsyms *>(this)->decompress_symbol(pos, &type, decomp)) {
            break;
        }

        if (decomp == name) {
            Symbol sym;
            sym.name = decomp;
            sym.type = type;
            sym.offset = get_index_offset(i);
            sym.index = i;

            // Try to get size from next symbol
            for (int32_t j = i + 1; j < num_syms_; ++j) {
                int32_t next_off = get_index_offset(j);
                if (next_off != sym.offset) {
                    sym.size = next_off - sym.offset;
                    break;
                }
            }

            kp_log_info("%s: type: %c, offset: 0x%08x, size: 0x%x\n",
                        decomp.c_str(), type, sym.offset, sym.size);
            return sym;
        }
    }

    kp_log_warn("symbol not found: %.*s\n",
                static_cast<int>(name.size()), name.data());
    return std::nullopt;
}

int32_t Kallsyms::get_index_offset(int32_t index) const {
    int32_t elem_size;
    int32_t pos;

    if (has_relative_base_) {
        elem_size = get_offsets_elem_size();
        pos = offsets_offset_;
    } else {
        elem_size = get_addresses_elem_size();
        pos = addresses_offset_;
    }

    uint64_t target = const_cast<Kallsyms *>(this)->uint_unpack(
        pos + index * elem_size, elem_size);

    if (has_relative_base_) {
        return static_cast<int32_t>(target);
    }
    return static_cast<int32_t>(target - kernel_base_);
}

void Kallsyms::dump_all() const {
    int32_t pos = names_offset_;
    std::string name;
    char type;

    for (int32_t i = 0; i < num_syms_; ++i) {
        name.clear();
        if (const_cast<Kallsyms *>(this)->decompress_symbol(pos, &type, name)) {
            break;
        }
        int32_t offset = get_index_offset(i);
        std::fprintf(stdout, "0x%08x %c %s\n", offset, type, name.c_str());
    }
}

bool Kallsyms::needs_patch() const {
    return version_.major >= 6 && version_.minor >= 7;
}

void Kallsyms::for_each_symbol(const std::function<bool(const Symbol &)> &callback) const {
    int32_t pos = names_offset_;
    std::string name;
    char type;

    for (int32_t i = 0; i < num_syms_; ++i) {
        name.clear();
        if (const_cast<Kallsyms *>(this)->decompress_symbol(pos, &type, name)) {
            break;
        }

        Symbol sym;
        sym.name = name;
        sym.type = type;
        sym.offset = get_index_offset(i);
        sym.index = i;

        if (callback(sym)) break;
    }
}

// Extract kernel config

Result<std::string> extract_ikconfig(const uint8_t *img, size_t imglen) {
    const char *start_marker = "IKCFG_ST";
    const char *end_marker = "IKCFG_ED";

    const uint8_t *start = mem_find(img, imglen,
                                    reinterpret_cast<const uint8_t *>(start_marker),
                                    strlen(start_marker));
    if (!start) {
        return Result<std::string>::Err("IKCFG_ST not found");
    }

    const uint8_t *end = mem_find(img, imglen,
                                  reinterpret_cast<const uint8_t *>(end_marker),
                                  strlen(end_marker));
    if (!end || end <= start) {
        return Result<std::string>::Err("IKCFG_ED not found");
    }

    // Skip marker and get compressed data
    start += strlen(start_marker);
    size_t compressed_len = end - start;

    // Note: Full implementation would need zlib decompression
    return Result<std::string>::Err("IKCONFIG decompression not implemented");
}

} // namespace kernel
} // namespace kp