/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "patch.hpp"
#include "../arm64/insn.hpp"
#include "../core/file.hpp"
#include "../core/logging.hpp"
#include "../crypto/sha256.hpp"
#include "../kpm/module.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace kp {
namespace kernel {

// Constants

static constexpr size_t SZ_4K = 4096;
static constexpr const char *UNCOMPRESSED_PREFIX = "UNCOMPRESSED_IMG";

// Magic string for KernelPatch
static constexpr const char *KP_MAGIC = "KP1158";

// Memory search helper

static const uint8_t *mem_find(const uint8_t *haystack, size_t haystack_len,
                               const void *needle, size_t needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) {
        return nullptr;
    }

    const uint8_t *end = haystack + haystack_len - needle_len + 1;
    const auto *needle_bytes = static_cast<const uint8_t *>(needle);

    for (const uint8_t *p = haystack; p < end; ++p) {
        if (std::memcmp(p, needle_bytes, needle_len) == 0) {
            return p;
        }
    }
    return nullptr;
}

// KernelFile implementation

Result<KernelFile> KernelFile::from_file(const std::filesystem::path &path) {
    auto buf_result = Buffer::from_file(path);
    if (!buf_result) {
        return Result<KernelFile>::Err(buf_result.error());
    }

    KernelFile kf;
    kf.data_ = std::move(buf_result).unwrap();

    // Check for UNCOMPRESSED_IMG prefix
    if (kf.data_.size() >= 20 &&
        std::memcmp(kf.data_.data(), UNCOMPRESSED_PREFIX, 16) == 0) {
        kf.has_prefix_ = true;
        kf.img_offset_ = 20;
        kp_log_info("kernel image has UNCOMPRESSED_IMG header\n");
    }

    return Result<KernelFile>::Ok(std::move(kf));
}

KernelFile KernelFile::create_new(const KernelFile &old, size_t kimg_len) {
    KernelFile kf;
    kf.has_prefix_ = old.has_prefix_;
    kf.img_offset_ = old.img_offset_;

    size_t total_len = kf.img_offset_ + kimg_len;
    kf.data_.resize(total_len);

    // Copy prefix if present
    if (kf.img_offset_ > 0) {
        std::memcpy(kf.data_.data(), old.data_.data(), kf.img_offset_);
    }

    // Update length in prefix
    if (kf.has_prefix_) {
        uint32_t len32 = static_cast<uint32_t>(kimg_len);
        std::memcpy(kf.data_.data() + 16, &len32, 4);
    }

    return kf;
}

void KernelFile::set_kimg_len(size_t len) {
    data_.resize(img_offset_ + len);
    if (has_prefix_) {
        uint32_t len32 = static_cast<uint32_t>(len);
        std::memcpy(data_.data() + 16, &len32, 4);
    }
}

Result<void> KernelFile::to_file(const std::filesystem::path &path) const {
    return data_.to_file(path);
}

// Preset finding

Preset *Patcher::find_preset(uint8_t *kimg, size_t len) {
    const uint8_t *found = mem_find(kimg, len, KP_MAGIC, strlen(KP_MAGIC));
    return found ? reinterpret_cast<Preset *>(const_cast<uint8_t *>(found)) : nullptr;
}

const Preset *Patcher::find_preset(const uint8_t *kimg, size_t len) const {
    const uint8_t *found = mem_find(kimg, len, KP_MAGIC, strlen(KP_MAGIC));
    return found ? reinterpret_cast<const Preset *>(found) : nullptr;
}

// Parse patch info

Result<PatchedKernelInfo> Patcher::parse_patch_info(const uint8_t *kimg, size_t len) {
    PatchedKernelInfo info;

    // Parse kernel image
    auto img_result = Image::from_buffer(Buffer(kimg, len));
    if (!img_result) {
        return Result<PatchedKernelInfo>::Err(img_result.error());
    }
    info.kinfo = img_result.unwrap().info();

    // Find linux banner
    const char prefix[] = "Linux version ";
    size_t prefix_len = strlen(prefix);

    const uint8_t *banner = kimg;
    const uint8_t *end = kimg + len;

    while (banner < end - prefix_len) {
        banner = mem_find(banner + 1, end - banner - 1,
                          reinterpret_cast<const uint8_t *>(prefix), prefix_len);
        if (!banner) break;

        if (std::isdigit(banner[prefix_len]) && banner[prefix_len + 1] == '.') {
            // Find end of banner (newline or null)
            const uint8_t *banner_end = banner;
            while (banner_end < end && *banner_end != '\n' && *banner_end != '\0') {
                ++banner_end;
            }
            info.banner = std::string(reinterpret_cast<const char *>(banner),
                                      banner_end - banner);
            break;
        }
    }

    if (info.banner.empty()) {
        return Result<PatchedKernelInfo>::Err("Linux banner not found");
    }

    // Check if patched
    info.preset = const_cast<Preset *>(find_preset(kimg, len));

    if (!info.preset) {
        info.ori_kimg_len = static_cast<int32_t>(len);
        return Result<PatchedKernelInfo>::Ok(std::move(info));
    }

    // Parse patched image
    int32_t saved_len = static_cast<int32_t>(info.preset->setup.kimg_size);
    info.ori_kimg_len = saved_len;

    // Parse extras
    int64_t extra_offset = static_cast<int64_t>(
        reinterpret_cast<const uint8_t *>(info.preset) - kimg +
        info.preset->setup.kpimg_size);

    if (extra_offset < static_cast<int64_t>(len)) {
        int64_t extra_size = info.preset->setup.extra_size;
        const uint8_t *item_pos = kimg + extra_offset;
        const uint8_t *extra_end = kimg + extra_offset + extra_size;

        while (item_pos < extra_end) {
            auto *item = reinterpret_cast<PatchExtraItem *>(
                const_cast<uint8_t *>(item_pos));

            if (std::memcmp(item->magic, EXTRA_HDR_MAGIC, 3) != 0) break;
            if (item->type == EXTRA_TYPE_NONE) break;

            info.embed_items.push_back(item);
            item_pos += sizeof(PatchExtraItem) + item->args_size + item->con_size;
        }
    }

    return Result<PatchedKernelInfo>::Ok(std::move(info));
}

// Get patch info

Result<PatchedKernelInfo> Patcher::get_patch_info(const std::filesystem::path &kimg_path) {
    auto kf_result = KernelFile::from_file(kimg_path);
    if (!kf_result) {
        return Result<PatchedKernelInfo>::Err(kf_result.error());
    }

    auto &kf = kf_result.unwrap();
    return parse_patch_info(kf.kimg(), kf.kimg_len());
}

// Print preset info

void print_preset_info(const Preset *preset) {
    const auto &header = preset->header;
    const auto &setup = preset->setup;

    uint32_t ver_num = header.kp_version.to_int();

    std::fprintf(stdout, "%s\n", INFO_KPIMG_SESSION);
    std::fprintf(stdout, "version=0x%x\n", ver_num);
    std::fprintf(stdout, "compile_time=%s\n", header.compile_time);
    std::fprintf(stdout, "config=%s,%s\n",
                 header.is_android() ? "android" : "linux",
                 header.is_debug() ? "debug" : "release");
    std::fprintf(stdout, "superkey=%s\n", setup.superkey);

    if (ver_num > 0xa04) {
        std::fprintf(stdout, "root_superkey=%s\n",
                     log::hex_string(setup.root_superkey, ROOT_SUPER_KEY_HASH_LEN).c_str());
    }

    std::fprintf(stdout, "%s\n", INFO_ADDITIONAL_SESSION);
    const char *pos = setup.additional;
    const char *end = setup.additional + ADDITIONAL_LEN;

    while (pos < end) {
        int len = static_cast<uint8_t>(*pos);
        if (!len) break;
        pos++;
        std::fprintf(stdout, "%.*s\n", len, pos);
        pos += len;
    }
}

// Print kpimg info

Result<void> Patcher::print_kpimg_info(const std::filesystem::path &kpimg_path) {
    auto buf_result = Buffer::from_file(kpimg_path);
    if (!buf_result) {
        return Result<void>::Err(buf_result.error());
    }

    auto &buf = buf_result.unwrap();
    auto *preset = reinterpret_cast<Preset *>(buf.data());

    if (find_preset(buf.data(), buf.size()) != preset) {
        return Result<void>::Err("Invalid kpimg file");
    }

    print_preset_info(preset);
    return Result<void>::Ok();
}

// Print patch info

Result<void> Patcher::print_patch_info(const std::filesystem::path &kimg_path) {
    auto info_result = get_patch_info(kimg_path);
    if (!info_result) {
        return Result<void>::Err(info_result.error());
    }

    auto &info = info_result.unwrap();

    std::fprintf(stdout, "%s\n", INFO_KERNEL_SESSION);
    std::fprintf(stdout, "banner=%s\n", info.banner.c_str());
    std::fprintf(stdout, "patched=%s\n", info.preset ? "true" : "false");

    if (info.preset) {
        print_preset_info(info.preset);

        std::fprintf(stdout, "%s\n", INFO_EXTRA_SESSION);
        std::fprintf(stdout, "num=%zu\n", info.embed_items.size());

        for (size_t i = 0; i < info.embed_items.size(); ++i) {
            auto *item = info.embed_items[i];

            std::fprintf(stdout, "[extra %zu]\n", i);
            std::fprintf(stdout, "index=%zu\n", i);
            std::fprintf(stdout, "type=%s\n", extra_type_str(item->type));
            std::fprintf(stdout, "name=%s\n", item->name);
            std::fprintf(stdout, "event=%s\n", item->event);
            std::fprintf(stdout, "priority=%d\n", item->priority);
            std::fprintf(stdout, "args_size=0x%x\n", item->args_size);

            const char *args = item->args_size > 0
                ? reinterpret_cast<const char *>(item) + sizeof(*item)
                : "";
            std::fprintf(stdout, "args=%s\n", args);
            std::fprintf(stdout, "con_size=0x%x\n", item->con_size);

            // For KPM modules, print additional info
            if (item->type == EXTRA_TYPE_KPM) {
                const uint8_t *kpm_data = reinterpret_cast<const uint8_t *>(item) +
                                          sizeof(*item) + item->args_size;
                auto mod_result = kpm::Module::from_buffer(
                    Buffer(kpm_data, item->con_size));
                if (mod_result) {
                    const auto &mod_info = mod_result.unwrap().info();
                    std::fprintf(stdout, "version=%s\n", mod_info.version.c_str());
                    std::fprintf(stdout, "license=%s\n", mod_info.license.c_str());
                    std::fprintf(stdout, "author=%s\n", mod_info.author.c_str());
                    std::fprintf(stdout, "description=%s\n", mod_info.description.c_str());
                }
            }
        }
    }

    return Result<void>::Ok();
}

// Unpatch

Result<void> Patcher::unpatch(
    const std::filesystem::path &kimg_path,
    const std::filesystem::path &out_path) {

    auto kf_result = KernelFile::from_file(kimg_path);
    if (!kf_result) {
        return Result<void>::Err(kf_result.error());
    }

    auto &kf = kf_result.unwrap();
    auto *preset = find_preset(kf.kimg(), kf.kimg_len());

    if (!preset) {
        return Result<void>::Err("Not a patched kernel image");
    }

    // Restore original header
    std::memcpy(kf.kimg(), preset->setup.header_backup, HDR_BACKUP_SIZE);

    // Calculate original size
    size_t orig_size = preset->setup.kimg_size;
    if (orig_size == 0) {
        orig_size = reinterpret_cast<const uint8_t *>(preset) - kf.kimg();
    }

    kf.set_kimg_len(orig_size);

    kp_log_info("Unpatched image size: 0x%zx\n", orig_size);
    return kf.to_file(out_path);
}

// Reset key

Result<void> Patcher::reset_key(
    const std::filesystem::path &kimg_path,
    const std::filesystem::path &out_path,
    const std::string &new_key) {

    if (new_key.empty()) {
        return Result<void>::Err("Empty superkey");
    }
    if (new_key.size() >= SUPER_KEY_LEN) {
        return Result<void>::Err("Superkey too long");
    }

    auto kf_result = KernelFile::from_file(kimg_path);
    if (!kf_result) {
        return Result<void>::Err(kf_result.error());
    }

    auto &kf = kf_result.unwrap();
    auto *preset = find_preset(kf.kimg(), kf.kimg_len());

    if (!preset) {
        return Result<void>::Err("Not a patched kernel image");
    }

    std::string old_key(reinterpret_cast<const char *>(preset->setup.superkey));

    std::memset(preset->setup.superkey, 0, SUPER_KEY_LEN);
    std::memcpy(preset->setup.superkey, new_key.c_str(), new_key.size());

    kp_log_info("Reset superkey: %s -> %s\n", old_key.c_str(), new_key.c_str());

    return kf.to_file(out_path);
}

// Symbol helper: Try to find symbol with suffix (like rest_init.xxx)

static std::optional<int32_t> try_find_suffixed_symbol(Kallsyms &ksym, std::string_view name) {
    std::optional<int32_t> result;
    std::string prefix(name);

    ksym.for_each_symbol([&](const Symbol &sym) -> bool {
        // Check if symbol starts with prefix and has suffix like .xxx or $xxx
        if (sym.name.size() > prefix.size() &&
            sym.name.compare(0, prefix.size(), prefix) == 0) {
            char separator = sym.name[prefix.size()];
            if ((separator == '.' || separator == '$') &&
                sym.name.find(".cfi_jt") == std::string::npos) {
                kp_log_info("%s -> %s: type: %c, offset: 0x%08x\n",
                            prefix.c_str(), sym.name.c_str(), sym.type, sym.offset);
                result = sym.offset;
                return true; // Stop iteration
            }
        }
        return false; // Continue iteration
    });

    return result;
}

// Helper: Get symbol offset or return 0 if not found
static int32_t get_symbol_offset_zero(Kallsyms &ksym, std::string_view name) {
    auto offset = ksym.get_offset(name);
    return offset.value_or(0);
}

// Helper: Get symbol offset or exit on failure
static int32_t get_symbol_offset_exit(Kallsyms &ksym, std::string_view name, std::string &error) {
    auto offset = ksym.get_offset(name);
    if (!offset) {
        error = "no symbol " + std::string(name);
        return -1;
    }
    return *offset;
}

// Helper: Try to get symbol offset, fallback to suffixed search
static int32_t try_get_symbol_offset_zero(Kallsyms &ksym, std::string_view name) {
    auto offset = ksym.get_offset(name);
    if (offset && *offset > 0) return *offset;
    auto suffixed = try_find_suffixed_symbol(ksym, name);
    return suffixed.value_or(0);
}

// Select map area (using tcp_init_sock)

static void select_map_area(Kallsyms &ksym, int32_t &map_start, int32_t &max_size, std::string &error) {
    auto tcp_offset = ksym.get_offset("tcp_init_sock");
    if (!tcp_offset) {
        error = "no symbol tcp_init_sock";
        return;
    }
    map_start = align_up(*tcp_offset, 16);
    max_size = 0x800;
}

// Fill map symbol offsets (memblock functions)

static bool fillin_map_symbol(Kallsyms &ksym, MapSymbol &symbol, std::string &error) {
    // Required symbols
    auto memblock_reserve = ksym.get_offset("memblock_reserve");
    if (!memblock_reserve) {
        error = "no symbol memblock_reserve";
        return false;
    }
    symbol.memblock_reserve_relo = static_cast<uint64_t>(*memblock_reserve);

    auto memblock_free = ksym.get_offset("memblock_free");
    if (!memblock_free) {
        error = "no symbol memblock_free";
        return false;
    }
    symbol.memblock_free_relo = static_cast<uint64_t>(*memblock_free);

    // Optional symbols
    symbol.memblock_mark_nomap_relo =
        static_cast<uint64_t>(get_symbol_offset_zero(ksym, "memblock_mark_nomap"));

    int32_t phys_alloc = get_symbol_offset_zero(ksym, "memblock_phys_alloc_try_nid");
    int32_t virt_alloc = get_symbol_offset_zero(ksym, "memblock_virt_alloc_try_nid");

    if (!phys_alloc && !virt_alloc) {
        // Try fallback to memblock_alloc_try_nid
        int32_t alloc_try_nid = get_symbol_offset_zero(ksym, "memblock_alloc_try_nid");
        if (alloc_try_nid) {
            phys_alloc = alloc_try_nid;
            virt_alloc = alloc_try_nid;
        }
    }

    if (!phys_alloc && !virt_alloc) {
        error = "no symbol memblock_alloc";
        return false;
    }

    symbol.memblock_phys_alloc_relo = static_cast<uint64_t>(phys_alloc);
    symbol.memblock_virt_alloc_relo = static_cast<uint64_t>(virt_alloc);

    return true;
}

// Fill patch config symbols

static bool fillin_patch_config(Kallsyms &ksym, PatchConfig &config, bool is_android, std::string &error) {
    // Optional: panic
    config.panic = static_cast<uint64_t>(get_symbol_offset_zero(ksym, "panic"));

    // Required: rest_init or cgroup_init
    config.rest_init = static_cast<uint64_t>(try_get_symbol_offset_zero(ksym, "rest_init"));
    if (!config.rest_init) {
        config.cgroup_init = static_cast<uint64_t>(try_get_symbol_offset_zero(ksym, "cgroup_init"));
    }
    if (!config.rest_init && !config.cgroup_init) {
        error = "no symbol rest_init";
        return false;
    }

    // Optional: kernel_init
    config.kernel_init = static_cast<uint64_t>(try_get_symbol_offset_zero(ksym, "kernel_init"));

    // CFI related symbols (optional)
    config.report_cfi_failure = static_cast<uint64_t>(get_symbol_offset_zero(ksym, "report_cfi_failure"));
    config.__cfi_slowpath_diag = static_cast<uint64_t>(get_symbol_offset_zero(ksym, "__cfi_slowpath_diag"));
    config.__cfi_slowpath = static_cast<uint64_t>(get_symbol_offset_zero(ksym, "__cfi_slowpath"));

    // Required: copy_process or cgroup_post_fork
    config.copy_process = static_cast<uint64_t>(try_get_symbol_offset_zero(ksym, "copy_process"));
    if (!config.copy_process) {
        config.cgroup_post_fork = static_cast<uint64_t>(get_symbol_offset_zero(ksym, "cgroup_post_fork"));
    }
    if (!config.copy_process && !config.cgroup_post_fork) {
        error = "no symbol copy_process";
        return false;
    }

    // SELinux related (required for Android)
    config.avc_denied = static_cast<uint64_t>(try_get_symbol_offset_zero(ksym, "avc_denied"));
    if (!config.avc_denied && is_android) {
        error = "no symbol avc_denied";
        return false;
    }

    config.slow_avc_audit = static_cast<uint64_t>(try_get_symbol_offset_zero(ksym, "slow_avc_audit"));

    // Optional: input_handle_event
    config.input_handle_event = static_cast<uint64_t>(get_symbol_offset_zero(ksym, "input_handle_event"));

    return true;
}

// Dump kallsyms

Result<void> Patcher::dump_kallsyms(const std::filesystem::path &kimg_path) {
    log::enabled = true;

    auto kf_result = KernelFile::from_file(kimg_path);
    if (!kf_result) {
        return Result<void>::Err(kf_result.error());
    }

    auto &kf = kf_result.unwrap();

    Kallsyms ksym;
    auto parse_result = ksym.parse(kf.kimg(), kf.kimg_len());
    if (!parse_result) {
        return Result<void>::Err(parse_result.error());
    }

    ksym.dump_all();

    log::enabled = false;
    return Result<void>::Ok();
}

// Patch

Result<void> Patcher::patch(
    const std::filesystem::path &kimg_path,
    const std::filesystem::path &kpimg_path,
    const std::filesystem::path &out_path,
    const std::string &superkey,
    bool root_key,
    const std::vector<std::string> &additional,
    std::vector<ExtraConfig> &extras) {

    log::enabled = true;

    // Validate inputs
    if (superkey.empty()) {
        return Result<void>::Err("Empty superkey");
    }
    if (superkey.size() >= SUPER_KEY_LEN) {
        return Result<void>::Err("Superkey too long");
    }

    // Load kernel image
    auto kf_result = KernelFile::from_file(kimg_path);
    if (!kf_result) {
        return Result<void>::Err("Failed to read kernel: " + kf_result.error());
    }
    auto &kf = kf_result.unwrap();

    // Parse kernel info
    auto info_result = parse_patch_info(kf.kimg(), kf.kimg_len());
    if (!info_result) {
        return Result<void>::Err("Failed to parse kernel: " + info_result.error());
    }
    auto &pinfo = info_result.unwrap();

    // Parse kallsyms
    Buffer ksym_buf(kf.kimg(), pinfo.ori_kimg_len);
    Kallsyms ksym;
    auto ksym_result = ksym.parse(ksym_buf.data(), ksym_buf.size());
    if (!ksym_result) {
        return Result<void>::Err("Failed to parse kallsyms: " + ksym_result.error());
    }

    // Load kpimg
    auto kpimg_result = Buffer::from_file(kpimg_path);
    if (!kpimg_result) {
        return Result<void>::Err("Failed to read kpimg: " + kpimg_result.error());
    }
    // Align kpimg to 16 bytes
    kpimg_result.unwrap().pad_to_alignment(16);
    auto &kpimg = kpimg_result.unwrap();

    // Calculate sizes
    size_t ori_kimg_len = pinfo.ori_kimg_len;
    size_t align_kimg_len = align_up(ori_kimg_len, SZ_4K);
    size_t kpimg_len = kpimg.size();

    // Calculate extra size
    size_t extra_size = sizeof(PatchExtraItem);  // Terminator
    for (auto &extra : extras) {
        // Load data if from path
        if (extra.is_path && !extra.path_or_name.empty()) {
            auto data_result = Buffer::from_file(extra.path_or_name);
            if (!data_result) {
                return Result<void>::Err("Failed to load extra: " + data_result.error());
            }
            data_result.unwrap().pad_to_alignment(EXTRA_ALIGN);
            extra.data = std::move(data_result).unwrap();
            extra.item.con_size = static_cast<int32_t>(extra.data.size());

            // Get name from KPM if not set
            if (extra.name.empty() && extra.type == EXTRA_TYPE_KPM) {
                auto mod_result = kpm::Module::from_buffer(
                    Buffer(extra.data.data(), extra.data.size()));
                if (mod_result) {
                    extra.name = mod_result.unwrap().info().name;
                }
            }
        }

        // Set item fields
        std::strncpy(extra.item.magic, EXTRA_HDR_MAGIC, 3);
        extra.item.type = extra.type;
        extra.item.priority = extra.priority;

        if (!extra.name.empty()) {
            std::strncpy(extra.item.name, extra.name.c_str(), EXTRA_NAME_LEN - 1);
        }
        if (!extra.event.empty()) {
            std::strncpy(extra.item.event, extra.event.c_str(), EXTRA_EVENT_LEN - 1);
        }
        if (!extra.args.empty()) {
            extra.item.args_size = static_cast<int32_t>(
                align_up(extra.args.size() + 1, EXTRA_ALIGN));
        }

        extra_size += sizeof(PatchExtraItem);
        extra_size += extra.item.args_size;
        extra_size += extra.item.con_size;
    }

    // Sort extras by priority (descending)
    std::sort(extras.begin(), extras.end(), [](const ExtraConfig &a, const ExtraConfig &b) {
        return a.priority > b.priority;
    });

    // Calculate output size and start offset
    size_t out_img_len = align_kimg_len + kpimg_len;
    size_t out_all_len = out_img_len + extra_size;
    size_t start_offset = align_up(static_cast<size_t>(pinfo.kinfo.kernel_size), SZ_4K);

    if (out_all_len > start_offset) {
        size_t old_start = start_offset;
        start_offset = align_up(out_all_len, SZ_4K);
        kp_log_info("patch overlap, move start from 0x%zx to 0x%zx\n", old_start, start_offset);
    }

    kp_log_info("layout kimg: 0x0,0x%zx, kpimg: 0x%zx,0x%zx, extra: 0x%zx,0x%zx, end: 0x%zx, start: 0x%zx\n",
                ori_kimg_len, align_kimg_len, kpimg_len, out_img_len, extra_size, out_all_len, start_offset);

    // Create output kernel file
    auto out_kf = KernelFile::create_new(kf, out_all_len);

    // Copy original kernel
    std::memcpy(out_kf.kimg(), kf.kimg(), ori_kimg_len);
    std::memset(out_kf.kimg() + ori_kimg_len, 0, align_kimg_len - ori_kimg_len);

    // Copy kpimg
    std::memcpy(out_kf.kimg() + align_kimg_len, kpimg.data(), kpimg_len);

    // Get preset pointer
    auto *preset = reinterpret_cast<Preset *>(out_kf.kimg() + align_kimg_len);

    kp_log_info("kpimg version: %x\n", preset->header.kp_version.to_int());
    kp_log_info("kpimg compile time: %s\n", preset->header.compile_time);
    kp_log_info("kpimg config: %s, %s\n",
                preset->header.is_android() ? "android" : "linux",
                preset->header.is_debug() ? "debug" : "release");

    // Fill setup preset
    auto &setup = preset->setup;
    std::memset(&setup, 0, sizeof(setup));

    setup.kernel_version.major = ksym.version().major;
    setup.kernel_version.minor = ksym.version().minor;
    setup.kernel_version.patch = ksym.version().patch;
    setup.kimg_size = static_cast<int64_t>(ori_kimg_len);
    setup.kpimg_size = static_cast<int64_t>(kpimg_len);
    setup.kernel_size = pinfo.kinfo.kernel_size;
    setup.page_shift = pinfo.kinfo.page_shift;
    setup.setup_offset = static_cast<int64_t>(align_kimg_len);
    setup.start_offset = static_cast<int64_t>(start_offset);
    setup.extra_size = static_cast<int64_t>(extra_size);

    // Get required symbol offsets
    auto kallsyms_offset = ksym.get_offset("kallsyms_lookup_name");
    if (!kallsyms_offset) {
        return Result<void>::Err("Symbol not found: kallsyms_lookup_name");
    }
    setup.kallsyms_lookup_name_offset = *kallsyms_offset;

    auto printk_offset = ksym.get_offset("printk");
    if (!printk_offset) {
        printk_offset = ksym.get_offset("_printk");
    }
    if (!printk_offset) {
        return Result<void>::Err("Symbol not found: printk");
    }
    setup.printk_offset = *printk_offset;

    auto paging_offset = ksym.get_offset("paging_init");
    if (!paging_offset) {
        return Result<void>::Err("Symbol not found: paging_init");
    }
    setup.paging_init_offset = *paging_offset;

    // Select map area (using tcp_init_sock)
    std::string error;
    int32_t map_start = 0, map_max_size = 0;
    select_map_area(ksym, map_start, map_max_size, error);
    if (!error.empty()) {
        return Result<void>::Err(error);
    }
    setup.map_offset = map_start;
    setup.map_max_size = map_max_size;
    kp_log_info("map_start: 0x%x, max_size: 0x%x\n", map_start, map_max_size);

    // Fill map symbol offsets (memblock functions)
    if (!fillin_map_symbol(ksym, setup.map_symbol, error)) {
        return Result<void>::Err(error);
    }

    // Backup original header
    std::memcpy(setup.header_backup, ksym_buf.data(), HDR_BACKUP_SIZE);

    // Fill patch config symbols
    bool is_android = preset->header.is_android();
    if (!fillin_patch_config(ksym, setup.patch_config, is_android, error)) {
        return Result<void>::Err(error);
    }

    // Set kallsyms_lookup_name and printk in patch_config
    setup.patch_config.kallsyms_lookup_name = static_cast<uint64_t>(setup.kallsyms_lookup_name_offset);
    setup.patch_config.printk = static_cast<uint64_t>(setup.printk_offset);

    // Set superkey
    if (!root_key) {
        kp_log_info("superkey: %s\n", superkey.c_str());
        std::strncpy(reinterpret_cast<char *>(setup.superkey),
                     superkey.c_str(), SUPER_KEY_LEN - 1);
    } else {
        auto hash = crypto::sha256(superkey);
        size_t copy_len = std::min(hash.size(), static_cast<size_t>(ROOT_SUPER_KEY_HASH_LEN));
        std::memcpy(setup.root_superkey, hash.data(), copy_len);
        kp_log_info("root superkey hash: %s\n",
                    crypto::SHA256::to_hex(hash).c_str());
    }

    // Modify kernel entry branch
    size_t text_offset = align_kimg_len + SZ_4K;
    uint32_t new_branch = arm64::make_branch_to(
        pinfo.kinfo.branch_offset, text_offset);
    std::memcpy(out_kf.kimg() + pinfo.kinfo.branch_offset, &new_branch, 4);

    // Set additional
    char *add_pos = setup.additional;
    for (const auto &kv : additional) {
        if (kv.find('=') == std::string::npos) {
            return Result<void>::Err("Additional must be key=value format");
        }
        if (kv.size() > 127) {
            return Result<void>::Err("Additional value too long");
        }
        if (add_pos + kv.size() + 1 > setup.additional + ADDITIONAL_LEN) {
            return Result<void>::Err("No space for additional values");
        }

        *add_pos++ = static_cast<char>(kv.size());
        std::memcpy(add_pos, kv.c_str(), kv.size());
        add_pos += kv.size();

        kp_log_info("Adding additional: %s\n", kv.c_str());
    }

    // Append extras
    size_t current_offset = out_img_len;
    for (auto &extra : extras) {
        kp_log_info("embedding %s, name: %s, priority: %d, event: %s, args: %s, size: 0x%x+0x%x+0x%x\n",
                    extra_type_str(extra.type), extra.item.name,
                    extra.priority, extra.item.event, extra.args.c_str(),
                    static_cast<int>(sizeof(extra.item)), extra.item.args_size, extra.item.con_size);

        // Write item header
        std::memcpy(out_kf.kimg() + current_offset, &extra.item, sizeof(extra.item));
        current_offset += sizeof(extra.item);

        // Write args
        if (extra.item.args_size > 0) {
            std::memcpy(out_kf.kimg() + current_offset,
                        extra.args.c_str(), extra.args.size());
            current_offset += extra.item.args_size;
        }

        // Write content
        if (extra.item.con_size > 0) {
            std::memcpy(out_kf.kimg() + current_offset,
                        extra.data.data(), extra.item.con_size);
            current_offset += extra.item.con_size;
        }
    }

    // Write terminator
    PatchExtraItem terminator{};
    std::memcpy(out_kf.kimg() + current_offset, &terminator, sizeof(terminator));

    // Write output file
    auto write_result = out_kf.to_file(out_path);
    if (!write_result) {
        return Result<void>::Err("Failed to write output: " + write_result.error());
    }

    kp_log_info("patch done: %s\n", out_path.string().c_str());
    log::enabled = false;

    return Result<void>::Ok();
}

// Get kpimg version

Result<uint32_t> get_kpimg_version(const std::filesystem::path &path) {
    auto buf_result = Buffer::from_file(path);
    if (!buf_result) {
        return Result<uint32_t>::Err(buf_result.error());
    }

    auto &buf = buf_result.unwrap();
    const uint8_t *magic = mem_find(buf.data(), buf.size(), KP_MAGIC, strlen(KP_MAGIC));

    if (!magic) {
        return Result<uint32_t>::Err("Not a valid kpimg file");
    }

    auto *preset = reinterpret_cast<const Preset *>(magic);
    return Result<uint32_t>::Ok(preset->header.kp_version.to_int());
}

} // namespace kernel
} // namespace kp