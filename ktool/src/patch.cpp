/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */

#include "patch.hpp"
#include "arm64_insn.hpp"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace ktool {

constexpr size_t kPageSize = 4096;
constexpr const char* kUncompressedMagic = "UNCOMPRESSED_IMG";
constexpr size_t kUncompressedMagicLen = 16;
constexpr size_t kUncompressedHeaderLen = 20;

const uint8_t* memmem(const uint8_t* h, size_t hl, const void* n, size_t nl) {
    if (nl == 0 || hl < nl) return nullptr;
    const auto* nb = static_cast<const uint8_t*>(n);
    for (const uint8_t* p = h; p <= h + hl - nl; ++p) {
        if (std::memcmp(p, nb, nl) == 0) return p;
    }
    return nullptr;
}

std::string hexify(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string r;
    r.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        r += hex[data[i] >> 4];
        r += hex[data[i] & 0xf];
    }
    return r;
}

KernelFile KernelFile::load(const fs::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw PatchError("cannot open: " + path.string());

    KernelFile kf;
    kf.data_.resize(static_cast<size_t>(f.tellg()));
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(kf.data_.data()), kf.data_.size()))
        throw PatchError("read failed: " + path.string());

    if (kf.data_.size() >= kUncompressedHeaderLen &&
        std::memcmp(kf.data_.data(), kUncompressedMagic, kUncompressedMagicLen) == 0) {
        kf.has_prefix_ = true;
        kf.offset_ = kUncompressedHeaderLen;
    }
    return kf;
}

KernelFile KernelFile::create(const KernelFile& base, size_t size) {
    KernelFile kf;
    kf.has_prefix_ = base.has_prefix_;
    kf.offset_ = base.offset_;
    kf.data_.resize(kf.offset_ + size);

    if (kf.offset_ > 0)
        std::memcpy(kf.data_.data(), base.data_.data(), kf.offset_);
    if (kf.has_prefix_) {
        uint32_t sz = static_cast<uint32_t>(size);
        std::memcpy(kf.data_.data() + kUncompressedMagicLen, &sz, 4);
    }
    return kf;
}

void KernelFile::resize(size_t n) {
    data_.resize(offset_ + n);
    if (has_prefix_) {
        uint32_t sz = static_cast<uint32_t>(n);
        std::memcpy(data_.data() + kUncompressedMagicLen, &sz, 4);
    }
}

void KernelFile::save(const fs::path& path) const {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw PatchError("cannot create: " + path.string());
    if (!f.write(reinterpret_cast<const char*>(data_.data()), data_.size()))
        throw PatchError("write failed: " + path.string());
}

void Patcher::log(const char* fmt, ...) const {
    if (!verbose_) return;
    va_list args;
    va_start(args, fmt);
    std::vfprintf(stderr, fmt, args);
    va_end(args);
}

Preset* Patcher::find_preset(uint8_t* data, size_t size) {
    auto* p = memmem(data, size, KP_MAGIC, 6);
    return p ? reinterpret_cast<Preset*>(const_cast<uint8_t*>(p)) : nullptr;
}

const Preset* Patcher::find_preset(const uint8_t* data, size_t size) const {
    auto* p = memmem(data, size, KP_MAGIC, 6);
    return p ? reinterpret_cast<const Preset*>(p) : nullptr;
}

std::string Patcher::find_banner(const uint8_t* data, size_t size) const {
    constexpr const char* prefix = "Linux version ";
    constexpr size_t plen = 14;

    for (const uint8_t* p = data; p < data + size - plen; ++p) {
        p = memmem(p, data + size - p, prefix, plen);
        if (!p) break;
        if (std::isdigit(p[plen]) && p[plen + 1] == '.' && p[plen] != '%') {
            const uint8_t* end = p;
            while (end < data + size && *end != '\n' && *end != '\0') ++end;
            return {reinterpret_cast<const char*>(p), static_cast<size_t>(end - p)};
        }
    }
    return {};
}

std::vector<std::pair<std::string, std::string>> Patcher::parse_metadata(const SetupPreset& s) const {
    std::vector<std::pair<std::string, std::string>> r;
    const char* p = s.additional;
    const char* end = s.additional + ADDITIONAL_LEN;

    while (p < end) {
        uint8_t len = static_cast<uint8_t>(*p++);
        if (len == 0 || p + len > end) break;
        std::string entry(p, len);
        if (auto eq = entry.find('='); eq != std::string::npos)
            r.emplace_back(entry.substr(0, eq), entry.substr(eq + 1));
        p += len;
    }
    return r;
}

std::optional<uint64_t> Patcher::lookup(KallsymsFinder& k, const std::string& name) {
    if (auto s = k.find_symbol(name)) return s->address;
    return std::nullopt;
}

std::optional<int64_t> Patcher::lookup_offset(KallsymsFinder& k, const std::string& name) {
    if (auto s = k.find_symbol(name)) return k.address_to_offset(s->address);
    return std::nullopt;
}

std::optional<uint64_t> Patcher::lookup_suffixed(KallsymsFinder& k, const std::string& name) {
    if (auto v = lookup(k, name); v && *v > 0) return v;

    std::optional<uint64_t> r;
    k.for_each_symbol([&](const Symbol& s) -> bool {
        if (s.name.size() > name.size() && s.name.compare(0, name.size(), name) == 0) {
            char c = s.name[name.size()];
            if ((c == '.' || c == '$') && s.name.find(".cfi_jt") == std::string::npos) {
                r = s.address;
                return true;
            }
        }
        return false;
    });
    return r;
}

std::optional<int64_t> Patcher::lookup_suffixed_offset(KallsymsFinder& k, const std::string& name) {
    if (auto v = lookup_suffixed(k, name); v && *v > 0) return k.address_to_offset(*v);
    return std::nullopt;
}

uint64_t Patcher::require(KallsymsFinder& k, const std::string& name) {
    if (auto v = lookup(k, name)) return *v;
    throw SymbolNotFound(name);
}

int64_t Patcher::require_offset(KallsymsFinder& k, const std::string& name) {
    if (auto v = lookup_offset(k, name)) return *v;
    throw SymbolNotFound(name);
}

void Patcher::check_branch(size_t from, size_t to) {
    if (!arm64::can_branch(from, to)) throw BranchOutOfRange(from, to);
}

void Patcher::fill_map_symbols(KallsymsFinder& k, MapSymbol& m) {
    auto reserve = lookup_offset(k, "memblock_reserve");
    if (!reserve) throw SymbolNotFound("memblock_reserve");
    m.memblock_reserve_relo = *reserve;

    auto free_off = lookup_offset(k, "memblock_free");
    if (!free_off) throw SymbolNotFound("memblock_free");
    m.memblock_free_relo = *free_off;

    auto phys = lookup_offset(k, "memblock_phys_alloc_try_nid");
    auto virt = lookup_offset(k, "memblock_virt_alloc_try_nid");
    if (!phys && !virt) throw SymbolNotFound("memblock_alloc");

    // Get fallback function for whichever is missing
    auto alloc = lookup_offset(k, "memblock_alloc_try_nid");

    // Apply fallback individually to each missing symbol (matching kptools behavior)
    if (!phys) phys = alloc;
    if (!virt) virt = alloc;

    m.memblock_phys_alloc_relo = phys.value_or(0);
    m.memblock_virt_alloc_relo = virt.value_or(0);
    m.memblock_mark_nomap_relo = lookup_offset(k, "memblock_mark_nomap").value_or(0);

    log("[+] memblock_reserve: 0x%llx\n", static_cast<unsigned long long>(m.memblock_reserve_relo));
    log("[+] memblock_free: 0x%llx\n", static_cast<unsigned long long>(m.memblock_free_relo));
    log("[+] memblock_phys_alloc: 0x%llx\n", static_cast<unsigned long long>(m.memblock_phys_alloc_relo));
    log("[+] memblock_virt_alloc: 0x%llx\n", static_cast<unsigned long long>(m.memblock_virt_alloc_relo));
}

void Patcher::fill_patch_config(KallsymsFinder& k, PatchConfig& c, bool android) {
    c.panic = lookup_offset(k, "panic").value_or(0);
    c.rest_init = lookup_suffixed_offset(k, "rest_init").value_or(0);
    if (!c.rest_init) c.cgroup_init = lookup_suffixed_offset(k, "cgroup_init").value_or(0);
    if (!c.rest_init && !c.cgroup_init) throw SymbolNotFound("rest_init");

    c.kernel_init = lookup_suffixed_offset(k, "kernel_init").value_or(0);
    c.report_cfi_failure = lookup_offset(k, "report_cfi_failure").value_or(0);
    c.__cfi_slowpath_diag = lookup_offset(k, "__cfi_slowpath_diag").value_or(0);
    c.__cfi_slowpath = lookup_offset(k, "__cfi_slowpath").value_or(0);

    c.copy_process = lookup_suffixed_offset(k, "copy_process").value_or(0);
    if (!c.copy_process) c.cgroup_post_fork = lookup_offset(k, "cgroup_post_fork").value_or(0);
    if (!c.copy_process && !c.cgroup_post_fork) throw SymbolNotFound("copy_process");

    c.avc_denied = lookup_suffixed_offset(k, "avc_denied").value_or(0);
    if (!c.avc_denied && android) throw SymbolNotFound("avc_denied");
    c.slow_avc_audit = lookup_suffixed_offset(k, "slow_avc_audit").value_or(0);
    c.input_handle_event = lookup_offset(k, "input_handle_event").value_or(0);

    log("[+] rest_init: 0x%llx\n", static_cast<unsigned long long>(c.rest_init));
    log("[+] kernel_init: 0x%llx\n", static_cast<unsigned long long>(c.kernel_init));
    log("[+] copy_process: 0x%llx\n", static_cast<unsigned long long>(c.copy_process));
    log("[+] avc_denied: 0x%llx\n", static_cast<unsigned long long>(c.avc_denied));
}

void Patcher::patch(const PatchOptions& opts) {
    verbose_ = opts.verbose;

    if (opts.superkey.empty()) throw PatchError("superkey required");
    if (opts.superkey.size() >= SUPER_KEY_LEN)
        throw PatchError("superkey too long (max " + std::to_string(SUPER_KEY_LEN - 1) + ")");

    log("[*] Loading kernel: %s\n", opts.kernel.c_str());
    auto kf = KernelFile::load(opts.kernel);
    if (kf.has_prefix()) log("[*] UNCOMPRESSED_IMG detected\n");

    if (find_preset(kf.data(), kf.size()))
        throw PatchError("kernel already patched");

    auto banner = find_banner(kf.data(), kf.size());
    if (banner.empty()) throw PatchError("not a valid kernel image");
    log("[+] Banner: %s\n", banner.c_str());

    ImageParser parser;
    auto img = parser.parse(kf.data(), kf.size());
    log("[+] Format: %s, size: 0x%llx\n", ImageParser::format_name(img.format).c_str(), img.image_size);

    log("[*] Parsing kallsyms...\n");
    KallsymsFinder ksym;
    ksym.parse(kf.data(), kf.size());
    log("[+] Found %zu symbols, version %d.%d.%d\n",
        ksym.num_symbols(), ksym.version().major, ksym.version().minor, ksym.version().patch);

    log("[*] Loading kpimg: %s\n", opts.kpimg.c_str());
    auto kpimg = KernelFile::load(opts.kpimg);

    auto* kp_preset = find_preset(kpimg.data(), kpimg.size());
    if (!kp_preset || kp_preset != reinterpret_cast<Preset*>(kpimg.data()))
        throw InvalidKpimg("magic not at start");

    log("[+] kpimg %s, %s, %s\n",
        version_string(kp_preset->header.kp_version).c_str(),
        header_android(kp_preset->header) ? "android" : "linux",
        header_debug(kp_preset->header) ? "debug" : "release");

    size_t ori_len = kf.size();
    size_t aligned_len = align_up(ori_len, kPageSize);
    size_t kpimg_len = align_up(kpimg.size(), size_t{16});
    size_t extra_size = sizeof(PatchExtraItem);

    for (auto& e : const_cast<std::vector<ExtraItem>&>(opts.extras)) {
        if (!e.path.empty()) {
            auto ef = KernelFile::load(e.path);
            e.data.assign(ef.data(), ef.data() + ef.size());
        }
        e.data.resize(align_up(e.data.size(), size_t{EXTRA_ALIGN}));
        std::memcpy(e.header.magic, EXTRA_HDR_MAGIC, 3);
        e.header.type = static_cast<int32_t>(e.type);
        e.header.priority = e.priority;
        e.header.con_size = static_cast<int32_t>(e.data.size());
        if (!e.name.empty()) std::strncpy(e.header.name, e.name.c_str(), EXTRA_NAME_LEN - 1);
        if (!e.event.empty()) std::strncpy(e.header.event, e.event.c_str(), EXTRA_EVENT_LEN - 1);
        if (!e.args.empty())
            e.header.args_size = static_cast<int32_t>(align_up(e.args.size() + 1, size_t{EXTRA_ALIGN}));
        extra_size += sizeof(PatchExtraItem) + e.header.args_size + e.header.con_size;
    }

    size_t out_img_len = aligned_len + kpimg_len;
    size_t out_total = out_img_len + extra_size;
    size_t start_off = align_up(static_cast<size_t>(img.image_size), kPageSize);

    if (out_total > start_off) {
        log("[!] Overlap, adjusting start 0x%zx -> 0x%zx\n", start_off, align_up(out_total, kPageSize));
        start_off = align_up(out_total, kPageSize);
    }

    log("[*] Layout: kernel=0x%zx, kpimg@0x%zx, start@0x%zx\n", ori_len, aligned_len, start_off);

    auto out = KernelFile::create(kf, out_total);
    std::memcpy(out.data(), kf.data(), ori_len);
    std::memset(out.data() + ori_len, 0, aligned_len - ori_len);
    std::memcpy(out.data() + aligned_len, kpimg.data(), kpimg.size());

    auto* preset = reinterpret_cast<Preset*>(out.data() + aligned_len);
    auto& setup = preset->setup;
    std::memset(&setup, 0, sizeof(setup));

    setup.kernel_version.major = static_cast<uint8_t>(ksym.version().major);
    setup.kernel_version.minor = static_cast<uint8_t>(ksym.version().minor);
    setup.kernel_version.patch = static_cast<uint8_t>(ksym.version().patch);
    setup.kimg_size = static_cast<int64_t>(ori_len);
    setup.kpimg_size = static_cast<int64_t>(kpimg_len);
    setup.kernel_size = static_cast<int64_t>(img.image_size);
    setup.page_shift = 12;
    setup.setup_offset = static_cast<int64_t>(aligned_len);
    setup.start_offset = static_cast<int64_t>(start_off);
    setup.extra_size = static_cast<int64_t>(extra_size);

    setup.kallsyms_lookup_name_offset = require_offset(ksym, "kallsyms_lookup_name");
    auto printk_off = lookup_offset(ksym, "printk");
    if (!printk_off) printk_off = lookup_offset(ksym, "_printk");
    if (!printk_off) throw SymbolNotFound("printk");
    setup.printk_offset = *printk_off;

    // Get paging_init offset and follow branch if present (relo_branch_func logic)
    int64_t paging_init_off = require_offset(ksym, "paging_init");
    uint32_t paging_insn = *reinterpret_cast<const uint32_t*>(kf.data() + paging_init_off);
    if (arm64::is_branch(paging_insn)) {
        int64_t branch_target = paging_init_off + arm64::branch_offset(paging_insn);
        log("[+] paging_init branch relocated: 0x%llx -> 0x%llx\n",
            static_cast<unsigned long long>(paging_init_off),
            static_cast<unsigned long long>(branch_target));
        paging_init_off = branch_target;
    }
    setup.paging_init_offset = paging_init_off;

    auto tcp_off = lookup_offset(ksym, "tcp_init_sock");
    if (!tcp_off) throw SymbolNotFound("tcp_init_sock");
    setup.map_offset = static_cast<int64_t>(align_up(static_cast<uint64_t>(*tcp_off), uint64_t{16}));
    setup.map_max_size = 0x800;

    log("[+] kallsyms_lookup_name: 0x%llx\n", static_cast<unsigned long long>(setup.kallsyms_lookup_name_offset));
    log("[+] paging_init: 0x%llx\n", static_cast<unsigned long long>(setup.paging_init_offset));
    log("[+] printk: 0x%llx\n", static_cast<unsigned long long>(setup.printk_offset));
    log("[+] map_offset: 0x%llx\n", static_cast<unsigned long long>(setup.map_offset));

    fill_map_symbols(ksym, setup.map_symbol);
    std::memcpy(setup.header_backup, kf.data(), HDR_BACKUP_SIZE);

    setup.patch_config.kallsyms_lookup_name = static_cast<uint64_t>(setup.kallsyms_lookup_name_offset);
    setup.patch_config.printk = static_cast<uint64_t>(setup.printk_offset);
    fill_patch_config(ksym, setup.patch_config, header_android(preset->header));

    if (!opts.root_key) {
        std::strncpy(reinterpret_cast<char*>(setup.superkey), opts.superkey.c_str(), SUPER_KEY_LEN - 1);
    } else {
        throw PatchError("root superkey not implemented");
    }

    size_t branch_off = 0;
    uint32_t insn0 = *reinterpret_cast<const uint32_t*>(kf.data());
    if ((insn0 & 0xffff) == 0x5a4d) branch_off = 4;  // EFI stub

    size_t text_off = aligned_len + kPageSize;
    check_branch(branch_off, text_off);
    uint32_t branch = arm64::encode_branch(branch_off, text_off);
    std::memcpy(out.data() + branch_off, &branch, 4);
    log("[+] Entry branch: 0x%zx -> 0x%zx (0x%08x)\n", branch_off, text_off, branch);

    char* meta = setup.additional;
    for (const auto& kv : opts.metadata) {
        if (kv.find('=') == std::string::npos) throw PatchError("metadata must be key=value");
        if (kv.size() > 127) throw PatchError("metadata too long");
        if (meta + kv.size() + 1 > setup.additional + ADDITIONAL_LEN)
            throw PatchError("no space for metadata");
        *meta++ = static_cast<char>(kv.size());
        std::memcpy(meta, kv.c_str(), kv.size());
        meta += kv.size();
    }

    size_t pos = out_img_len;
    for (const auto& e : opts.extras) {
        std::memcpy(out.data() + pos, &e.header, sizeof(e.header));
        pos += sizeof(e.header);
        if (e.header.args_size > 0) {
            std::memcpy(out.data() + pos, e.args.c_str(), e.args.size());
            pos += e.header.args_size;
        }
        if (e.header.con_size > 0) {
            std::memcpy(out.data() + pos, e.data.data(), e.header.con_size);
            pos += e.header.con_size;
        }
        log("[+] Extra: %s (%s)\n", e.header.name, extra_type_name(e.type));
    }

    PatchExtraItem term{};
    std::memcpy(out.data() + pos, &term, sizeof(term));

    log("[*] Writing: %s\n", opts.output.c_str());
    out.save(opts.output);
    std::fprintf(stderr, "[+] Patch complete: %s\n", opts.output.c_str());
}

void Patcher::unpatch(const fs::path& input, const fs::path& output) {
    auto kf = KernelFile::load(input);
    auto* p = find_preset(kf.data(), kf.size());
    if (!p) throw PatchError("not patched");

    std::memcpy(kf.data(), p->setup.header_backup, HDR_BACKUP_SIZE);
    size_t orig = static_cast<size_t>(p->setup.kimg_size);
    if (orig == 0) orig = reinterpret_cast<const uint8_t*>(p) - kf.data();

    kf.resize(orig);
    kf.save(output);
    std::fprintf(stderr, "[+] Unpatch complete: %s (0x%zx)\n", output.c_str(), orig);
}

PatchInfo Patcher::info(const fs::path& path) {
    auto kf = KernelFile::load(path);
    PatchInfo i;
    i.banner = find_banner(kf.data(), kf.size());

    const auto* p = find_preset(kf.data(), kf.size());
    i.patched = (p != nullptr);
    if (!p) {
        i.original_size = kf.size();
        return i;
    }

    i.kp_version = version_string(p->header.kp_version);
    i.compile_time = std::string(p->header.compile_time);
    i.android = header_android(p->header);
    i.debug = header_debug(p->header);
    i.version.major = p->setup.kernel_version.major;
    i.version.minor = p->setup.kernel_version.minor;
    i.version.patch = p->setup.kernel_version.patch;
    i.original_size = static_cast<size_t>(p->setup.kimg_size);
    i.superkey = std::string(reinterpret_cast<const char*>(p->setup.superkey));
    i.metadata = parse_metadata(p->setup);

    const uint8_t* ex = reinterpret_cast<const uint8_t*>(p) + p->setup.kpimg_size;
    const uint8_t* end = ex + p->setup.extra_size;
    while (ex < end) {
        const auto* item = reinterpret_cast<const PatchExtraItem*>(ex);
        if (!extra_valid(*item) || extra_end(*item)) break;
        i.extras.push_back(*item);
        ex += sizeof(PatchExtraItem) + item->args_size + item->con_size;
    }
    return i;
}

void Patcher::reset_key(const fs::path& input, const fs::path& output, const std::string& key) {
    if (key.empty()) throw PatchError("key cannot be empty");
    if (key.size() >= SUPER_KEY_LEN) throw PatchError("key too long");

    auto kf = KernelFile::load(input);
    auto* p = find_preset(kf.data(), kf.size());
    if (!p) throw PatchError("not patched");

    std::string old(reinterpret_cast<const char*>(p->setup.superkey));
    std::memset(p->setup.superkey, 0, SUPER_KEY_LEN);
    std::memcpy(p->setup.superkey, key.c_str(), key.size());

    kf.save(output);
    std::fprintf(stderr, "[+] Key reset: %s -> %s\n", old.c_str(), key.c_str());
}

std::string Patcher::kpimg_version(const fs::path& path) {
    auto kf = KernelFile::load(path);
    auto* m = memmem(kf.data(), kf.size(), KP_MAGIC, 6);
    if (!m) throw InvalidKpimg("magic not found");
    return version_string(reinterpret_cast<const Preset*>(m)->header.kp_version);
}

void Patcher::kpimg_info(const fs::path& path) {
    auto kf = KernelFile::load(path);
    auto* m = memmem(kf.data(), kf.size(), KP_MAGIC, 6);
    if (!m) throw InvalidKpimg("magic not found");

    const auto* p = reinterpret_cast<const Preset*>(m);
    std::printf("[kpimg]\n");
    std::printf("version=%s\n", version_string(p->header.kp_version).c_str());
    std::printf("compile_time=%s\n", p->header.compile_time);
    std::printf("config=%s,%s\n",
                header_android(p->header) ? "android" : "linux",
                header_debug(p->header) ? "debug" : "release");
}

} // namespace ktool