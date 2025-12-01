/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */

#include "kallsyms.hpp"
#include "ikconfig.hpp"
#include "image.hpp"
#include "patch.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <filesystem>

namespace fs = std::filesystem;

namespace ktool {

constexpr int kVersionMajor = KTOOL_VERSION_MAJOR;
constexpr int kVersionMinor = KTOOL_VERSION_MINOR;
constexpr int kVersionPatch = KTOOL_VERSION_PATCH;

std::string version_str() {
    return std::to_string(kVersionMajor) + "." + std::to_string(kVersionMinor) + "." + std::to_string(kVersionPatch);
}

enum class Cmd { None, Help, Version, Patch, Unpatch, ResetKey, Info, Dump, Config, Image };

struct Args {
    Cmd cmd = Cmd::None;
    fs::path kernel;
    fs::path kpimg;
    fs::path output;
    std::string superkey;
    bool root_key = false;
    std::vector<std::string> metadata;
    std::vector<ExtraItem> extras;
    bool verbose = false;
};

void usage(const char* prog) {
    std::fprintf(stderr,
        "ktool - KernelPatch Tool v%s\n\n"
        "Usage: %s <command> [options]\n\n"
        "Commands:\n"
        "  patch      Patch kernel image\n"
        "  unpatch    Remove patch\n"
        "  resetkey   Reset superkey\n"
        "  info       Show patch info\n"
        "  dump       Dump kallsyms\n"
        "  config     Extract IKCONFIG\n"
        "  image      Analyze image format\n"
        "  help       Show help\n"
        "  version    Show version\n\n"
        "Options:\n"
        "  -i, --image <path>       Kernel image\n"
        "  -k, --kpimg <path>       KernelPatch image\n"
        "  -o, --output <path>      Output path\n"
        "  -s, --superkey <key>     Superkey (stored directly)\n"
        "  -S, --root-superkey      Store superkey as SHA256 hash\n"
        "  -a, --addition <k=v>     Add metadata (can repeat)\n"
        "  -v, --verbose            Verbose output\n\n"
        "Extra Options (for embedding KPMs, scripts, etc.):\n"
        "  -M, --extra <path>       Embed extra item from file\n"
        "  -T, --extra-type <type>  Type: kpm, shell, exec, raw, android_rc\n"
        "  -N, --extra-name <name>  Extra item name\n"
        "  -V, --extra-event <ev>   Trigger event (e.g. pre-kernel-init)\n"
        "  -A, --extra-args <args>  Arguments string\n"
        "  -P, --extra-priority <n> Priority (higher = earlier, default 0)\n\n"
        "Examples:\n"
        "  %s patch -i kernel -k kpimg -o patched -s mykey\n"
        "  %s patch -i kernel -k kpimg -o patched -s mykey \\\n"
        "       -M hello.kpm -T kpm -N hello -V pre-kernel-init\n"
        "  %s info -i patched\n"
        "  %s unpatch -i patched -o original\n\n",
        version_str().c_str(), prog, prog, prog, prog, prog);
}

Cmd parse_cmd(std::string_view s) {
    if (s == "patch") return Cmd::Patch;
    if (s == "unpatch") return Cmd::Unpatch;
    if (s == "resetkey" || s == "reset-key") return Cmd::ResetKey;
    if (s == "info") return Cmd::Info;
    if (s == "dump") return Cmd::Dump;
    if (s == "config") return Cmd::Config;
    if (s == "image") return Cmd::Image;
    if (s == "help" || s == "-h" || s == "--help") return Cmd::Help;
    if (s == "version" || s == "-V" || s == "--version") return Cmd::Version;
    return Cmd::None;
}

std::optional<Args> parse_args(int argc, char** argv) {
    if (argc < 2) return std::nullopt;

    Args a;
    a.cmd = parse_cmd(argv[1]);

    ExtraItem* current_extra = nullptr;

    for (int i = 2; i < argc; ++i) {
        std::string_view arg = argv[i];

        if ((arg == "-i" || arg == "--image") && ++i < argc) {
            a.kernel = argv[i];
        } else if ((arg == "-k" || arg == "--kpimg") && ++i < argc) {
            a.kpimg = argv[i];
        } else if ((arg == "-o" || arg == "--output") && ++i < argc) {
            a.output = argv[i];
        } else if ((arg == "-s" || arg == "--superkey") && ++i < argc) {
            a.superkey = argv[i];
        } else if (arg == "-S" || arg == "--root-superkey") {
            a.root_key = true;
        } else if ((arg == "-a" || arg == "--addition") && ++i < argc) {
            a.metadata.push_back(argv[i]);
        } else if (arg == "-v" || arg == "--verbose") {
            a.verbose = true;
        } else if (arg == "-h" || arg == "--help") {
            a.cmd = Cmd::Help;
        }
        // Extra options
        else if ((arg == "-M" || arg == "--extra") && ++i < argc) {
            a.extras.emplace_back();
            current_extra = &a.extras.back();
            current_extra->path = argv[i];
            current_extra->type = EXTRA_TYPE_KPM;  // Default type
            current_extra->event = EXTRA_EVENT_PRE_KERNEL_INIT;  // Default event
        } else if ((arg == "-T" || arg == "--extra-type") && ++i < argc) {
            if (current_extra) {
                current_extra->type = extra_type_from_name(argv[i]);
                if (current_extra->type == EXTRA_TYPE_NONE) {
                    std::fprintf(stderr, "Invalid extra type: %s\n", argv[i]);
                    std::fprintf(stderr, "Valid types: kpm, shell, exec, raw, android_rc\n");
                    return std::nullopt;
                }
            } else {
                std::fprintf(stderr, "-T must follow -M\n");
                return std::nullopt;
            }
        } else if ((arg == "-N" || arg == "--extra-name") && ++i < argc) {
            if (current_extra) {
                current_extra->name = argv[i];
            } else {
                std::fprintf(stderr, "-N must follow -M\n");
                return std::nullopt;
            }
        } else if ((arg == "-V" || arg == "--extra-event") && ++i < argc) {
            if (current_extra) {
                current_extra->event = argv[i];
            } else {
                std::fprintf(stderr, "-V must follow -M\n");
                return std::nullopt;
            }
        } else if ((arg == "-A" || arg == "--extra-args") && ++i < argc) {
            if (current_extra) {
                current_extra->args = argv[i];
            } else {
                std::fprintf(stderr, "-A must follow -M\n");
                return std::nullopt;
            }
        } else if ((arg == "-P" || arg == "--extra-priority") && ++i < argc) {
            if (current_extra) {
                current_extra->priority = std::atoi(argv[i]);
            } else {
                std::fprintf(stderr, "-P must follow -M\n");
                return std::nullopt;
            }
        } else {
            std::fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return std::nullopt;
        }
    }
    return a;
}

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open: " + path.string());
    std::vector<uint8_t> data(f.tellg());
    f.seekg(0);
    if (!f.read(reinterpret_cast<char*>(data.data()), data.size()))
        throw std::runtime_error("read failed: " + path.string());
    return data;
}

int cmd_patch(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }
    if (a.kpimg.empty()) { std::fprintf(stderr, "Error: -k required\n"); return 1; }
    if (a.output.empty()) { std::fprintf(stderr, "Error: -o required\n"); return 1; }
    if (a.superkey.empty()) { std::fprintf(stderr, "Error: -s required\n"); return 1; }

    try {
        PatchOptions opts;
        opts.kernel = a.kernel;
        opts.kpimg = a.kpimg;
        opts.output = a.output;
        opts.superkey = a.superkey;
        opts.root_key = a.root_key;
        opts.metadata = a.metadata;
        opts.extras = a.extras;
        opts.verbose = a.verbose;

        Patcher().patch(opts);
        return 0;
    } catch (const SymbolNotFound& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    } catch (const BranchOutOfRange& e) {
        std::fprintf(stderr, "Error: %s (0x%zx -> 0x%zx)\n", e.what(), e.from(), e.to());
        return 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int cmd_unpatch(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }
    if (a.output.empty()) { std::fprintf(stderr, "Error: -o required\n"); return 1; }

    try {
        Patcher().unpatch(a.kernel, a.output);
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int cmd_reset_key(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }
    if (a.output.empty()) { std::fprintf(stderr, "Error: -o required\n"); return 1; }
    if (a.superkey.empty()) { std::fprintf(stderr, "Error: -s required\n"); return 1; }

    try {
        Patcher().reset_key(a.kernel, a.output, a.superkey);
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int cmd_info(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }

    try {
        auto i = Patcher().info(a.kernel);

        std::printf("[kernel]\nbanner=%s\npatched=%s\n",
                    i.banner.c_str(), i.patched ? "true" : "false");

        if (i.patched) {
            std::printf("\n[kpimg]\nversion=%s\ncompile_time=%s\nconfig=%s,%s\nsuperkey=%s\n",
                        i.kp_version.c_str(), i.compile_time.c_str(),
                        i.android ? "android" : "linux",
                        i.debug ? "debug" : "release",
                        i.superkey.c_str());

            if (!i.metadata.empty()) {
                std::printf("\n[metadata]\n");
                for (const auto& [k, v] : i.metadata) std::printf("%s=%s\n", k.c_str(), v.c_str());
            }

            if (!i.extras.empty()) {
                std::printf("\n[extras]\ncount=%zu\n", i.extras.size());
                for (size_t n = 0; n < i.extras.size(); ++n) {
                    const auto& e = i.extras[n];
                    std::printf("\n[extra.%zu]\ntype=%s\nname=%s\nevent=%s\npriority=%d\nargs_size=%d\ncon_size=%d\n",
                                n, extra_type_name(static_cast<ExtraType>(e.type)),
                                e.name, e.event, e.priority, e.args_size, e.con_size);
                }
            }
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int cmd_dump(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }

    try {
        auto data = read_file(a.kernel);
        std::fprintf(stderr, "[ktool] Read %zu bytes\n", data.size());

        KallsymsFinder finder;
        finder.parse(data.data(), data.size());
        std::fprintf(stderr, "[+] Found %zu symbols\n", finder.num_symbols());

        if (!a.output.empty()) {
            std::ofstream out(a.output);
            if (!out) throw std::runtime_error("cannot create: " + a.output.string());
            const char* fmt = finder.is_64_bits() ? "%016llx %c %s\n" : "%08llx %c %s\n";
            for (const auto& s : finder.symbols()) {
                char buf[256];
                std::snprintf(buf, sizeof(buf), fmt,
                              (unsigned long long)s.address, s.type, s.name.c_str());
                out << buf;
            }
            std::fprintf(stderr, "[+] Saved to %s\n", a.output.c_str());
        } else {
            finder.print_symbols();
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int cmd_config(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }

    try {
        auto data = read_file(a.kernel);
        std::fprintf(stderr, "[ktool] Read %zu bytes\n", data.size());

        IkconfigFinder finder;
        auto config_text = finder.extract(data.data(), data.size());
        std::fprintf(stderr, "[+] Extracted %zu bytes\n", config_text.size());

        KernelConfig config;
        config.parse(config_text);

        if (a.verbose) {
            std::fprintf(stderr, "\n[*] Relevant options:\n");
            std::fprintf(stderr, "    KALLSYMS=%s\n", config.has_kallsyms() ? "y" : "n");
            std::fprintf(stderr, "    KALLSYMS_ALL=%s\n", config.has_kallsyms_all() ? "y" : "n");
            std::fprintf(stderr, "    RELOCATABLE=%s\n", config.has_relocatable() ? "y" : "n");
        }

        if (!a.output.empty()) {
            std::ofstream out(a.output);
            if (!out) throw std::runtime_error("cannot create: " + a.output.string());
            out << config_text;
            std::fprintf(stderr, "[+] Saved to %s\n", a.output.c_str());
        } else {
            std::printf("%s", config_text.c_str());
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int cmd_image(const Args& a) {
    if (a.kernel.empty()) { std::fprintf(stderr, "Error: -i required\n"); return 1; }

    try {
        auto data = read_file(a.kernel);
        std::printf("[ktool] Analyzing: %s (%zu bytes)\n", a.kernel.c_str(), data.size());

        ImageParser parser;
        auto info = parser.parse(data.data(), data.size());

        std::printf("\n[format]\ntype=%s\ncompression=%s\n",
                    ImageParser::format_name(info.format).c_str(),
                    ImageParser::compression_name(info.compression).c_str());

        if (info.format == ImageFormat::ARM64_Image || info.format == ImageFormat::ARM64_EFI_Stub) {
            std::printf("\n[arm64]\ntext_offset=0x%llx\nimage_size=0x%llx\nflags=0x%llx\n",
                        (unsigned long long)info.text_offset,
                        (unsigned long long)info.image_size,
                        (unsigned long long)info.flags);
            std::printf("endian=%s\npage_size=%s\n",
                        info.endianness == Endianness::Little ? "little" : "big",
                        ImageParser::page_size_str(info.page_size).c_str());
        }

        if (info.format == ImageFormat::Android_BootImg) {
            std::printf("\n[android]\nheader_version=%u\npage_size=%u\nkernel_offset=0x%x\nkernel_size=%u\n",
                        info.android_header_version, info.android_page_size,
                        info.android_kernel_offset, info.android_kernel_size);
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "Error: %s\n", e.what());
        return 1;
    }
}

int run(int argc, char** argv) {
    auto a = parse_args(argc, argv);
    if (!a || a->cmd == Cmd::None) { usage(argv[0]); return 1; }

    switch (a->cmd) {
        case Cmd::Help: usage(argv[0]); return 0;
        case Cmd::Version:
            std::printf("ktool %s\n", version_str().c_str());
#ifdef KTOOL_ANDROID
            std::printf("Platform: Android\n");
#endif
#ifdef KTOOL_HAVE_ZLIB
            std::printf("zlib: yes\n");
#endif
            return 0;
        case Cmd::Patch: return cmd_patch(*a);
        case Cmd::Unpatch: return cmd_unpatch(*a);
        case Cmd::ResetKey: return cmd_reset_key(*a);
        case Cmd::Info: return cmd_info(*a);
        case Cmd::Dump: return cmd_dump(*a);
        case Cmd::Config: return cmd_config(*a);
        case Cmd::Image: return cmd_image(*a);
        default: return 1;
    }
}

} // namespace ktool

int main(int argc, char** argv) { return ktool::run(argc, argv); }