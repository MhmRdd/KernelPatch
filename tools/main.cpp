/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#include "core/types.hpp"
#include "core/logging.hpp"
#include "kernel/patch.hpp"
#include "kernel/preset.hpp"
#include "kpm/module.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <string>
#include <vector>

// Version from version file (set by CMake)
#ifndef KPTOOLS_VERSION_MAJOR
#define KPTOOLS_VERSION_MAJOR 0
#endif
#ifndef KPTOOLS_VERSION_MINOR
#define KPTOOLS_VERSION_MINOR 12
#endif
#ifndef KPTOOLS_VERSION_PATCH
#define KPTOOLS_VERSION_PATCH 2
#endif

static constexpr uint32_t version = (static_cast<uint32_t>(KPTOOLS_VERSION_MAJOR) << 16) |
                                    (static_cast<uint32_t>(KPTOOLS_VERSION_MINOR) << 8) |
                                    static_cast<uint32_t>(KPTOOLS_VERSION_PATCH);

static const char *program_name = nullptr;

static void print_usage() {
    std::fprintf(stdout,
        "Kernel Image Patch Tools. version: %x\n"
        "\n"
        "Usage: %s COMMAND [Options...]\n"
        "\n"
        "COMMAND:\n"
        "  -h, --help                       Print this message.\n"
        "  -v, --version                    Print version number. Print kpimg version if -k specified.\n"
        "  -p, --patch                      Patch or Update patch of kernel image(-i) with specified kpimg(-k) and superkey(-s).\n"
        "  -u, --unpatch                    Unpatch patched kernel image(-i).\n"
        "  -r, --reset-skey                 Reset superkey of patched image(-i).\n"
        "  -d, --dump                       Dump kallsyms infomations of kernel image(-i).\n"
        "  -l, --list                       Print all patch informations of kernel image if (-i) specified.\n"
        "                                   Print extra item informations if (-M) specified.\n"
        "                                   Print KernelPatch image informations if (-k) specified.\n"
        "\n"
        "Options:\n"
        "  -i, --image PATH                 Kernel image path.\n"
        "  -k, --kpimg PATH                 KernelPatch image path.\n"
        "  -s, --skey KEY                   Set the superkey and save it directly in the boot.img.\n"
        "  -S, --root-skey KEY              Set the root-superkey using hash verification, and the superkey can be changed dynamically.\n"
        "  -o, --out PATH                   Patched image path.\n"
        "  -a  --addition KEY=VALUE         Add additional information.\n"
        "\n"
        "  -M, --embed-extra-path PATH      Embed new extra item.\n"
        "  -E, --embeded-extra-name NAME    Preserve and modify embedded extra item.\n"
        "  -T, --extra-type TYPE            Set type of previous extra item.\n"
        "  -N, --extra-name NAME            Set name of previous extra item.\n"
        "  -V, --extra-event EVENT          Set trigger event of previous extra item.\n"
        "  -A, --extra-args ARGS            Set arguments of previous extra item.\n"
        "\n",
        version, program_name);
}

int main(int argc, char *argv[]) {
    program_name = argv[0];

    static struct option longopts[] = {
        {"help",              no_argument,       nullptr, 'h'},
        {"version",           no_argument,       nullptr, 'v'},
        {"patch",             no_argument,       nullptr, 'p'},
        {"unpatch",           no_argument,       nullptr, 'u'},
        {"resetkey",          no_argument,       nullptr, 'r'},
        {"dump",              no_argument,       nullptr, 'd'},
        {"list",              no_argument,       nullptr, 'l'},
        {"image",             required_argument, nullptr, 'i'},
        {"kpimg",             required_argument, nullptr, 'k'},
        {"skey",              required_argument, nullptr, 's'},
        {"root-skey",         required_argument, nullptr, 'S'},
        {"out",               required_argument, nullptr, 'o'},
        {"addition",          required_argument, nullptr, 'a'},
        {"embed-extra-path",  required_argument, nullptr, 'M'},
        {"embeded-extra-name", required_argument, nullptr, 'E'},
        {"extra-type",        required_argument, nullptr, 'T'},
        {"extra-name",        required_argument, nullptr, 'N'},
        {"extra-event",       required_argument, nullptr, 'V'},
        {"extra-args",        required_argument, nullptr, 'A'},
        {nullptr, 0, nullptr, 0}
    };
    const char *optstr = "hvpurdli:s:S:k:o:a:M:E:T:N:V:A:";

    std::string kimg_path;
    std::string kpimg_path;
    std::string out_path;
    std::string superkey;
    bool root_skey = false;

    std::vector<std::string> additional;
    std::vector<kp::kernel::ExtraConfig> extras;
    kp::kernel::ExtraConfig *current_extra = nullptr;

    char cmd = '\0';
    int opt;

    while ((opt = getopt_long(argc, argv, optstr, longopts, nullptr)) != -1) {
        switch (opt) {
        case 'h':
        case 'v':
        case 'p':
        case 'u':
        case 'r':
        case 'd':
        case 'l':
            cmd = static_cast<char>(opt);
            break;

        case 'i':
            kimg_path = optarg;
            break;

        case 'k':
            kpimg_path = optarg;
            break;

        case 'S':
            root_skey = true;
            [[fallthrough]];
        case 's':
            superkey = optarg;
            break;

        case 'o':
            out_path = optarg;
            break;

        case 'a':
            additional.emplace_back(optarg);
            break;

        case 'M':
            extras.emplace_back();
            current_extra = &extras.back();
            current_extra->is_path = true;
            current_extra->path_or_name = optarg;
            break;

        case 'E':
            extras.emplace_back();
            current_extra = &extras.back();
            current_extra->is_path = false;
            current_extra->path_or_name = optarg;
            break;

        case 'T':
            if (current_extra) {
                current_extra->type = kp::kernel::extra_str_type(optarg);
                if (current_extra->type == kp::kernel::EXTRA_TYPE_NONE) {
                    std::fprintf(stderr, "Invalid extra type: %s\n", optarg);
                    return 1;
                }
            }
            break;

        case 'V':
            if (current_extra) {
                current_extra->event = optarg;
            }
            break;

        case 'N':
            if (current_extra) {
                current_extra->name = optarg;
            }
            break;

        case 'A':
            if (current_extra) {
                current_extra->args = optarg;
            }
            break;

        default:
            break;
        }
    }

    kp::kernel::Patcher patcher;
    int ret = 0;

    switch (cmd) {
    case 'h':
        print_usage();
        break;

    case 'v':
        if (!kpimg_path.empty()) {
            auto ver_result = kp::kernel::get_kpimg_version(kpimg_path);
            if (ver_result) {
                std::fprintf(stdout, "%x\n", ver_result.unwrap());
            } else {
                std::fprintf(stderr, "Error: %s\n", ver_result.error().c_str());
                ret = 1;
            }
        } else {
            std::fprintf(stdout, "%x\n", version);
        }
        break;

    case 'p': {
        if (kimg_path.empty() || kpimg_path.empty() || out_path.empty() || superkey.empty()) {
            std::fprintf(stderr, "Patch requires: -i <kernel> -k <kpimg> -o <output> -s <superkey>\n");
            ret = 1;
            break;
        }

        auto result = patcher.patch(kimg_path, kpimg_path, out_path, superkey,
                                    root_skey, additional, extras);
        if (!result) {
            std::fprintf(stderr, "Error: %s\n", result.error().c_str());
            ret = 1;
        }
        break;
    }

    case 'u': {
        if (kimg_path.empty() || out_path.empty()) {
            std::fprintf(stderr, "Unpatch requires: -i <kernel> -o <output>\n");
            ret = 1;
            break;
        }

        auto result = patcher.unpatch(kimg_path, out_path);
        if (!result) {
            std::fprintf(stderr, "Error: %s\n", result.error().c_str());
            ret = 1;
        }
        break;
    }

    case 'r': {
        if (kimg_path.empty() || out_path.empty() || superkey.empty()) {
            std::fprintf(stderr, "Reset key requires: -i <kernel> -o <output> -s <new-key>\n");
            ret = 1;
            break;
        }

        auto result = patcher.reset_key(kimg_path, out_path, superkey);
        if (!result) {
            std::fprintf(stderr, "Error: %s\n", result.error().c_str());
            ret = 1;
        }
        break;
    }

    case 'd': {
        if (kimg_path.empty()) {
            std::fprintf(stderr, "Dump requires: -i <kernel>\n");
            ret = 1;
            break;
        }

        auto result = patcher.dump_kallsyms(kimg_path);
        if (!result) {
            std::fprintf(stderr, "Error: %s\n", result.error().c_str());
            ret = 1;
        }
        break;
    }

    case 'l': {
        if (!kimg_path.empty()) {
            auto result = patcher.print_patch_info(kimg_path);
            if (!result) {
                std::fprintf(stderr, "Error: %s\n", result.error().c_str());
                ret = 1;
            }
        } else if (current_extra && current_extra->is_path) {
            auto result = kp::kpm::Module::from_file(current_extra->path_or_name);
            if (result) {
                std::fprintf(stdout, "%s\n", kp::kpm::INFO_EXTRA_KPM_SESSION);
                result.unwrap().info().print();
            } else {
                std::fprintf(stderr, "Error: %s\n", result.error().c_str());
                ret = 1;
            }
        } else if (!kpimg_path.empty()) {
            auto result = patcher.print_kpimg_info(kpimg_path);
            if (!result) {
                std::fprintf(stderr, "Error: %s\n", result.error().c_str());
                ret = 1;
            }
        } else {
            std::fprintf(stderr, "List requires: -i <kernel>, -k <kpimg>, or -M <kpm>\n");
            ret = 1;
        }
        break;
    }

    default:
        print_usage();
        break;
    }

    return ret;
}