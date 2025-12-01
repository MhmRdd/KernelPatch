/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>
#include <stdexcept>

namespace kptools {

constexpr uint32_t kArm64Magic = 0x644d5241;
constexpr size_t kArm64MagicOffset = 0x38;
constexpr uint16_t kDosMagic = 0x5a4d;
constexpr uint32_t kPeMagic = 0x00004550;
constexpr uint16_t kPeMachineArm64 = 0xaa64;
constexpr size_t kDosPeOffsetLoc = 0x3c;
constexpr uint16_t kGzipMagic = 0x8b1f;
constexpr uint32_t kLz4FrameMagic = 0x184D2204;
constexpr uint32_t kLz4LegacyMagic = 0x184C2102;
constexpr uint8_t kLzmaMagic[] = {0x5d, 0x00, 0x00};
constexpr uint8_t kXzMagic[] = {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00};
constexpr uint16_t kBzip2Magic = 0x5a42;
constexpr uint32_t kLzoMagic = 0x4f5a4c89;
constexpr uint32_t kZstdMagic = 0xfd2fb528;
constexpr uint8_t kAndroidBootMagic[] = "ANDROID!";
constexpr uint8_t kAndroidBootMagicUncomp[] = "UNCOMPRESSED_IMG";
constexpr size_t kAndroidBootMagicSize = 8;

enum class ImageFormat {
    Unknown,
    ARM64_Image,
    ARM64_EFI_Stub,
    Android_BootImg,
    Compressed,
};

enum class CompressionType {
    None,
    Gzip,
    LZ4_Frame,
    LZ4_Legacy,
    LZMA,
    XZ,
    Bzip2,
    LZO,
    Zstd,
};

enum class Endianness {
    Little,
    Big,
};

enum class PageSize {
    Unspecified = 0,
    Size_4K = 1,
    Size_16K = 2,
    Size_64K = 3,
};

#pragma pack(push, 1)
struct ARM64ImageHeader {
    uint32_t code0;
    uint32_t code1;
    uint64_t text_offset;
    uint64_t image_size;
    uint64_t flags;
    uint64_t res2;
    uint64_t res3;
    uint64_t res4;
    uint32_t magic;
    uint32_t res5;
};
static_assert(sizeof(ARM64ImageHeader) == 64, "ARM64ImageHeader must be 64 bytes");

struct DOSHeader {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
};
static_assert(sizeof(DOSHeader) == 64, "DOSHeader must be 64 bytes");

struct PECOFFHeader {
    uint32_t signature;
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symbol_table;
    uint32_t num_symbols;
    uint16_t opt_header_size;
    uint16_t characteristics;
};
static_assert(sizeof(PECOFFHeader) == 24, "PECOFFHeader must be 24 bytes");

struct AndroidBootHeader {
    uint8_t  magic[8];
    uint32_t kernel_size;
    uint32_t kernel_addr;
    uint32_t ramdisk_size;
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;
    uint32_t header_version;
    uint32_t os_version;
    uint8_t  name[16];
    uint8_t  cmdline[512];
    uint8_t  id[32];
    uint8_t  extra_cmdline[1024];
};
#pragma pack(pop)

class ImageError : public std::runtime_error {
public:
    explicit ImageError(const std::string& msg) : std::runtime_error(msg) {}
};

struct ImageInfo {
    ImageFormat format = ImageFormat::Unknown;
    CompressionType compression = CompressionType::None;

    uint64_t text_offset = 0;
    uint64_t image_size = 0;
    uint64_t flags = 0;

    Endianness endianness = Endianness::Little;
    PageSize page_size = PageSize::Unspecified;
    bool phys_placement_anywhere = false;

    bool has_efi_stub = false;
    uint32_t pe_header_offset = 0;

    bool is_android_boot = false;
    uint32_t android_kernel_offset = 0;
    uint32_t android_kernel_size = 0;
    uint32_t android_page_size = 0;
    uint32_t android_header_version = 0;

    size_t compressed_offset = 0;
    size_t compressed_size = 0;

    size_t kernel_offset = 0;
    size_t kernel_size = 0;

    std::string version_string;
    int version_major = 0;
    int version_minor = 0;
    int version_patch = 0;
};

class ImageParser {
public:
    ImageParser() = default;

    ImageInfo parse(const uint8_t* data, size_t size);
    bool is_valid_image(const uint8_t* data, size_t size) const;

    static CompressionType detect_compression(const uint8_t* data, size_t size);
    static ImageFormat detect_format(const uint8_t* data, size_t size);

    std::vector<uint8_t> decompress(const uint8_t* data, size_t size);
    std::pair<const uint8_t*, size_t> get_kernel_data(
        const uint8_t* data, size_t size,
        std::vector<uint8_t>& decompressed_buffer);

    static std::string format_name(ImageFormat fmt);
    static std::string compression_name(CompressionType comp);
    static std::string page_size_str(PageSize ps);

private:
    void parse_arm64_header(const ARM64ImageHeader* hdr, ImageInfo& info);
    void parse_flags(uint64_t flags, ImageInfo& info);
    bool parse_pe_header(const uint8_t* data, size_t size, ImageInfo& info);
    bool parse_android_boot(const uint8_t* data, size_t size, ImageInfo& info);

    std::optional<std::pair<size_t, CompressionType>>
    find_compressed_kernel(const uint8_t* data, size_t size);

    std::vector<uint8_t> decompress_gzip(const uint8_t* data, size_t size);
    std::vector<uint8_t> decompress_lz4(const uint8_t* data, size_t size, bool legacy);
    std::vector<uint8_t> decompress_xz(const uint8_t* data, size_t size);
    std::vector<uint8_t> decompress_lzma(const uint8_t* data, size_t size);
    std::vector<uint8_t> decompress_bzip2(const uint8_t* data, size_t size);
    std::vector<uint8_t> decompress_lzo(const uint8_t* data, size_t size);
    std::vector<uint8_t> decompress_zstd(const uint8_t* data, size_t size);
};

inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_le64(const uint8_t* p) {
    return static_cast<uint64_t>(read_le32(p)) |
           (static_cast<uint64_t>(read_le32(p + 4)) << 32);
}

} // namespace kptools