/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2024 bmax121. All Rights Reserved. */

#include "image.hpp"

#include <algorithm>
#include <cstring>
#include <cstdio>

#ifdef KPTOOLS_HAVE_ZLIB
#include <zlib.h>
#endif

namespace kptools {

namespace {

bool starts_with(const uint8_t* data, size_t size,
                 const uint8_t* pattern, size_t pattern_len) {
    if (size < pattern_len) return false;
    return std::memcmp(data, pattern, pattern_len) == 0;
}

size_t mem_find(const uint8_t* data, size_t size,
                const uint8_t* pattern, size_t pattern_len,
                size_t start = 0) {
    if (start >= size || pattern_len == 0 || size - start < pattern_len) {
        return SIZE_MAX;
    }

    const uint8_t* pos = std::search(data + start, data + size,
                                      pattern, pattern + pattern_len);
    if (pos == data + size) return SIZE_MAX;
    return pos - data;
}

} // namespace

CompressionType ImageParser::detect_compression(const uint8_t* data, size_t size) {
    if (size < 4) return CompressionType::None;

    if (size >= 2 && data[0] == 0x1f && data[1] == 0x8b) {
        return CompressionType::Gzip;
    }

    if (size >= 6 && starts_with(data, size, kXzMagic, sizeof(kXzMagic))) {
        return CompressionType::XZ;
    }

    uint32_t magic32 = read_le32(data);
    if (magic32 == kLz4FrameMagic) {
        return CompressionType::LZ4_Frame;
    }

    if (magic32 == kLz4LegacyMagic) {
        return CompressionType::LZ4_Legacy;
    }

    if (size >= 3 && starts_with(data, size, kLzmaMagic, sizeof(kLzmaMagic))) {
        return CompressionType::LZMA;
    }

    if (size >= 3 && data[0] == 0x42 && data[1] == 0x5a && data[2] == 0x68) {
        return CompressionType::Bzip2;
    }

    if (magic32 == kLzoMagic) {
        return CompressionType::LZO;
    }

    if (magic32 == kZstdMagic) {
        return CompressionType::Zstd;
    }

    return CompressionType::None;
}

ImageFormat ImageParser::detect_format(const uint8_t* data, size_t size) {
    if (size < 64) return ImageFormat::Unknown;

    if (size >= sizeof(AndroidBootHeader)) {
        if (starts_with(data, size, kAndroidBootMagic, kAndroidBootMagicSize)) {
            return ImageFormat::Android_BootImg;
        }
    }

    uint32_t arm64_magic = read_le32(data + kArm64MagicOffset);
    if (arm64_magic == kArm64Magic) {
        uint16_t dos_magic = read_le16(data);
        if (dos_magic == kDosMagic) {
            return ImageFormat::ARM64_EFI_Stub;
        }
        return ImageFormat::ARM64_Image;
    }

    CompressionType comp = detect_compression(data, size);
    if (comp != CompressionType::None) {
        return ImageFormat::Compressed;
    }

    return ImageFormat::Unknown;
}

ImageInfo ImageParser::parse(const uint8_t* data, size_t size) {
    ImageInfo info;

    if (size < 64) {
        throw ImageError("Image too small (< 64 bytes)");
    }

    info.format = detect_format(data, size);

    switch (info.format) {
    case ImageFormat::ARM64_Image:
    case ImageFormat::ARM64_EFI_Stub: {
        const auto* hdr = reinterpret_cast<const ARM64ImageHeader*>(data);
        parse_arm64_header(hdr, info);

        if (info.format == ImageFormat::ARM64_EFI_Stub) {
            parse_pe_header(data, size, info);
        }

        info.kernel_offset = 0;
        info.kernel_size = size;
        break;
    }

    case ImageFormat::Android_BootImg: {
        if (!parse_android_boot(data, size, info)) {
            throw ImageError("Failed to parse Android boot.img header");
        }

        if (info.android_kernel_size > 0 && info.android_kernel_offset < size) {
            const uint8_t* kernel_data = data + info.android_kernel_offset;
            size_t kernel_size = std::min(static_cast<size_t>(info.android_kernel_size),
                                          size - info.android_kernel_offset);
            info.compression = detect_compression(kernel_data, kernel_size);
        }
        break;
    }

    case ImageFormat::Compressed: {
        info.compression = detect_compression(data, size);
        info.compressed_offset = 0;
        info.compressed_size = size;
        break;
    }

    case ImageFormat::Unknown:
    default:
        auto comp_info = find_compressed_kernel(data, size);
        if (comp_info) {
            info.compressed_offset = comp_info->first;
            info.compression = comp_info->second;
            info.compressed_size = size - info.compressed_offset;
        }
        break;
    }

    return info;
}

bool ImageParser::is_valid_image(const uint8_t* data, size_t size) const {
    if (size < 64) return false;

    ImageFormat fmt = detect_format(data, size);
    return fmt != ImageFormat::Unknown;
}

void ImageParser::parse_arm64_header(const ARM64ImageHeader* hdr, ImageInfo& info) {
    info.text_offset = hdr->text_offset;
    info.image_size = hdr->image_size;
    info.flags = hdr->flags;

    parse_flags(hdr->flags, info);

    if (info.image_size == 0) {
        if (info.text_offset == 0) {
            info.text_offset = 0x80000;
        }
    }

    if (hdr->res5 != 0 && hdr->res5 < 0x1000) {
        info.has_efi_stub = true;
        info.pe_header_offset = hdr->res5;
    }
}

void ImageParser::parse_flags(uint64_t flags, ImageInfo& info) {
    info.endianness = (flags & 1) ? Endianness::Big : Endianness::Little;
    uint64_t page_bits = (flags >> 1) & 0x3;
    info.page_size = static_cast<PageSize>(page_bits);
    info.phys_placement_anywhere = (flags >> 3) & 1;
}

bool ImageParser::parse_pe_header(const uint8_t* data, size_t size, ImageInfo& info) {
    if (size < 64) return false;

    uint32_t pe_offset = read_le32(data + kDosPeOffsetLoc);
    if (pe_offset == 0 || pe_offset >= size - sizeof(PECOFFHeader)) {
        return false;
    }

    uint32_t pe_sig = read_le32(data + pe_offset);
    if (pe_sig != kPeMagic) {
        return false;
    }

    info.has_efi_stub = true;
    info.pe_header_offset = pe_offset;

    const auto* coff = reinterpret_cast<const PECOFFHeader*>(data + pe_offset);

    if (coff->machine != kPeMachineArm64) {
        std::fprintf(stderr, "[!] Warning: PE machine type is 0x%04x, expected 0x%04x (ARM64)\n",
                     coff->machine, kPeMachineArm64);
    }

    return true;
}

bool ImageParser::parse_android_boot(const uint8_t* data, size_t size, ImageInfo& info) {
    if (size < sizeof(AndroidBootHeader)) {
        return false;
    }

    const auto* hdr = reinterpret_cast<const AndroidBootHeader*>(data);

    if (!starts_with(hdr->magic, sizeof(hdr->magic),
                     kAndroidBootMagic, kAndroidBootMagicSize)) {
        return false;
    }

    info.is_android_boot = true;
    info.android_kernel_size = hdr->kernel_size;
    info.android_page_size = hdr->page_size;
    info.android_header_version = hdr->header_version;

    info.android_kernel_offset = hdr->page_size;

    if (info.android_kernel_offset >= size) {
        std::fprintf(stderr, "[!] Warning: Android kernel offset beyond file size\n");
        return false;
    }

    info.kernel_offset = info.android_kernel_offset;
    info.kernel_size = info.android_kernel_size;

    return true;
}

std::optional<std::pair<size_t, CompressionType>>
ImageParser::find_compressed_kernel(const uint8_t* data, size_t size) {
    struct {
        const uint8_t* pattern;
        size_t len;
        CompressionType type;
    } patterns[] = {
        { (const uint8_t*)"\x1f\x8b\x08", 3, CompressionType::Gzip },
        { kXzMagic, sizeof(kXzMagic), CompressionType::XZ },
    };

    for (const auto& p : patterns) {
        size_t pos = mem_find(data, size, p.pattern, p.len, 0);
        if (pos != SIZE_MAX && pos < size) {
            if (p.type == CompressionType::Gzip && pos + 10 < size) {
                uint8_t method = data[pos + 2];
                uint8_t flags = data[pos + 3];
                if (method == 8 && (flags & 0xe0) == 0) {
                    return std::make_pair(pos, p.type);
                }
            } else if (p.type == CompressionType::XZ) {
                return std::make_pair(pos, p.type);
            }
        }
    }

    return std::nullopt;
}

std::vector<uint8_t> ImageParser::decompress(const uint8_t* data, size_t size) {
    CompressionType comp = detect_compression(data, size);

    switch (comp) {
    case CompressionType::Gzip:
        return decompress_gzip(data, size);
    case CompressionType::LZ4_Frame:
        return decompress_lz4(data, size, false);
    case CompressionType::LZ4_Legacy:
        return decompress_lz4(data, size, true);
    case CompressionType::XZ:
        return decompress_xz(data, size);
    case CompressionType::LZMA:
        return decompress_lzma(data, size);
    case CompressionType::Bzip2:
        return decompress_bzip2(data, size);
    case CompressionType::LZO:
        return decompress_lzo(data, size);
    case CompressionType::Zstd:
        return decompress_zstd(data, size);
    case CompressionType::None:
    default:
        return {};
    }
}

std::pair<const uint8_t*, size_t> ImageParser::get_kernel_data(
    const uint8_t* data, size_t size,
    std::vector<uint8_t>& decompressed_buffer) {

    ImageInfo info = parse(data, size);

    if (info.format == ImageFormat::Android_BootImg) {
        data += info.android_kernel_offset;
        size = info.android_kernel_size;

        info.compression = detect_compression(data, size);
    }

    if (info.compression != CompressionType::None) {
        if (info.compressed_offset > 0) {
            data += info.compressed_offset;
            size -= info.compressed_offset;
        }

        decompressed_buffer = decompress(data, size);
        if (!decompressed_buffer.empty()) {
            return { decompressed_buffer.data(), decompressed_buffer.size() };
        }
    }

    return { data, size };
}

std::vector<uint8_t> ImageParser::decompress_gzip(const uint8_t* data, size_t size) {
#ifdef KPTOOLS_HAVE_ZLIB
    z_stream strm{};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = static_cast<uInt>(size);
    strm.next_in = const_cast<Bytef*>(data);

    int ret = inflateInit2(&strm, 15 + 16);
    if (ret != Z_OK) {
        return {};
    }

    std::vector<uint8_t> result;
    result.reserve(size * 4);

    uint8_t buffer[32768];
    do {
        strm.avail_out = sizeof(buffer);
        strm.next_out = buffer;

        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            return {};
        }

        size_t have = sizeof(buffer) - strm.avail_out;
        result.insert(result.end(), buffer, buffer + have);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return result;
#else
    (void)data;
    (void)size;
    std::fprintf(stderr, "[!] gzip decompression not available (zlib not compiled)\n");
    return {};
#endif
}

std::vector<uint8_t> ImageParser::decompress_lz4(const uint8_t* data, size_t size, bool legacy) {
    (void)data;
    (void)size;
    (void)legacy;
    std::fprintf(stderr, "[!] LZ4 decompression not implemented\n");
    return {};
}

std::vector<uint8_t> ImageParser::decompress_xz(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    std::fprintf(stderr, "[!] XZ decompression not implemented\n");
    return {};
}

std::vector<uint8_t> ImageParser::decompress_lzma(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    std::fprintf(stderr, "[!] LZMA decompression not implemented\n");
    return {};
}

std::vector<uint8_t> ImageParser::decompress_bzip2(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    std::fprintf(stderr, "[!] bzip2 decompression not implemented\n");
    return {};
}

std::vector<uint8_t> ImageParser::decompress_lzo(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    std::fprintf(stderr, "[!] LZO decompression not implemented\n");
    return {};
}

std::vector<uint8_t> ImageParser::decompress_zstd(const uint8_t* data, size_t size) {
    (void)data;
    (void)size;
    std::fprintf(stderr, "[!] Zstd decompression not implemented\n");
    return {};
}

std::string ImageParser::format_name(ImageFormat fmt) {
    switch (fmt) {
    case ImageFormat::ARM64_Image:      return "ARM64 Image";
    case ImageFormat::ARM64_EFI_Stub:   return "ARM64 EFI Stub (PE/COFF)";
    case ImageFormat::Android_BootImg:  return "Android boot.img";
    case ImageFormat::Compressed:       return "Compressed";
    case ImageFormat::Unknown:
    default:                            return "Unknown";
    }
}

std::string ImageParser::compression_name(CompressionType comp) {
    switch (comp) {
    case CompressionType::None:         return "None";
    case CompressionType::Gzip:         return "gzip";
    case CompressionType::LZ4_Frame:    return "LZ4 (frame)";
    case CompressionType::LZ4_Legacy:   return "LZ4 (legacy)";
    case CompressionType::LZMA:         return "LZMA";
    case CompressionType::XZ:           return "XZ";
    case CompressionType::Bzip2:        return "bzip2";
    case CompressionType::LZO:          return "LZO";
    case CompressionType::Zstd:         return "Zstd";
    default:                            return "Unknown";
    }
}

std::string ImageParser::page_size_str(PageSize ps) {
    switch (ps) {
    case PageSize::Size_4K:   return "4K";
    case PageSize::Size_16K:  return "16K";
    case PageSize::Size_64K:  return "64K";
    case PageSize::Unspecified:
    default:                  return "Unspecified";
    }
}

} // namespace kptools