# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 bmax121. All Rights Reserved.
#
# kptools - KernelPatch Tool
# A modern C++ implementation for kernel image patching

cmake_minimum_required(VERSION 3.20)

# Project definition
project(kptools
    VERSION 1.0.0
    DESCRIPTION "KernelPatch kernel image patching tool"
    LANGUAGES C CXX
)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# C Standard with GNU extensions (enables binary literals for ARM64 instruction decoding)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    message(STATUS "[kptools] Defaulting to Release build")
endif()

# Options
option(KPTOOLS_ANDROID "Build for Android target" OFF)
option(KPTOOLS_STATIC "Build static binary" OFF)

# ARM64 Disassembler/Assembler library (C sources)
set(DISASM_SOURCES
    disasm/arm64_disasm.c
    disasm/arm64_asm.c
)

# Disable pedantic warnings for disasm (uses binary literals for clarity)
set_source_files_properties(${DISASM_SOURCES} PROPERTIES
    COMPILE_FLAGS "-Wno-pedantic"
)

# Source files
set(KPTOOLS_SOURCES
    src/main.cpp
    src/kallsyms.cpp
    src/ikconfig.cpp
    src/image.cpp
    src/patch.cpp
    ${DISASM_SOURCES}
)

# Include directories
set(KPTOOLS_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/disasm/include
)

# Create executable
add_executable(kptools ${KPTOOLS_SOURCES})

target_include_directories(kptools PRIVATE ${KPTOOLS_INCLUDE_DIRS})

# Compiler flags
target_compile_options(kptools PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
)

# Release build optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    target_compile_options(kptools PRIVATE
        -O2
        -ffunction-sections
        -fdata-sections
        -fvisibility=hidden
    )
    target_compile_definitions(kptools PRIVATE NDEBUG)

    # Platform-specific linker optimizations
    if(APPLE)
        target_link_options(kptools PRIVATE
            -Wl,-dead_strip
        )
        # Strip symbols post-build on macOS
        add_custom_command(TARGET kptools POST_BUILD
            COMMAND strip $<TARGET_FILE:kptools>
            COMMENT "[kptools] Stripping symbols"
        )
    else()
        target_link_options(kptools PRIVATE
            -Wl,--gc-sections
            -Wl,-s
        )
    endif()
    message(STATUS "[kptools] Release optimizations enabled (strip + gc-sections)")
endif()

# Platform-specific configuration
if(KPTOOLS_ANDROID)
    target_compile_definitions(kptools PRIVATE KPTOOLS_ANDROID=1)
    message(STATUS "[kptools] Building for Android")
endif()

# Static linking option
if(KPTOOLS_STATIC)
    target_link_options(kptools PRIVATE -static)
    message(STATUS "[kptools] Static linking enabled")
endif()

# Find zlib (required for decompression)
find_package(ZLIB)
if(ZLIB_FOUND)
    target_link_libraries(kptools PRIVATE ZLIB::ZLIB)
    target_compile_definitions(kptools PRIVATE KPTOOLS_HAVE_ZLIB=1)
    message(STATUS "[kptools] zlib found: ${ZLIB_VERSION_STRING}")
else()
    message(STATUS "[kptools] zlib not found - compression support disabled")
endif()

# Version info
target_compile_definitions(kptools PRIVATE
    KPTOOLS_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    KPTOOLS_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    KPTOOLS_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    KPTOOLS_VERSION="${PROJECT_VERSION}"
)

# Output directory
set_target_properties(kptools PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ADB device path for push targets
if(NOT DEFINED ADB_DEVICE_PATH)
    set(ADB_DEVICE_PATH "/data/local/tmp")
endif()

# Build target (alias)
add_custom_target(kptools_Build
    DEPENDS kptools
    COMMENT "[kptools] Build complete"
)

# Clean target
add_custom_target(kptools_Clean
    COMMAND ${CMAKE_COMMAND} -E remove -f $<TARGET_FILE:kptools>
    COMMAND ${CMAKE_COMMAND} -E echo "[kptools] Cleaned"
    COMMENT "[kptools] Cleaning build artifacts"
)

# Push target (requires adb)
find_program(ADB_EXECUTABLE adb)
if(ADB_EXECUTABLE)
    add_custom_target(kptools_Push
        COMMAND ${ADB_EXECUTABLE} push $<TARGET_FILE:kptools> ${ADB_DEVICE_PATH}/
        COMMAND ${ADB_EXECUTABLE} shell chmod 755 ${ADB_DEVICE_PATH}/kptools
        DEPENDS kptools
        COMMENT "[kptools] Pushing to device: ${ADB_DEVICE_PATH}/kptools"
    )

    add_custom_target(kptools_BuildAndPush
        DEPENDS kptools_Push
        COMMENT "[kptools] Build and push complete"
    )
else()
    message(STATUS "[kptools] adb not found - push targets disabled")
endif()

# Summary
message(STATUS "")
message(STATUS "=== kptools Configuration ===")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Android:        ${KPTOOLS_ANDROID}")
message(STATUS "  Static:         ${KPTOOLS_STATIC}")
message(STATUS "  zlib:           ${ZLIB_FOUND}")
message(STATUS "")
message(STATUS "  Targets:")
message(STATUS "    kptools             - Build executable")
message(STATUS "    kptools_Build       - Build executable")
message(STATUS "    kptools_Clean       - Clean build artifacts")
if(ADB_EXECUTABLE)
    message(STATUS "    kptools_Push        - Push to device")
    message(STATUS "    kptools_BuildAndPush - Build and push")
endif()
message(STATUS "")