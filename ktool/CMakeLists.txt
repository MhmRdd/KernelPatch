# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 bmax121. All Rights Reserved.
#
# ktool - KernelPatch Tool
# A modern C++ implementation for kernel image patching

cmake_minimum_required(VERSION 3.20)

# Project definition
project(ktool
    VERSION 1.0.0
    DESCRIPTION "KernelPatch kernel image patching tool"
    LANGUAGES CXX
)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    message(STATUS "[ktool] Defaulting to Release build")
endif()

# Options
option(KTOOL_ANDROID "Build for Android target" OFF)
option(KTOOL_STATIC "Build static binary" OFF)

# Source files
set(KTOOL_SOURCES
    src/main.cpp
    src/kallsyms.cpp
    src/ikconfig.cpp
    src/image.cpp
    src/patch.cpp
)

# Include directories
set(KTOOL_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Create executable
add_executable(ktool ${KTOOL_SOURCES})

target_include_directories(ktool PRIVATE ${KTOOL_INCLUDE_DIRS})

# Compiler flags
target_compile_options(ktool PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
)

# Release build optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    target_compile_options(ktool PRIVATE
        -O2
        -ffunction-sections
        -fdata-sections
        -fvisibility=hidden
    )
    target_compile_definitions(ktool PRIVATE NDEBUG)

    # Platform-specific linker optimizations
    if(APPLE)
        target_link_options(ktool PRIVATE
            -Wl,-dead_strip
        )
        # Strip symbols post-build on macOS
        add_custom_command(TARGET ktool POST_BUILD
            COMMAND strip $<TARGET_FILE:ktool>
            COMMENT "[ktool] Stripping symbols"
        )
    else()
        target_link_options(ktool PRIVATE
            -Wl,--gc-sections
            -Wl,-s
        )
    endif()
    message(STATUS "[ktool] Release optimizations enabled (strip + gc-sections)")
endif()

# Platform-specific configuration
if(KTOOL_ANDROID)
    target_compile_definitions(ktool PRIVATE KTOOL_ANDROID=1)
    message(STATUS "[ktool] Building for Android")
endif()

# Static linking option
if(KTOOL_STATIC)
    target_link_options(ktool PRIVATE -static)
    message(STATUS "[ktool] Static linking enabled")
endif()

# Find zlib (required for decompression)
find_package(ZLIB)
if(ZLIB_FOUND)
    target_link_libraries(ktool PRIVATE ZLIB::ZLIB)
    target_compile_definitions(ktool PRIVATE KTOOL_HAVE_ZLIB=1)
    message(STATUS "[ktool] zlib found: ${ZLIB_VERSION_STRING}")
else()
    message(STATUS "[ktool] zlib not found - compression support disabled")
endif()

# Version info
target_compile_definitions(ktool PRIVATE
    KTOOL_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    KTOOL_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    KTOOL_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    KTOOL_VERSION="${PROJECT_VERSION}"
)

# Output directory
set_target_properties(ktool PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# ADB device path for push targets
if(NOT DEFINED ADB_DEVICE_PATH)
    set(ADB_DEVICE_PATH "/data/local/tmp")
endif()

# Build target (alias)
add_custom_target(ktool_Build
    DEPENDS ktool
    COMMENT "[ktool] Build complete"
)

# Clean target
add_custom_target(ktool_Clean
    COMMAND ${CMAKE_COMMAND} -E remove -f $<TARGET_FILE:ktool>
    COMMAND ${CMAKE_COMMAND} -E echo "[ktool] Cleaned"
    COMMENT "[ktool] Cleaning build artifacts"
)

# Push target (requires adb)
find_program(ADB_EXECUTABLE adb)
if(ADB_EXECUTABLE)
    add_custom_target(ktool_Push
        COMMAND ${ADB_EXECUTABLE} push $<TARGET_FILE:ktool> ${ADB_DEVICE_PATH}/
        COMMAND ${ADB_EXECUTABLE} shell chmod 755 ${ADB_DEVICE_PATH}/ktool
        DEPENDS ktool
        COMMENT "[ktool] Pushing to device: ${ADB_DEVICE_PATH}/ktool"
    )

    add_custom_target(ktool_BuildAndPush
        DEPENDS ktool_Push
        COMMENT "[ktool] Build and push complete"
    )
else()
    message(STATUS "[ktool] adb not found - push targets disabled")
endif()

# Summary
message(STATUS "")
message(STATUS "=== ktool Configuration ===")
message(STATUS "  Version:        ${PROJECT_VERSION}")
message(STATUS "  Android:        ${KTOOL_ANDROID}")
message(STATUS "  Static:         ${KTOOL_STATIC}")
message(STATUS "  zlib:           ${ZLIB_FOUND}")
message(STATUS "")
message(STATUS "  Targets:")
message(STATUS "    ktool             - Build executable")
message(STATUS "    ktool_Build       - Build executable")
message(STATUS "    ktool_Clean       - Clean build artifacts")
if(ADB_EXECUTABLE)
    message(STATUS "    ktool_Push        - Push to device")
    message(STATUS "    ktool_BuildAndPush - Build and push")
endif()
message(STATUS "")