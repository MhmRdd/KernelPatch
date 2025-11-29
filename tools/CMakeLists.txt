# SPDX-License-Identifier: GPL-2.0-or-later
# kptools build configuration

cmake_minimum_required(VERSION 3.16)
project(kptools LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Platform Detection
if(ANDROID)
    message(STATUS "[kptools] Building for Android (${ANDROID_ABI})")
    set(KPTOOLS_ANDROID TRUE)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    message(STATUS "[kptools] Building for ARM64")
    set(KPTOOLS_ARM64 TRUE)
else()
    message(STATUS "[kptools] Building for host (${CMAKE_SYSTEM_PROCESSOR})")
endif()

# Read version from version file
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../version")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../version" VERSION_CONTENT)
    string(REGEX MATCH "#define MAJOR ([0-9]+)" _ "${VERSION_CONTENT}")
    set(KPTOOLS_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define MINOR ([0-9]+)" _ "${VERSION_CONTENT}")
    set(KPTOOLS_VERSION_MINOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define PATCH ([0-9]+)" _ "${VERSION_CONTENT}")
    set(KPTOOLS_VERSION_PATCH ${CMAKE_MATCH_1})
endif()

# Fallback if version parsing failed
if(NOT KPTOOLS_VERSION_MAJOR)
    set(KPTOOLS_VERSION_MAJOR 0)
endif()
if(NOT KPTOOLS_VERSION_MINOR)
    set(KPTOOLS_VERSION_MINOR 12)
endif()
if(NOT KPTOOLS_VERSION_PATCH)
    set(KPTOOLS_VERSION_PATCH 2)
endif()

message(STATUS "kptools version: ${KPTOOLS_VERSION_MAJOR}.${KPTOOLS_VERSION_MINOR}.${KPTOOLS_VERSION_PATCH}")

# Source files
set(KPTOOLS_SOURCES
    main.cpp
    core/types.hpp
    core/buffer.hpp
    core/file.hpp
    core/logging.hpp
    arm64/insn.hpp
    arm64/insn.cpp
    kernel/image.hpp
    kernel/image.cpp
    kernel/kallsym.hpp
    kernel/kallsym.cpp
    kernel/preset.hpp
    kernel/patch.hpp
    kernel/patch.cpp
    kpm/module.hpp
    kpm/module.cpp
    crypto/sha256.hpp
    crypto/sha256.cpp
)

add_executable(kptools ${KPTOOLS_SOURCES})

target_compile_definitions(kptools PRIVATE
    KPTOOLS_VERSION_MAJOR=${KPTOOLS_VERSION_MAJOR}
    KPTOOLS_VERSION_MINOR=${KPTOOLS_VERSION_MINOR}
    KPTOOLS_VERSION_PATCH=${KPTOOLS_VERSION_PATCH}
)

target_compile_options(kptools PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=return-type
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(kptools PRIVATE -O2)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(kptools PRIVATE -g -O0)
endif()

# Android NDK include paths for IDE code analysis
if(ANDROID AND ANDROID_NDK)
    set(_NDK_SYSROOT "${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/sysroot")
    target_include_directories(kptools SYSTEM BEFORE PRIVATE
        "${_NDK_SYSROOT}/usr/include/c++/v1"
        "${_NDK_SYSROOT}/usr/include/aarch64-linux-android"
        "${_NDK_SYSROOT}/usr/include"
    )
    message(STATUS "[kptools] Added NDK sysroot includes for IDE: ${_NDK_SYSROOT}")
endif()

# Custom Targets
add_custom_target(kptools_Build
    DEPENDS kptools
    COMMENT "[kptools] Build complete"
)

add_custom_target(kptools_Clean
    COMMAND ${CMAKE_COMMAND} -E remove -f $<TARGET_FILE:kptools>
    COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_BINARY_DIR}/*.o
    COMMENT "[kptools] Cleaned"
)

add_custom_target(kptools_Rebuild
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kptools_Clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kptools
    COMMENT "[kptools] Rebuilding..."
)

# ADB Push Targets
add_custom_target(kptools_Push
    COMMAND adb push $<TARGET_FILE:kptools> /data/local/tmp/kptools
    COMMENT "[kptools] Pushing to /data/local/tmp/kptools"
)

add_custom_target(kptools_BuildAndPush
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kptools
    COMMAND adb push $<TARGET_FILE:kptools> /data/local/tmp/kptools
    COMMENT "[kptools] Building and pushing..."
)

# Installation
install(TARGETS kptools RUNTIME DESTINATION bin)