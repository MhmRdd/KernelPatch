# ============================================================================
# KernelPatch - Root CMakeLists.txt
# Cross-platform build configuration for the KernelPatch project
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# Add cmake modules path early
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ============================================================================
# Local Configuration (optional, user-specific settings)
# ============================================================================

# Load local config if it exists (copy LocalConfig.cmake.example to LocalConfig.cmake)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/LocalConfig.cmake")
    message(STATUS "Loading local configuration from cmake/LocalConfig.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/LocalConfig.cmake")
endif()

# Project definition
project(KernelPatch
    VERSION 0.12.2
    DESCRIPTION "Kernel patching and hooking framework for ARM64 Linux kernels"
    LANGUAGES C ASM
)

# Generate compile_commands.json for IDE code analysis
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find host compiler (needed when CMake is configured with cross-compiler)
include(FindHostCompiler)

# ============================================================================
# Build Options
# ============================================================================

option(KP_BUILD_KPTOOLS "Build kptools (host patching utility)" ON)
option(KP_BUILD_KPIMG "Build kpimg (kernel-level component)" ON)
option(KP_BUILD_KPMS "Build KPM demo modules" ON)
option(KP_ANDROID "Enable Android-specific features" OFF)
option(KP_DEBUG "Enable debug mode" OFF)
option(KP_MAP_DEBUG "Enable map debugging" OFF)

# ============================================================================
# Platform Detection
# ============================================================================

if(WIN32)
    set(KP_PLATFORM "Windows")
    set(KP_EXE_SUFFIX ".exe")
    set(KP_SHELL_PREFIX "cmd" "/c")
elseif(APPLE)
    set(KP_PLATFORM "macOS")
    set(KP_EXE_SUFFIX "")
    set(KP_SHELL_PREFIX "")
else()
    set(KP_PLATFORM "Linux")
    set(KP_EXE_SUFFIX "")
    set(KP_SHELL_PREFIX "")
endif()

message(STATUS "=== KernelPatch Build Configuration ===")
message(STATUS "Platform: ${KP_PLATFORM}")
message(STATUS "Version: ${PROJECT_VERSION}")

# ============================================================================
# Cross-Compiler Configuration for kpimg and KPMs
# ============================================================================

# Try to find the cross-compiler
# Users can override by setting TARGET_COMPILE environment variable or CMake variable
if(NOT DEFINED TARGET_COMPILE)
    if(DEFINED ENV{TARGET_COMPILE})
        set(TARGET_COMPILE "$ENV{TARGET_COMPILE}")
    else()
        # Try to find aarch64-none-elf-gcc in common locations
        find_program(AARCH64_GCC
            NAMES aarch64-none-elf-gcc aarch64-elf-gcc
            HINTS
                "$ENV{HOME}/Downloads/arm-gnu-toolchain-14.3.rel1-x86_64-aarch64-none-elf/bin"
                "$ENV{HOME}/arm-gnu-toolchain/bin"
                "/opt/arm-gnu-toolchain/bin"
                "/usr/local/bin"
                "/usr/bin"
            PATH_SUFFIXES bin
        )
        if(AARCH64_GCC)
            get_filename_component(AARCH64_GCC_DIR "${AARCH64_GCC}" DIRECTORY)
            # Extract prefix (e.g., "aarch64-none-elf-")
            get_filename_component(AARCH64_GCC_NAME "${AARCH64_GCC}" NAME)
            string(REGEX REPLACE "gcc$" "" TARGET_COMPILE "${AARCH64_GCC_DIR}/${AARCH64_GCC_NAME}")
        endif()
    endif()
endif()

# Validate cross-compiler
if(TARGET_COMPILE)
    set(KP_CROSS_CC "${TARGET_COMPILE}gcc${KP_EXE_SUFFIX}")
    set(KP_CROSS_LD "${TARGET_COMPILE}ld${KP_EXE_SUFFIX}")
    set(KP_CROSS_AS "${TARGET_COMPILE}as${KP_EXE_SUFFIX}")
    set(KP_CROSS_OBJCOPY "${TARGET_COMPILE}objcopy${KP_EXE_SUFFIX}")

    if(EXISTS "${KP_CROSS_CC}" OR KP_CROSS_CC MATCHES "aarch64")
        set(KP_HAVE_CROSS_COMPILER TRUE)
        message(STATUS "Cross-compiler prefix: ${TARGET_COMPILE}")
    else()
        # Try without full path (might be in PATH)
        find_program(KP_CROSS_CC_FOUND NAMES "${KP_CROSS_CC}" "aarch64-none-elf-gcc")
        if(KP_CROSS_CC_FOUND)
            set(KP_HAVE_CROSS_COMPILER TRUE)
            message(STATUS "Cross-compiler found: ${KP_CROSS_CC_FOUND}")
        else()
            set(KP_HAVE_CROSS_COMPILER FALSE)
            message(WARNING "Cross-compiler not found at: ${KP_CROSS_CC}")
        endif()
    endif()
else()
    set(KP_HAVE_CROSS_COMPILER FALSE)
    message(WARNING "TARGET_COMPILE not set. Set it to build kpimg and KPMs.")
    message(WARNING "Example: cmake -DTARGET_COMPILE=/path/to/aarch64-none-elf-")
endif()

# ============================================================================
# Common Definitions
# ============================================================================

# Read version from version file
if(EXISTS "${CMAKE_SOURCE_DIR}/version")
    file(READ "${CMAKE_SOURCE_DIR}/version" VERSION_CONTENT)
    string(REGEX MATCH "MAJOR=([0-9]+)" _ ${VERSION_CONTENT})
    set(KP_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "MINOR=([0-9]+)" _ ${VERSION_CONTENT})
    set(KP_VERSION_MINOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "PATCH=([0-9]+)" _ ${VERSION_CONTENT})
    set(KP_VERSION_PATCH ${CMAKE_MATCH_1})
    message(STATUS "KernelPatch Version: ${KP_VERSION_MAJOR}.${KP_VERSION_MINOR}.${KP_VERSION_PATCH}")
endif()

# Global include directories for IDE integration
set(KP_KERNEL_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/kernel
    ${CMAKE_SOURCE_DIR}/kernel/include
    ${CMAKE_SOURCE_DIR}/kernel/patch/include
    ${CMAKE_SOURCE_DIR}/kernel/linux
    ${CMAKE_SOURCE_DIR}/kernel/linux/include
    ${CMAKE_SOURCE_DIR}/kernel/linux/arch/arm64/include
    ${CMAKE_SOURCE_DIR}/kernel/linux/tools/arch/arm64/include
)

set(KP_TOOLS_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/tools
    ${CMAKE_SOURCE_DIR}/tools/elf
)

set(KP_USER_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/user
)

# ============================================================================
# Output Directories
# ============================================================================

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Create output directories
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/kpimg)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/kpms)

# ============================================================================
# Subdirectories
# ============================================================================

# kptools - Host tool (built with system compiler, C++17)
if(KP_BUILD_KPTOOLS)
    message(STATUS "Configuring kptools...")
    # Enable CXX language for kptools
    enable_language(CXX)
    # Pass Android flag to kptools
    if(KP_ANDROID)
        set(KPTOOLS_ANDROID ON CACHE BOOL "Build kptools for Android" FORCE)
    endif()
    add_subdirectory(tools)
endif()

# kpimg - Kernel component (requires cross-compiler)
if(KP_BUILD_KPIMG AND KP_HAVE_CROSS_COMPILER)
    message(STATUS "Configuring kpimg...")
    add_subdirectory(kernel)
endif()

# KPM modules (requires cross-compiler)
if(KP_BUILD_KPMS AND KP_HAVE_CROSS_COMPILER)
    message(STATUS "Configuring KPM modules...")
    add_subdirectory(kpms)
endif()

# ============================================================================
# IDE Integration - Source Grouping for all sources
# ============================================================================

# Collect all source files for IDE indexing
file(GLOB_RECURSE ALL_KERNEL_SOURCES
    "${CMAKE_SOURCE_DIR}/kernel/*.c"
    "${CMAKE_SOURCE_DIR}/kernel/*.h"
    "${CMAKE_SOURCE_DIR}/kernel/*.S"
)

file(GLOB_RECURSE ALL_TOOLS_SOURCES
    "${CMAKE_SOURCE_DIR}/tools/*.c"
    "${CMAKE_SOURCE_DIR}/tools/*.h"
)

file(GLOB_RECURSE ALL_USER_SOURCES
    "${CMAKE_SOURCE_DIR}/user/*.c"
    "${CMAKE_SOURCE_DIR}/user/*.h"
)

file(GLOB_RECURSE ALL_KPM_SOURCES
    "${CMAKE_SOURCE_DIR}/kpms/*.c"
    "${CMAKE_SOURCE_DIR}/kpms/*.h"
)

# Create a dummy target for IDE indexing of all sources
add_library(kp_ide_helper INTERFACE)
target_sources(kp_ide_helper INTERFACE
    ${ALL_KERNEL_SOURCES}
    ${ALL_TOOLS_SOURCES}
    ${ALL_USER_SOURCES}
    ${ALL_KPM_SOURCES}
)
target_include_directories(kp_ide_helper INTERFACE
    ${KP_KERNEL_INCLUDE_DIRS}
    ${KP_TOOLS_INCLUDE_DIRS}
    ${KP_USER_INCLUDE_DIRS}
)

# IDE source grouping
source_group(TREE ${CMAKE_SOURCE_DIR}/kernel PREFIX "kernel" FILES ${ALL_KERNEL_SOURCES})
source_group(TREE ${CMAKE_SOURCE_DIR}/tools PREFIX "tools" FILES ${ALL_TOOLS_SOURCES})
source_group(TREE ${CMAKE_SOURCE_DIR}/user PREFIX "user" FILES ${ALL_USER_SOURCES})
source_group(TREE ${CMAKE_SOURCE_DIR}/kpms PREFIX "kpms" FILES ${ALL_KPM_SOURCES})

# ============================================================================
# Top-Level Build Targets
# ============================================================================

# Build all target
add_custom_target(build_all
    COMMENT "Building all KernelPatch components..."
)

if(TARGET kptools)
    add_dependencies(build_all kptools)
endif()

if(TARGET kpimg_Build)
    add_dependencies(build_all kpimg_Build)
endif()

if(TARGET kpms_Build)
    add_dependencies(build_all kpms_Build)
endif()

# Clean all target
add_custom_target(clean_all
    COMMAND ${CMAKE_COMMAND} -E echo "Cleaning all build artifacts..."
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/kpimg
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/kpms
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/bin
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/kpimg
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/kpms
    COMMENT "Cleaned all build artifacts"
)

# ============================================================================
# Installation
# ============================================================================

install(DIRECTORY ${CMAKE_BINARY_DIR}/bin/
    DESTINATION bin
    USE_SOURCE_PERMISSIONS
    PATTERN "*"
)

# ============================================================================
# Summary
# ============================================================================

message(STATUS "")
message(STATUS "=== Build Configuration Summary ===")
message(STATUS "  Build kptools:        ${KP_BUILD_KPTOOLS}")
message(STATUS "  Build kpimg:          ${KP_BUILD_KPIMG}")
message(STATUS "  Build KPMs:           ${KP_BUILD_KPMS}")
message(STATUS "  Android support:      ${KP_ANDROID}")
message(STATUS "  Debug mode:           ${KP_DEBUG}")
message(STATUS "  Cross-compiler:       ${KP_HAVE_CROSS_COMPILER}")
if(KP_HAVE_CROSS_COMPILER)
    message(STATUS "  Cross-compiler path:  ${TARGET_COMPILE}")
endif()
message(STATUS "")
message(STATUS "Build targets:")
message(STATUS "  kptools               - Build C++17 host patching utility")
message(STATUS "  kptools_Build         - Build kptools")
message(STATUS "  kptools_Push          - Push kptools to device")
message(STATUS "  kptools_BuildAndPush  - Build and push kptools")
if(KP_HAVE_CROSS_COMPILER)
    message(STATUS "  kpimg_Build           - Build kernel component")
    message(STATUS "  kpimg_Push            - Push kpimg to device")
    message(STATUS "  kpimg_BuildAndPush    - Build and push kpimg")
    message(STATUS "  kpms_Build            - Build all KPM modules")
    message(STATUS "  kpms_Push             - Push all KPMs to device")
    message(STATUS "  kpms_BuildAndPush     - Build and push all KPMs")
endif()
message(STATUS "  build_all             - Build everything")
message(STATUS "")