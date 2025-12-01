# ============================================================================
# KernelPatch - kernel/CMakeLists.txt
# Build configuration for kpimg (kernel-level patching component)
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# ============================================================================
# Source Files
# ============================================================================

# Base sources (order matters for linker)
set(KPIMG_BASE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/base/setup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/setup1.S
    ${CMAKE_CURRENT_SOURCE_DIR}/base/cache.S
    ${CMAKE_CURRENT_SOURCE_DIR}/base/tlsf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/start.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/map.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/map1.S
    ${CMAKE_CURRENT_SOURCE_DIR}/base/hook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/fphook.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/hmem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/predata.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/symbol.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/baselib.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/base/hotpatch.c
)

# Patch sources
file(GLOB KPIMG_PATCH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/patch/*.c")
file(GLOB KPIMG_PATCH_COMMON_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/patch/common/*.c")
file(GLOB KPIMG_PATCH_MODULE_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/patch/module/*.c")
file(GLOB KPIMG_PATCH_KSYMS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/patch/ksyms/*.c")

# Android sources (conditional)
if(KP_ANDROID)
    file(GLOB KPIMG_PATCH_ANDROID_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/patch/android/*.c")
else()
    set(KPIMG_PATCH_ANDROID_SOURCES "")
endif()

# Combine all sources
set(KPIMG_ALL_SOURCES
    ${KPIMG_BASE_SOURCES}
    ${KPIMG_PATCH_SOURCES}
    ${KPIMG_PATCH_COMMON_SOURCES}
    ${KPIMG_PATCH_MODULE_SOURCES}
    ${KPIMG_PATCH_KSYMS_SOURCES}
    ${KPIMG_PATCH_ANDROID_SOURCES}
)

# ============================================================================
# Include Directories
# ============================================================================

set(KPIMG_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/patch/include
    ${CMAKE_CURRENT_SOURCE_DIR}/linux
    ${CMAKE_CURRENT_SOURCE_DIR}/linux/include
    ${CMAKE_CURRENT_SOURCE_DIR}/linux/arch/arm64/include
    ${CMAKE_CURRENT_SOURCE_DIR}/linux/tools/arch/arm64/include
)

# Build include flags as a list (for proper argument expansion)
set(KPIMG_INCLUDE_FLAGS "")
foreach(dir ${KPIMG_INCLUDE_DIRS})
    list(APPEND KPIMG_INCLUDE_FLAGS "-I${dir}")
endforeach()

# ============================================================================
# Compiler Flags (as lists for proper argument expansion)
# ============================================================================

set(KPIMG_COMMON_FLAGS -Wall -fno-builtin -std=gnu11 -nostdinc -mgeneral-regs-only -g)

if(KP_DEBUG)
    list(APPEND KPIMG_COMMON_FLAGS -DDEBUG -DMAP_DEBUG)
endif()

if(KP_ANDROID)
    list(APPEND KPIMG_COMMON_FLAGS -DANDROID)
endif()

set(KPIMG_C_FLAGS ${KPIMG_COMMON_FLAGS} -O2)
set(KPIMG_SHA256_FLAGS ${KPIMG_COMMON_FLAGS} -O0)  # SHA256 needs -O0
set(KPIMG_ASM_FLAGS ${KPIMG_COMMON_FLAGS})

# ============================================================================
# Output Paths
# ============================================================================

set(KPIMG_OUTPUT_DIR ${CMAKE_BINARY_DIR}/kpimg)
# Object files go directly under KPIMG_OUTPUT_DIR to match linker script paths
# (linker script references base/setup.o, patch/common/accctl.o, etc.)
set(KPIMG_OBJ_DIR ${KPIMG_OUTPUT_DIR})
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR})
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR}/base)
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR}/patch)
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR}/patch/common)
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR}/patch/module)
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR}/patch/ksyms)
file(MAKE_DIRECTORY ${KPIMG_OBJ_DIR}/patch/android)

# ============================================================================
# IDE Integration - Create a target for code indexing
# ============================================================================

# Collect all headers for IDE
file(GLOB_RECURSE KPIMG_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
)

# Create an INTERFACE library for IDE support
add_library(kpimg_sources INTERFACE)
target_sources(kpimg_sources INTERFACE
    ${KPIMG_ALL_SOURCES}
    ${KPIMG_HEADERS}
)
target_include_directories(kpimg_sources INTERFACE
    ${KPIMG_INCLUDE_DIRS}
)

# Add compile definitions for IDE
target_compile_definitions(kpimg_sources INTERFACE
    __KERNEL__
    __aarch64__
    $<$<BOOL:${KP_ANDROID}>:ANDROID>
    $<$<BOOL:${KP_DEBUG}>:DEBUG>
)

# ============================================================================
# Pre-build: Copy headers to tools and user directories
# ============================================================================

add_custom_target(kpimg_headers
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/patch/include/uapi
        ${CMAKE_SOURCE_DIR}/user/uapi
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/version
        ${CMAKE_SOURCE_DIR}/user/version
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_CURRENT_SOURCE_DIR}/include/preset.h
        ${CMAKE_SOURCE_DIR}/tools/preset.h
    COMMENT "[kpimg] Copying headers..."
)

# ============================================================================
# Object File Compilation Rules
# ============================================================================

set(KPIMG_OBJECTS "")
set(KPIMG_OBJECTS_REL "")  # Relative paths for linker

foreach(source ${KPIMG_ALL_SOURCES})
    # Get relative path from kernel directory
    file(RELATIVE_PATH rel_source ${CMAKE_CURRENT_SOURCE_DIR} ${source})

    # Create object file path
    get_filename_component(source_dir ${rel_source} DIRECTORY)
    get_filename_component(source_name ${rel_source} NAME_WE)
    get_filename_component(source_ext ${rel_source} EXT)

    set(obj_file "${KPIMG_OBJ_DIR}/${source_dir}/${source_name}.o")
    set(obj_file_rel "${source_dir}/${source_name}.o")
    list(APPEND KPIMG_OBJECTS ${obj_file})
    list(APPEND KPIMG_OBJECTS_REL ${obj_file_rel})

    # Determine flags based on source type and name
    if(source_ext STREQUAL ".S")
        set(compile_flags ${KPIMG_ASM_FLAGS})
    elseif(source_name STREQUAL "sha256")
        set(compile_flags ${KPIMG_SHA256_FLAGS})
    else()
        set(compile_flags ${KPIMG_C_FLAGS})
    endif()

    # Create compile command
    add_custom_command(
        OUTPUT ${obj_file}
        COMMAND ${KP_CROSS_CC} ${compile_flags} ${KPIMG_INCLUDE_FLAGS} -c -o ${obj_file} ${source}
        DEPENDS ${source}
        COMMENT "[kpimg] Compiling ${rel_source}"
        VERBATIM
    )
endforeach()

# ============================================================================
# Link and Create Binary
# ============================================================================

set(KPIMG_ELF ${KPIMG_OUTPUT_DIR}/kpimg.elf)
set(KPIMG_BIN ${KPIMG_OUTPUT_DIR}/kpimg)

# Link ELF (run from KPIMG_OUTPUT_DIR so linker script relative paths work)
# Pass object files with relative paths to match linker script expectations
add_custom_command(
    OUTPUT ${KPIMG_ELF}
    COMMAND ${KP_CROSS_LD} -nostdlib -static -no-pie
        -T${CMAKE_CURRENT_SOURCE_DIR}/kpimg.lds
        -o kpimg.elf
        ${KPIMG_OBJECTS_REL}
    DEPENDS ${KPIMG_OBJECTS}
    WORKING_DIRECTORY ${KPIMG_OUTPUT_DIR}
    COMMENT "[kpimg] Linking kpimg.elf"
    VERBATIM
)

# Create raw binary
add_custom_command(
    OUTPUT ${KPIMG_BIN}
    COMMAND ${KP_CROSS_OBJCOPY} -O binary -S ${KPIMG_ELF} ${KPIMG_BIN}
    DEPENDS ${KPIMG_ELF}
    COMMENT "[kpimg] Creating kpimg binary"
    VERBATIM
)

# Copy to bin directory
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/bin/kpimg
    COMMAND ${CMAKE_COMMAND} -E copy ${KPIMG_BIN} ${CMAKE_BINARY_DIR}/bin/kpimg
    DEPENDS ${KPIMG_BIN}
    COMMENT "[kpimg] Copying to bin directory"
)

# ============================================================================
# Build Targets
# ============================================================================

# Main build target
add_custom_target(kpimg_Build
    DEPENDS ${CMAKE_BINARY_DIR}/bin/kpimg
    COMMENT "[kpimg] Build complete"
)
add_dependencies(kpimg_Build kpimg_headers)

# Clean target
add_custom_target(kpimg_Clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${KPIMG_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${KPIMG_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${KPIMG_OBJ_DIR}
    COMMENT "[kpimg] Cleaned"
)

# Rebuild target
add_custom_target(kpimg_Rebuild
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kpimg_Clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kpimg_Build
    COMMENT "[kpimg] Rebuilding..."
)

# ============================================================================
# ADB Push Targets
# ============================================================================

# Push to device
add_custom_target(kpimg_Push
    COMMAND adb push ${CMAKE_BINARY_DIR}/bin/kpimg /data/local/tmp/kpimg
    COMMENT "[kpimg] Pushing to /data/local/tmp/kpimg"
)

# Build and push
add_custom_target(kpimg_BuildAndPush
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kpimg_Build
    COMMAND adb push ${CMAKE_BINARY_DIR}/bin/kpimg /data/local/tmp/kpimg
    COMMENT "[kpimg] Building and pushing..."
)