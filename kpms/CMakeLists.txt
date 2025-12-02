# ============================================================================
# KernelPatch - kpms/CMakeLists.txt
# Build configuration for KernelPatch Modules (KPMs)
# ============================================================================

cmake_minimum_required(VERSION 3.20)

# ============================================================================
# Common KPM Configuration
# ============================================================================

# Include directories for KPMs (from kernel)
set(KPM_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/kernel
    ${CMAKE_SOURCE_DIR}/kernel/include
    ${CMAKE_SOURCE_DIR}/kernel/patch/include
    ${CMAKE_SOURCE_DIR}/kernel/linux
    ${CMAKE_SOURCE_DIR}/kernel/linux/include
    ${CMAKE_SOURCE_DIR}/kernel/linux/arch/arm64/include
    ${CMAKE_SOURCE_DIR}/kernel/linux/tools/arch/arm64/include
)

# Build include flags as a list (for proper argument expansion)
set(KPM_INCLUDE_FLAGS "")
foreach(dir ${KPM_INCLUDE_DIRS})
    list(APPEND KPM_INCLUDE_FLAGS "-I${dir}")
endforeach()

# Common compiler flags for KPMs (as lists for proper argument expansion)
set(KPM_COMMON_FLAGS -Wall -fno-builtin -std=gnu11 -nostdinc -mgeneral-regs-only -O2)

if(KP_DEBUG)
    list(APPEND KPM_COMMON_FLAGS -DDEBUG -g)
endif()

if(KP_ANDROID)
    list(APPEND KPM_COMMON_FLAGS -DANDROID)
endif()

# Output directory
set(KPM_OUTPUT_DIR ${CMAKE_BINARY_DIR}/kpms)
set(KPM_OBJ_DIR ${KPM_OUTPUT_DIR}/obj)
file(MAKE_DIRECTORY ${KPM_OUTPUT_DIR})
file(MAKE_DIRECTORY ${KPM_OBJ_DIR})

# ============================================================================
# Function to add a KPM module
# ============================================================================

function(add_kpm_module MODULE_NAME)
    set(options)
    set(oneValueArgs)
    set(multiValueArgs SOURCES)
    cmake_parse_arguments(KPM "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    set(MODULE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${MODULE_NAME})
    set(MODULE_OBJ_DIR ${KPM_OBJ_DIR}/${MODULE_NAME})
    set(MODULE_OUTPUT ${KPM_OUTPUT_DIR}/${MODULE_NAME}.kpm)

    file(MAKE_DIRECTORY ${MODULE_OBJ_DIR})

    # Collect source files if not specified
    if(NOT KPM_SOURCES)
        file(GLOB KPM_SOURCES "${MODULE_DIR}/*.c")
    endif()

    # Collect headers for IDE
    file(GLOB MODULE_HEADERS "${MODULE_DIR}/*.h")

    # Create objects list
    set(MODULE_OBJECTS "")

    foreach(source ${KPM_SOURCES})
        get_filename_component(source_name ${source} NAME_WE)
        set(obj_file "${MODULE_OBJ_DIR}/${source_name}.o")
        list(APPEND MODULE_OBJECTS ${obj_file})

        # Compile command
        add_custom_command(
            OUTPUT ${obj_file}
            COMMAND ${KP_CROSS_CC} ${KPM_COMMON_FLAGS} ${KPM_INCLUDE_FLAGS} -c -o ${obj_file} ${source}
            DEPENDS ${source}
            COMMENT "[kpms] Compiling ${MODULE_NAME}/${source_name}.c"
            VERBATIM
        )
    endforeach()

    # Link command (relocatable)
    add_custom_command(
        OUTPUT ${MODULE_OUTPUT}
        COMMAND ${KP_CROSS_CC} -r -o ${MODULE_OUTPUT} ${MODULE_OBJECTS}
        DEPENDS ${MODULE_OBJECTS}
        COMMENT "[kpms] Linking ${MODULE_NAME}.kpm"
        VERBATIM
    )

    # Build target
    add_custom_target(kpm_${MODULE_NAME}
        DEPENDS ${MODULE_OUTPUT}
        COMMENT "[kpms] ${MODULE_NAME}.kpm build complete"
    )

    # IDE integration
    add_library(kpm_${MODULE_NAME}_sources INTERFACE)
    target_sources(kpm_${MODULE_NAME}_sources INTERFACE
        ${KPM_SOURCES}
        ${MODULE_HEADERS}
    )
    target_include_directories(kpm_${MODULE_NAME}_sources INTERFACE
        ${MODULE_DIR}
        ${KPM_INCLUDE_DIRS}
    )
    target_compile_definitions(kpm_${MODULE_NAME}_sources INTERFACE
        __KERNEL__
        __aarch64__
        $<$<BOOL:${KP_ANDROID}>:ANDROID>
    )

    # Add to parent scope list
    set(KPM_ALL_TARGETS ${KPM_ALL_TARGETS} kpm_${MODULE_NAME} PARENT_SCOPE)
endfunction()

# ============================================================================
# Define KPM Modules
# ============================================================================

set(KPM_ALL_TARGETS "")

# demo-hello module
add_kpm_module(demo-hello
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/demo-hello/hello.c
)

# demo-inlinehook module
add_kpm_module(demo-inlinehook
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/demo-inlinehook/inlinehook.c
)

# demo-syscallhook module
add_kpm_module(demo-syscallhook
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/demo-syscallhook/syscallhook.c
)

# kpm-sampolicy module
add_kpm_module(kpm-sampolicy
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/kpm-sampolicy/sampolicy.c
)

# ============================================================================
# All Modules Target
# ============================================================================

add_custom_target(kpms_Build
    DEPENDS ${KPM_ALL_TARGETS}
    COMMENT "[kpms] All modules built"
)

# ============================================================================
# Clean Target
# ============================================================================

add_custom_target(kpms_Clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${KPM_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${KPM_OUTPUT_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${KPM_OBJ_DIR}
    COMMENT "[kpms] Cleaned all KPM modules"
)

# ============================================================================
# Rebuild Target
# ============================================================================

add_custom_target(kpms_Rebuild
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kpms_Clean
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kpms_Build
    COMMENT "[kpms] Rebuilding all modules..."
)

# ============================================================================
# ADB Push Targets
# ============================================================================

# Push all modules to device
add_custom_target(kpms_Push
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-hello.kpm /data/local/tmp/
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-inlinehook.kpm /data/local/tmp/
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-syscallhook.kpm /data/local/tmp/
    COMMAND adb push ${KPM_OUTPUT_DIR}/kpm-sampolicy.kpm /data/local/tmp/
    COMMENT "[kpms] Pushing all modules to /data/local/tmp/"
)

# Build and push all modules
add_custom_target(kpms_BuildAndPush
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target kpms_Build
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-hello.kpm /data/local/tmp/
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-inlinehook.kpm /data/local/tmp/
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-syscallhook.kpm /data/local/tmp/
    COMMAND adb push ${KPM_OUTPUT_DIR}/kpm-sampolicy.kpm /data/local/tmp/
    COMMENT "[kpms] Building and pushing all modules..."
)

# ============================================================================
# Individual Module Push Targets
# ============================================================================

# demo-hello
add_custom_target(kpm_hello_Push
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-hello.kpm /data/local/tmp/
    COMMENT "[kpms] Pushing demo-hello.kpm"
)

add_custom_target(kpm_hello_BuildAndPush
    DEPENDS kpm_demo-hello
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-hello.kpm /data/local/tmp/
    COMMENT "[kpms] Building and pushing demo-hello.kpm"
)

# demo-inlinehook
add_custom_target(kpm_inlinehook_Push
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-inlinehook.kpm /data/local/tmp/
    COMMENT "[kpms] Pushing demo-inlinehook.kpm"
)

add_custom_target(kpm_inlinehook_BuildAndPush
    DEPENDS kpm_demo-inlinehook
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-inlinehook.kpm /data/local/tmp/
    COMMENT "[kpms] Building and pushing demo-inlinehook.kpm"
)

# demo-syscallhook
add_custom_target(kpm_syscallhook_Push
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-syscallhook.kpm /data/local/tmp/
    COMMENT "[kpms] Pushing demo-syscallhook.kpm"
)

add_custom_target(kpm_syscallhook_BuildAndPush
    DEPENDS kpm_demo-syscallhook
    COMMAND adb push ${KPM_OUTPUT_DIR}/demo-syscallhook.kpm /data/local/tmp/
    COMMENT "[kpms] Building and pushing demo-syscallhook.kpm"
)

# kpm-sampolicy
add_custom_target(kpm_sampolicy_Push
    COMMAND adb push ${KPM_OUTPUT_DIR}/kpm-sampolicy.kpm /data/local/tmp/
    COMMENT "[kpms] Pushing kpm-sampolicy.kpm"
)

add_custom_target(kpm_sampolicy_BuildAndPush
    DEPENDS kpm_kpm-sampolicy
    COMMAND adb push ${KPM_OUTPUT_DIR}/kpm-sampolicy.kpm /data/local/tmp/
    COMMENT "[kpms] Building and pushing kpm-sampolicy.kpm"
)

# ============================================================================
# IDE Integration - Collect all KPM sources
# ============================================================================

file(GLOB_RECURSE ALL_KPM_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
)

add_library(kpms_sources INTERFACE)
target_sources(kpms_sources INTERFACE ${ALL_KPM_SOURCES})
target_include_directories(kpms_sources INTERFACE ${KPM_INCLUDE_DIRS})
target_compile_definitions(kpms_sources INTERFACE
    __KERNEL__
    __aarch64__
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} PREFIX "kpms" FILES ${ALL_KPM_SOURCES})