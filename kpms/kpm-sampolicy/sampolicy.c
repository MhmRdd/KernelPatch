/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 KernelPatch
 * kpm-sampolicy - Samsung Policy Module
 *
 * This module hooks do_init_module and do_one_initcall to block initialization
 * of exynos-s2mpu driver, and hooks verity_handle_err_hex_debug to prevent
 * dm-verity panics.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kallsyms.h>

KPM_NAME("kpm-sampolicy");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("KernelPatch");
KPM_DESCRIPTION("Samsung policy module - blocks exynos-s2mpu init and dm-verity panics");

#define MODULE_NAME_LEN 56
#define BLOCKED_MODULE "exynos-s2mpu"

/*
 * Search range for finding init pointer in struct module.
 *
 * Calculated offset to init field on ARM64 (Samsung kernel config):
 *   - enum module_state state          : 4 + 4 padding = 8
 *   - struct list_head list            : 16
 *   - char name[56]                    : 56
 *   - struct module_kobject mkobj      : ~88 (kobject ~64 + ptrs)
 *   - module_attribute *modinfo_attrs  : 8
 *   - const char *version              : 8
 *   - const char *srcversion           : 8
 *   - struct kobject *holders_dir      : 8
 *   - const struct kernel_symbol *syms : 8
 *   - const s32 *crcs                  : 8
 *   - unsigned int num_syms            : 4 + 4 padding
 *   - struct mutex param_lock (SYSFS=y): ~40
 *   - struct kernel_param *kp          : 8
 *   - unsigned int num_kp              : 4 + 4 padding
 *   - unsigned int num_gpl_syms        : 4
 *   - const struct kernel_symbol *gpl_syms : 8
 *   - const s32 *gpl_crcs              : 8
 *   - bool using_gplonly_symbols       : 1 + 7 padding
 *   - bool async_probe_requested       : 1 + 7 padding
 *   - const struct kernel_symbol *gpl_future_syms : 8
 *   - const s32 *gpl_future_crcs       : 8
 *   - unsigned int num_gpl_future_syms : 4 + 4 padding
 *   - unsigned int num_exentries       : 4 + 4 padding
 *   - struct exception_table_entry *extable : 8
 *   - int (*init)(void)                : 8  <-- TARGET
 *
 * Estimated offset: ~350-400 bytes. Use 512 for safety margin.
 * CONFIG_UNUSED_SYMBOLS=n, CONFIG_MODULE_SIG=n on this kernel.
 */
#define MODULE_STRUCT_SEARCH_SIZE 512

static void *do_init_module_func = NULL;
static void *do_one_initcall_func = NULL;
static void *verity_handle_err_func = NULL;

/* Cached module pointer when we detect exynos-s2mpu in do_init_module */
static void *cached_s2mpu_module = NULL;

/*
 * Stub function to replace exynos-s2mpu init
 * Simply returns 0 (success) without doing anything
 */
static int stub_init(void)
{
    pr_info("kpm-sampolicy: stub_init called for exynos-s2mpu, returning 0\n");
    return 0;
}

/*
 * Search for a function pointer value within a memory region
 * Returns 1 if found, 0 otherwise
 */
static int search_ptr_in_struct(void *struct_ptr, size_t search_size, void *target_ptr)
{
    uint64_t *search = (uint64_t *)struct_ptr;
    size_t count = search_size / sizeof(uint64_t);

    for (size_t i = 0; i < count; i++) {
        if (search[i] == (uint64_t)target_ptr) {
            return 1;
        }
    }
    return 0;
}

/*
 * Hook for do_init_module
 * static noinline int do_init_module(struct module *mod)
 *
 * We check if the module being initialized is exynos-s2mpu by looking up
 * the module name. The name field is at offset after state and list_head.
 *
 * struct module layout (partial):
 *   enum module_state state;      // 4 bytes
 *   struct list_head list;        // 16 bytes (2 pointers)
 *   char name[MODULE_NAME_LEN];   // starts around offset 20-24 (with padding)
 */
static void before_do_init_module(hook_fargs1_t *args, void *udata)
{
    void *mod = (void *)args->arg0;
    const char *mod_name;

    if (!mod) {
        return;
    }

    /*
     * Try to get module name - it's located after:
     * - enum module_state (4 bytes, but likely padded to 8)
     * - struct list_head (16 bytes = 2 pointers)
     * So name starts around offset 24 on 64-bit
     */
    mod_name = (const char *)((uint64_t)mod + 24);

    /* Verify it looks like a valid string */
    if ((uint64_t)mod_name < 0xFFFF000000000000ULL) {
        return;
    }

    /* Check if this is the blocked module */
    if (strncmp(mod_name, BLOCKED_MODULE, sizeof(BLOCKED_MODULE) - 1) == 0) {
        pr_info("kpm-sampolicy: do_init_module detected module: %s\n", mod_name);
        pr_info("kpm-sampolicy: caching module struct at %px\n", mod);
        cached_s2mpu_module = mod;
    }
}

/*
 * Hook for do_one_initcall
 * int __init_or_module do_one_initcall(initcall_t fn)
 *
 * This is called when mod->init is executed: ret = do_one_initcall(mod->init);
 * We check if the fn pointer exists within our cached module struct,
 * and if so, replace it with our stub.
 */
static void before_do_one_initcall(hook_fargs1_t *args, void *udata)
{
    void *fn = (void *)args->arg0;

    if (!fn || !cached_s2mpu_module) {
        return;
    }

    /*
     * Search for this function pointer within the cached module struct.
     * If found, it means this is the init function of exynos-s2mpu.
     */
    if (search_ptr_in_struct(cached_s2mpu_module, MODULE_STRUCT_SEARCH_SIZE, fn)) {
        pr_info("kpm-sampolicy: found init function %px in cached exynos-s2mpu module\n", fn);
        pr_info("kpm-sampolicy: replacing with stub_init\n");

        /* Replace the function pointer with our stub */
        args->arg0 = (uint64_t)stub_init;

        /* Clear the cache since we've handled this module */
        cached_s2mpu_module = NULL;
    }
}

/*
 * Hook for verity_handle_err_hex_debug
 * Force it to return 0 always to prevent dm-verity panics
 */
static void before_verity_handle_err(hook_fargs4_t *args, void *udata)
{
    pr_info("kpm-sampolicy: intercepting verity_handle_err_hex_debug, forcing return 0\n");
    args->skip_origin = 1;
    args->ret = 0;
}

static long sampolicy_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;

    pr_info("kpm-sampolicy: initializing, event: %s, args: %s\n",
            event ? event : "none", args ? args : "none");

    /* Look up do_init_module */
    do_init_module_func = (void *)kallsyms_lookup_name("do_init_module");
    if (!do_init_module_func) {
        pr_err("kpm-sampolicy: failed to find do_init_module\n");
        return -1;
    }
    pr_info("kpm-sampolicy: found do_init_module at %px\n", do_init_module_func);

    /* Hook do_init_module with 1 arg (struct module *mod) */
    err = hook_wrap1(do_init_module_func, before_do_init_module, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("kpm-sampolicy: failed to hook do_init_module: %d\n", err);
        return -1;
    }
    pr_info("kpm-sampolicy: hooked do_init_module successfully\n");

    /* Look up do_one_initcall */
    do_one_initcall_func = (void *)kallsyms_lookup_name("do_one_initcall");
    if (!do_one_initcall_func) {
        pr_err("kpm-sampolicy: failed to find do_one_initcall\n");
        /* Unhook do_init_module before returning */
        hook_unwrap(do_init_module_func, before_do_init_module, NULL);
        return -1;
    }
    pr_info("kpm-sampolicy: found do_one_initcall at %px\n", do_one_initcall_func);

    /* Hook do_one_initcall with 1 arg (initcall_t fn) */
    err = hook_wrap1(do_one_initcall_func, before_do_one_initcall, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("kpm-sampolicy: failed to hook do_one_initcall: %d\n", err);
        hook_unwrap(do_init_module_func, before_do_init_module, NULL);
        return -1;
    }
    pr_info("kpm-sampolicy: hooked do_one_initcall successfully\n");

    /* Look up verity_handle_err_hex_debug */
    verity_handle_err_func = (void *)kallsyms_lookup_name("verity_handle_err_hex_debug");
    if (!verity_handle_err_func) {
        pr_warn("kpm-sampolicy: verity_handle_err_hex_debug not found (may not exist on this kernel)\n");
        /* Not fatal - the function may not exist on all kernels */
    } else {
        pr_info("kpm-sampolicy: found verity_handle_err_hex_debug at %px\n", verity_handle_err_func);

        /* Hook with 4 args - captures main parameters */
        err = hook_wrap4(verity_handle_err_func, before_verity_handle_err, NULL, NULL);
        if (err != HOOK_NO_ERR) {
            pr_err("kpm-sampolicy: failed to hook verity_handle_err_hex_debug: %d\n", err);
            /* Continue anyway - module hooks are more important */
        } else {
            pr_info("kpm-sampolicy: hooked verity_handle_err_hex_debug successfully\n");
        }
    }

    pr_info("kpm-sampolicy: initialization complete\n");
    return 0;
}

static long sampolicy_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm-sampolicy: control called with args: %s\n", args ? args : "none");
    return 0;
}

static long sampolicy_exit(void *__user reserved)
{
    pr_info("kpm-sampolicy: exiting\n");

    /* Unhook do_init_module */
    if (do_init_module_func) {
        hook_unwrap(do_init_module_func, before_do_init_module, NULL);
        pr_info("kpm-sampolicy: unhooked do_init_module\n");
    }

    /* Unhook do_one_initcall */
    if (do_one_initcall_func) {
        hook_unwrap(do_one_initcall_func, before_do_one_initcall, NULL);
        pr_info("kpm-sampolicy: unhooked do_one_initcall\n");
    }

    /* Unhook verity_handle_err_hex_debug */
    if (verity_handle_err_func) {
        hook_unwrap(verity_handle_err_func, before_verity_handle_err, NULL);
        pr_info("kpm-sampolicy: unhooked verity_handle_err_hex_debug\n");
    }

    /* Clear cached pointer */
    cached_s2mpu_module = NULL;

    pr_info("kpm-sampolicy: exit complete\n");
    return 0;
}

KPM_INIT(sampolicy_init);
KPM_CTL0(sampolicy_control0);
KPM_EXIT(sampolicy_exit);
