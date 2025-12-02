/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 KernelPatch
 * kpm-sampolicy - Samsung Policy Module
 *
 * This module hooks __request_module to block loading of exynos-s2mpu driver
 * and hooks verity_handle_err_hex_debug to prevent dm-verity panics.
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
KPM_DESCRIPTION("Samsung policy module - blocks exynos-s2mpu loading and dm-verity panics");

#define MODULE_NAME_LEN 64
#define BLOCKED_MODULE "exynos-s2mpu"

static void *request_module_func = NULL;
static void *verity_handle_err_func = NULL;

/*
 * Hook for __request_module
 * int __request_module(bool wait, const char *fmt, ...)
 *
 * We hook before execution to check the module name.
 * Since it's variadic, the first vararg (module name) is typically in arg2 (after wait and fmt).
 * However, since fmt is usually "%s" and the module name is arg2, we check there.
 *
 * Looking at the function: after vsnprintf, module_name contains the actual name.
 * We intercept before and check if fmt contains our blocked module or if it's a simple "%s" call.
 */
static void before_request_module(hook_fargs4_t *args, void *udata)
{
    /* arg0 = wait (bool)
     * arg1 = fmt (const char *)
     * arg2 = first vararg (usually module name if fmt is "%s")
     */
    const char *fmt = (const char *)args->arg1;
    const char *modname = (const char *)args->arg2;

    if (!fmt) {
        return;
    }

    /* Check if the format string itself contains the blocked module name */
    if (strstr(fmt, BLOCKED_MODULE)) {
        pr_info("kpm-sampolicy: blocking module request (in fmt): %s\n", fmt);
        args->skip_origin = 1;
        args->ret = 0;  /* Return success but don't actually load */
        return;
    }

    /* If fmt is "%s" or similar, check the actual module name argument */
    if (modname && strstr(modname, BLOCKED_MODULE)) {
        pr_info("kpm-sampolicy: blocking module request: %s\n", modname);
        args->skip_origin = 1;
        args->ret = 0;  /* Return success but don't actually load */
        return;
    }
}

/*
 * Hook for verity_handle_err_hex_debug
 * Force it to return 0 always to prevent dm-verity panics
 *
 * The function signature has many arguments, we use hook_wrap4 since
 * the main arguments are: (struct dm_verity *v, enum verity_block_type type,
 *                          unsigned long long block, struct dm_verity_io *io, ...)
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

    /* Look up __request_module */
    request_module_func = (void *)kallsyms_lookup_name("__request_module");
    if (!request_module_func) {
        pr_err("kpm-sampolicy: failed to find __request_module\n");
        return -1;
    }
    pr_info("kpm-sampolicy: found __request_module at %px\n", request_module_func);

    /* Hook __request_module with 4 args (wait, fmt, varargs...)
     * We use 4 to capture the first vararg */
    err = hook_wrap4(request_module_func, before_request_module, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        pr_err("kpm-sampolicy: failed to hook __request_module: %d\n", err);
        return -1;
    }
    pr_info("kpm-sampolicy: hooked __request_module successfully\n");

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
            /* Continue anyway - __request_module hook is more important */
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

    /* Unhook __request_module */
    if (request_module_func) {
        hook_unwrap(request_module_func, before_request_module, NULL);
        pr_info("kpm-sampolicy: unhooked __request_module\n");
    }

    /* Unhook verity_handle_err_hex_debug */
    if (verity_handle_err_func) {
        hook_unwrap(verity_handle_err_func, before_verity_handle_err, NULL);
        pr_info("kpm-sampolicy: unhooked verity_handle_err_hex_debug\n");
    }

    pr_info("kpm-sampolicy: exit complete\n");
    return 0;
}

KPM_INIT(sampolicy_init);
KPM_CTL0(sampolicy_control0);
KPM_EXIT(sampolicy_exit);
