/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 mhmrdd. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>

KPM_NAME("kpm-kconfig-demo");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("mhmrdd");
KPM_DESCRIPTION("KernelPatch Module kernel config resolution example");

static void dump_kconfig(const char *tag)
{
    const char *lv = KPM_KCONFIG_GET(CONFIG_LOCALVERSION);
    long hz = 0;

    pr_info("kpm kconfig [%s] CONFIG_KALLSYMS bool=%d tristate=%d\n", tag, KPM_KCONFIG_BOOL(CONFIG_KALLSYMS),
            KPM_KCONFIG_TRISTATE(CONFIG_KALLSYMS));
    if (KPM_KCONFIG_INT(CONFIG_HZ, &hz)) pr_info("kpm kconfig [%s] CONFIG_HZ=%ld\n", tag, hz);
    pr_info("kpm kconfig [%s] CONFIG_LOCALVERSION=%s\n", tag, lv ? lv : "(unset)");
}

static long kconfig_demo_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm kconfig-demo init, event: %s, args: %s\n", event, args);
    dump_kconfig("init");
    return 0;
}

static long kconfig_demo_control0(const char *args, char *__user out_msg, int outlen)
{
    dump_kconfig("ctl0");
    return 0;
}

static long kconfig_demo_exit(void *__user reserved)
{
    dump_kconfig("exit");
    pr_info("kpm kconfig-demo exit\n");
    return 0;
}

KPM_INIT(kconfig_demo_init);
KPM_CTL0(kconfig_demo_control0);
KPM_EXIT(kconfig_demo_exit);
