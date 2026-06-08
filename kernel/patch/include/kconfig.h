/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef _KP_KCONFIG_H_
#define _KP_KCONFIG_H_

#include <stdbool.h>

// todo: move config to here

extern bool has_config_compat;

extern const void *kp_kconfig_data;
extern unsigned long kp_kconfig_data_size;

void kpm_kconfig_init(void);

#endif
