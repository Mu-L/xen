/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2024 Apertus Solutions, LLC
 * Author: Daniel P. Smith <dpsmith@apertussolutions.com>
 * Copyright (c) 2024 Christopher Clark <christopher.w.clark@gmail.com>
 */

#ifndef __XEN_X86_BOOTDOMAIN_H__
#define __XEN_X86_BOOTDOMAIN_H__

#include <public/xen.h>

struct boot_domain {
    domid_t domid;

    struct boot_module *kernel;
    struct boot_module *module;
    const char *cmdline;

    struct domain *d;
};

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
