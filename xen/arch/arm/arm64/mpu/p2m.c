/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/bug.h>
#include <xen/init.h>
#include <asm/p2m.h>

void __init setup_virt_paging(void)
{
    BUG_ON("unimplemented");
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
