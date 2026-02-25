#ifndef XEN_LIB_X86_PRIVATE_H
#define XEN_LIB_X86_PRIVATE_H

#ifdef __XEN__

#include <xen/bitops.h>
#include <xen/guest_access.h>
#include <xen/kernel.h>
#include <xen/lib.h>
#include <xen/nospec.h>
#include <xen/types.h>

#include <asm/msr.h>

#else

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <xen/asm/msr-index.h>
#include <xen/asm/x86-vendors.h>

#include <xen-tools/common-macros.h>

static inline bool test_bit(unsigned int bit, const void *vaddr)
{
    const char *addr = vaddr;

    return addr[bit / 8] & (1u << (bit % 8));
}

#endif /* __XEN__ */

#endif /* XEN_LIB_X86_PRIVATE_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
