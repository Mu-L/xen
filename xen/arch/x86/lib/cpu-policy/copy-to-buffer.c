#ifdef __XEN__

#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/types.h>

#include <asm/msr-index.h>

#define copy_to_buffer_offset copy_to_guest_offset

#else /* !__XEN__ */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <xen/asm/msr-index.h>

#include <xen-tools/common-macros.h>

/* memcpy(), but with copy_to_guest_offset()'s API. */
#define copy_to_buffer_offset(dst, index, src, nr)      \
({                                                      \
    const typeof(*(src)) *src_ = (src);                 \
    typeof(*(dst)) *dst_ = (dst);                       \
    typeof(index) index_ = (index);                     \
    typeof(nr) nr_ = (nr), i_;                          \
                                                        \
    for ( i_ = 0; i_ < nr_; i_++ )                      \
        dst_[index_ + i_] = src_[i_];                   \
    0;                                                  \
})

#endif /* __XEN__ */

#include <xen/lib/x86/cpu-policy.h>

/*
 * Copy a single cpuid_leaf into a provided xen_cpuid_leaf_t buffer,
 * performing boundary checking against the buffer size.
 */
static int copy_leaf_to_buffer(uint32_t leaf, uint32_t subleaf,
                               const struct cpuid_leaf *data,
                               cpuid_leaf_buffer_t leaves,
                               uint32_t *curr_entry, const uint32_t nr_entries)
{
    const xen_cpuid_leaf_t val = {
        leaf, subleaf, data->a, data->b, data->c, data->d,
    };

    if ( *curr_entry == nr_entries )
        return -ENOBUFS;

    if ( copy_to_buffer_offset(leaves, *curr_entry, &val, 1) )
        return -EFAULT;

    ++*curr_entry;

    return 0;
}

int x86_cpuid_copy_to_buffer(const struct cpu_policy *p,
                             cpuid_leaf_buffer_t leaves, uint32_t *nr_entries_p)
{
    const uint32_t nr_entries = *nr_entries_p;
    uint32_t curr_entry = 0, leaf, subleaf;

#define COPY_LEAF(l, s, data)                                       \
    ({                                                              \
        int ret;                                                    \
                                                                    \
        if ( (ret = copy_leaf_to_buffer(                            \
                  l, s, data, leaves, &curr_entry, nr_entries)) )   \
            return ret;                                             \
    })

    /* Basic leaves. */
    for ( leaf = 0; leaf <= MIN(p->basic.max_leaf,
                                ARRAY_SIZE(p->basic.raw) - 1); ++leaf )
    {
        switch ( leaf )
        {
        case 0x4:
            for ( subleaf = 0; subleaf < ARRAY_SIZE(p->cache.raw); ++subleaf )
            {
                COPY_LEAF(leaf, subleaf, &p->cache.raw[subleaf]);

                if ( p->cache.subleaf[subleaf].type == 0 )
                    break;
            }
            break;

        case 0x7:
            for ( subleaf = 0;
                  subleaf <= MIN(p->feat.max_subleaf,
                                 ARRAY_SIZE(p->feat.raw) - 1); ++subleaf )
                COPY_LEAF(leaf, subleaf, &p->feat.raw[subleaf]);
            break;

        case 0xb:
            for ( subleaf = 0; subleaf < ARRAY_SIZE(p->topo.raw); ++subleaf )
            {
                COPY_LEAF(leaf, subleaf, &p->topo.raw[subleaf]);

                if ( p->topo.subleaf[subleaf].type == 0 )
                    break;
            }
            break;

        case 0xd:
        {
            uint64_t xstates = cpu_policy_xstates(p);

            COPY_LEAF(leaf, 0, &p->xstate.raw[0]);
            COPY_LEAF(leaf, 1, &p->xstate.raw[1]);

            for ( xstates >>= 2, subleaf = 2;
                  xstates && subleaf < ARRAY_SIZE(p->xstate.raw);
                  xstates >>= 1, ++subleaf )
                COPY_LEAF(leaf, subleaf, &p->xstate.raw[subleaf]);
            break;
        }

        default:
            COPY_LEAF(leaf, XEN_CPUID_NO_SUBLEAF, &p->basic.raw[leaf]);
            break;
        }
    }

    /* TODO: Port Xen and Viridian leaves to the new CPUID infrastructure. */
    COPY_LEAF(0x40000000, XEN_CPUID_NO_SUBLEAF,
              &(struct cpuid_leaf){ p->hv_limit });
    COPY_LEAF(0x40000100, XEN_CPUID_NO_SUBLEAF,
              &(struct cpuid_leaf){ p->hv2_limit });

    /* Extended leaves. */
    for ( leaf = 0; leaf <= MIN(p->extd.max_leaf & 0xffffUL,
                                ARRAY_SIZE(p->extd.raw) - 1); ++leaf )
        COPY_LEAF(0x80000000U | leaf, XEN_CPUID_NO_SUBLEAF, &p->extd.raw[leaf]);

#undef COPY_LEAF

    *nr_entries_p = curr_entry;

    return 0;
}

/*
 * Copy a single MSR into the provided msr_entry_buffer_t buffer, performing a
 * boundary check against the buffer size.
 */
static int copy_msr_to_buffer(uint32_t idx, uint64_t val,
                              msr_entry_buffer_t msrs,
                              uint32_t *curr_entry, const uint32_t nr_entries)
{
    const xen_msr_entry_t ent = { .idx = idx, .val = val };

    if ( *curr_entry == nr_entries )
        return -ENOBUFS;

    if ( copy_to_buffer_offset(msrs, *curr_entry, &ent, 1) )
        return -EFAULT;

    ++*curr_entry;

    return 0;
}

int x86_msr_copy_to_buffer(const struct cpu_policy *p,
                           msr_entry_buffer_t msrs, uint32_t *nr_entries_p)
{
    const uint32_t nr_entries = *nr_entries_p;
    uint32_t curr_entry = 0;

#define COPY_MSR(idx, val)                                      \
    ({                                                          \
        int ret;                                                \
                                                                \
        if ( (ret = copy_msr_to_buffer(                         \
                  idx, val, msrs, &curr_entry, nr_entries)) )   \
            return ret;                                         \
    })

    COPY_MSR(MSR_INTEL_PLATFORM_INFO, p->platform_info.raw);
    COPY_MSR(MSR_ARCH_CAPABILITIES,   p->arch_caps.raw);

#undef COPY_MSR

    *nr_entries_p = curr_entry;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
