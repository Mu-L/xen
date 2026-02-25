#ifdef __XEN__

#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/nospec.h>
#include <xen/types.h>

#include <asm/msr-index.h>

#define copy_from_buffer_offset copy_from_guest_offset

#else /* !__XEN__ */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <xen/asm/msr-index.h>

#include <xen-tools/common-macros.h>

#define array_access_nospec(a, i) (a)[(i)]

/* memcpy(), but with copy_from_guest_offset()'s API. */
#define copy_from_buffer_offset(dst, src, index, nr)    \
({                                                      \
    const typeof(*(src)) *src_ = (src);                 \
    typeof(*(dst)) *dst_ = (dst);                       \
    typeof(index) index_ = (index);                     \
    typeof(nr) nr_ = (nr), i_;                          \
                                                        \
    for ( i_ = 0; i_ < nr_; i_++ )                      \
        dst_[i_] = src_[index_ + i_];                   \
    0;                                                  \
})

#endif /* __XEN__ */

#include <xen/lib/x86/cpu-policy.h>

int x86_cpuid_copy_from_buffer(struct cpu_policy *p,
                               const cpuid_leaf_buffer_t leaves,
                               uint32_t nr_entries, uint32_t *err_leaf,
                               uint32_t *err_subleaf)
{
    unsigned int i;
    xen_cpuid_leaf_t data;

    if ( err_leaf )
        *err_leaf = -1;
    if ( err_subleaf )
        *err_subleaf = -1;

    /*
     * A well formed caller is expected to pass an array with leaves in order,
     * and without any repetitions.  However, due to per-vendor differences,
     * and in the case of upgrade or levelled scenarios, we typically expect
     * fewer than MAX leaves to be passed.
     *
     * Detecting repeated entries is prohibitively complicated, so we don't
     * bother.  That said, one way or another if more than MAX leaves are
     * passed, something is wrong.
     */
    if ( nr_entries > CPUID_MAX_SERIALISED_LEAVES )
        return -E2BIG;

    for ( i = 0; i < nr_entries; ++i )
    {
        struct cpuid_leaf l;

        if ( copy_from_buffer_offset(&data, leaves, i, 1) )
            return -EFAULT;

        l = (struct cpuid_leaf){ data.a, data.b, data.c, data.d };

        switch ( data.leaf )
        {
        case 0 ... ARRAY_SIZE(p->basic.raw) - 1:
            switch ( data.leaf )
            {
            case 0x4:
                if ( data.subleaf >= ARRAY_SIZE(p->cache.raw) )
                    goto out_of_range;

                array_access_nospec(p->cache.raw, data.subleaf) = l;
                break;

            case 0x7:
                if ( data.subleaf >= ARRAY_SIZE(p->feat.raw) )
                    goto out_of_range;

                array_access_nospec(p->feat.raw, data.subleaf) = l;
                break;

            case 0xb:
                if ( data.subleaf >= ARRAY_SIZE(p->topo.raw) )
                    goto out_of_range;

                array_access_nospec(p->topo.raw, data.subleaf) = l;
                break;

            case 0xd:
                if ( data.subleaf >= ARRAY_SIZE(p->xstate.raw) )
                    goto out_of_range;

                array_access_nospec(p->xstate.raw, data.subleaf) = l;
                break;

            default:
                if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                    goto out_of_range;

                array_access_nospec(p->basic.raw, data.leaf) = l;
                break;
            }
            break;

        case 0x40000000:
            if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                goto out_of_range;

            p->hv_limit = l.a;
            break;

        case 0x40000100:
            if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                goto out_of_range;

            p->hv2_limit = l.a;
            break;

        case 0x80000000U ... 0x80000000U + ARRAY_SIZE(p->extd.raw) - 1:
            if ( data.subleaf != XEN_CPUID_NO_SUBLEAF )
                goto out_of_range;

            array_access_nospec(p->extd.raw, data.leaf & 0xffff) = l;
            break;

        default:
            goto out_of_range;
        }
    }

    x86_cpu_policy_recalc_synth(p);

    return 0;

 out_of_range:
    if ( err_leaf )
        *err_leaf = data.leaf;
    if ( err_subleaf )
        *err_subleaf = data.subleaf;

    return -ERANGE;
}

int x86_msr_copy_from_buffer(struct cpu_policy *p,
                             const msr_entry_buffer_t msrs, uint32_t nr_entries,
                             uint32_t *err_msr)
{
    unsigned int i;
    xen_msr_entry_t data;
    int rc;

    if ( err_msr )
        *err_msr = -1;

    /*
     * A well formed caller is expected to pass an array with entries in
     * order, and without any repetitions.  However, due to per-vendor
     * differences, and in the case of upgrade or levelled scenarios, we
     * typically expect fewer than MAX entries to be passed.
     *
     * Detecting repeated entries is prohibitively complicated, so we don't
     * bother.  That said, one way or another if more than MAX entries are
     * passed, something is wrong.
     */
    if ( nr_entries > MSR_MAX_SERIALISED_ENTRIES )
        return -E2BIG;

    for ( i = 0; i < nr_entries; i++ )
    {
        if ( copy_from_buffer_offset(&data, msrs, i, 1) )
            return -EFAULT;

        if ( data.flags ) /* .flags MBZ */
        {
            rc = -EINVAL;
            goto err;
        }

        switch ( data.idx )
        {
            /*
             * Assign data.val to p->field, checking for truncation if the
             * backing storage for field is smaller than uint64_t
             */
#define ASSIGN(field)                             \
({                                                \
    if ( (typeof(p->field))data.val != data.val ) \
    {                                             \
        rc = -EOVERFLOW;                          \
        goto err;                                 \
    }                                             \
    p->field = data.val;                          \
})

        case MSR_INTEL_PLATFORM_INFO: ASSIGN(platform_info.raw); break;
        case MSR_ARCH_CAPABILITIES:   ASSIGN(arch_caps.raw);     break;

#undef ASSIGN

        default:
            rc = -ERANGE;
            goto err;
        }
    }

    return 0;

 err:
    if ( err_msr )
        *err_msr = data.idx;

    return rc;
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
