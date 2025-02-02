/*
 * Copyright (C) 2005 Hewlett-Packard Co.
 * written by Aravind Menon & Jose Renato Santos
 *            (email: xenoprof@groups.hp.com)
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 * x86 specific part
 */

#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/xenoprof.h>
#include <public/xenoprof.h>

#include "op_counter.h"

int xenoprof_arch_counter(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xenoprof_counter counter;

    if ( copy_from_guest(&counter, arg, 1) )
        return -EFAULT;

    if ( counter.ind >= OP_MAX_COUNTER )
        return -E2BIG;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;

    return 0;
}

int xenoprof_arch_ibs_counter(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xenoprof_ibs_counter ibs_counter;

    if ( copy_from_guest(&ibs_counter, arg, 1) )
        return -EFAULT;

    ibs_config.op_enabled = ibs_counter.op_enabled;
    ibs_config.fetch_enabled = ibs_counter.fetch_enabled;
    ibs_config.max_cnt_fetch = ibs_counter.max_cnt_fetch;
    ibs_config.max_cnt_op = ibs_counter.max_cnt_op;
    ibs_config.rand_en = ibs_counter.rand_en;
    ibs_config.dispatched_ops = ibs_counter.dispatched_ops;

    return 0;
}

#ifdef CONFIG_COMPAT
#include <compat/xenoprof.h>

int compat_oprof_arch_counter(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct compat_oprof_counter counter;

    if ( copy_from_guest(&counter, arg, 1) )
        return -EFAULT;

    if ( counter.ind >= OP_MAX_COUNTER )
        return -E2BIG;

    counter_config[counter.ind].count     = counter.count;
    counter_config[counter.ind].enabled   = counter.enabled;
    counter_config[counter.ind].event     = counter.event;
    counter_config[counter.ind].kernel    = counter.kernel;
    counter_config[counter.ind].user      = counter.user;
    counter_config[counter.ind].unit_mask = counter.unit_mask;

    return 0;
}
#endif

int xenoprofile_get_mode(struct vcpu *curr, const struct cpu_user_regs *regs)
{
    if ( !guest_mode(regs) )
        return 2;

    if ( !is_hvm_vcpu(curr) )
        return guest_kernel_mode(curr, regs);

    switch ( hvm_guest_x86_mode(curr) )
    {
    case X86_MODE_REAL:
        return 1;
    case X86_MODE_VM86:
        return 0;
    default: /* 16BIT | 32BIT | 64BIT */
        return hvm_get_cpl(curr) != 3;
    }
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
