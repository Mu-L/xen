/* SPDX-License-Identifier: GPL-2.0-or-later */
/******************************************************************************
 * arch/x86/guest/xen.c
 *
 * Support for detecting and running under Xen.
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */
#include <xen/event.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/rangeset.h>
#include <xen/types.h>
#include <xen/pv_console.h>

#include <asm/apic.h>
#include <asm/e820.h>
#include <asm/guest.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include <public/arch-x86/cpuid.h>
#include <public/hvm/params.h>

bool __read_mostly xen_guest;

uint32_t __read_mostly xen_cpuid_base;
static struct rangeset *mem;

DEFINE_PER_CPU(unsigned int, vcpu_id);

static struct vcpu_info *vcpu_info;
static unsigned long vcpu_info_mapped[BITS_TO_LONGS(NR_CPUS)];
DEFINE_PER_CPU(struct vcpu_info *, vcpu_info);

/*
 * Which instruction to use for early hypercalls:
 *   < 0 setup
 *     0 vmcall
 *   > 0 vmmcall
 */
int8_t __initdata early_hypercall_insn = -1;

/*
 * Called once during the first hypercall to figure out which instruction to
 * use.  Error handling options are limited.
 */
void asmlinkage __init early_hypercall_setup(void)
{
    BUG_ON(early_hypercall_insn != -1);

    if ( !boot_cpu_data.x86_vendor )
    {
        unsigned int eax, ebx, ecx, edx;

        cpuid(0, &eax, &ebx, &ecx, &edx);

        boot_cpu_data.x86_vendor = x86_cpuid_lookup_vendor(ebx, ecx, edx);
    }

    switch ( boot_cpu_data.x86_vendor )
    {
    case X86_VENDOR_INTEL:
    case X86_VENDOR_CENTAUR:
    case X86_VENDOR_SHANGHAI:
        early_hypercall_insn = 0;
        setup_force_cpu_cap(X86_FEATURE_USE_VMCALL);
        break;

    case X86_VENDOR_AMD:
    case X86_VENDOR_HYGON:
        early_hypercall_insn = 1;
        break;

    default:
        BUG();
    }
}

static void __init find_xen_leaves(void)
{
    uint32_t eax, ebx, ecx, edx, base;

    for ( base = XEN_CPUID_FIRST_LEAF;
          base < XEN_CPUID_FIRST_LEAF + 0x10000; base += 0x100 )
    {
        cpuid(base, &eax, &ebx, &ecx, &edx);

        if ( (ebx == XEN_CPUID_SIGNATURE_EBX) &&
             (ecx == XEN_CPUID_SIGNATURE_ECX) &&
             (edx == XEN_CPUID_SIGNATURE_EDX) &&
             ((eax - base) >= 2) )
        {
            xen_cpuid_base = base;
            break;
        }
    }
}

static void map_shared_info(void)
{
    mfn_t mfn;
    struct xen_add_to_physmap xatp = {
        .domid = DOMID_SELF,
        .space = XENMAPSPACE_shared_info,
    };
    unsigned int i;
    unsigned long rc;

    if ( xg_alloc_unused_page(&mfn) )
        panic("unable to reserve shared info memory page\n");

    xatp.gpfn = mfn_x(mfn);
    rc = xen_hypercall_memory_op(XENMEM_add_to_physmap, &xatp);
    if ( rc )
        panic("failed to map shared_info page: %ld\n", rc);

    set_fixmap(FIX_XEN_SHARED_INFO, mfn_to_maddr(mfn));

    /* Mask all upcalls */
    for ( i = 0; i < ARRAY_SIZE(XEN_shared_info->evtchn_mask); i++ )
        write_atomic(&XEN_shared_info->evtchn_mask[i], ~0ul);
}

static int map_vcpuinfo(void)
{
    unsigned int vcpu = this_cpu(vcpu_id);
    struct vcpu_register_vcpu_info info;
    int rc;

    if ( !vcpu_info )
    {
        this_cpu(vcpu_info) = &XEN_shared_info->vcpu_info[vcpu];
        return 0;
    }

    if ( test_bit(vcpu, vcpu_info_mapped) )
    {
        this_cpu(vcpu_info) = &vcpu_info[vcpu];
        return 0;
    }

    info.mfn = virt_to_mfn(&vcpu_info[vcpu]);
    info.offset = (unsigned long)&vcpu_info[vcpu] & ~PAGE_MASK;
    rc = xen_hypercall_vcpu_op(VCPUOP_register_vcpu_info, vcpu, &info);
    if ( !rc )
    {
        this_cpu(vcpu_info) = &vcpu_info[vcpu];
        set_bit(vcpu, vcpu_info_mapped);
    }
    else if ( vcpu < XEN_LEGACY_MAX_VCPUS )
    {
        rc = 0;
        this_cpu(vcpu_info) = &XEN_shared_info->vcpu_info[vcpu];
    }

    return rc;
}

static void set_vcpu_id(void)
{
    uint32_t eax, ebx, ecx, edx;

    ASSERT(xen_cpuid_base);

    /* Fetch vcpu id from cpuid. */
    cpuid(xen_cpuid_base + 4, &eax, &ebx, &ecx, &edx);
    if ( eax & XEN_HVM_CPUID_VCPU_ID_PRESENT )
        this_cpu(vcpu_id) = ebx;
    else
        this_cpu(vcpu_id) = smp_processor_id();
}

static void __init init_memmap(void)
{
    unsigned int i;

    mem = rangeset_new(NULL, "host memory map", 0);
    if ( !mem )
        panic("failed to allocate PFN usage rangeset\n");

    /*
     * Mark up to the last memory page (or 4GiB) as RAM. This is done because
     * Xen doesn't know the position of possible MMIO holes, so at least try to
     * avoid the know MMIO hole below 4GiB. Note that this is subject to future
     * discussion and improvements.
     */
    if ( rangeset_add_range(mem, 0, max_t(unsigned long, max_page - 1,
                                          PFN_DOWN(GB(4) - 1))) )
        panic("unable to add RAM to in-use PFN rangeset\n");

    for ( i = 0; i < e820.nr_map; i++ )
    {
        struct e820entry *e = &e820.map[i];

        if ( rangeset_add_range(mem, PFN_DOWN(e->addr),
                                PFN_UP(e->addr + e->size - 1)) )
            panic("unable to add range [%#lx, %#lx] to in-use PFN rangeset\n",
                  PFN_DOWN(e->addr), PFN_UP(e->addr + e->size - 1));
    }
}

static void cf_check xen_evtchn_upcall(void)
{
    struct vcpu_info *vcpu_info = this_cpu(vcpu_info);
    unsigned long pending;

    vcpu_info->evtchn_upcall_pending = 0;
    pending = xchg(&vcpu_info->evtchn_pending_sel, 0);

    while ( pending )
    {
        unsigned int l1 = ffsl(pending) - 1;
        unsigned long evtchn = xchg(&XEN_shared_info->evtchn_pending[l1], 0);

        __clear_bit(l1, &pending);
        evtchn &= ~XEN_shared_info->evtchn_mask[l1];
        while ( evtchn )
        {
            unsigned int port = ffsl(evtchn) - 1;

            __clear_bit(port, &evtchn);
            port += l1 * BITS_PER_LONG;

            if ( pv_console && port == pv_console_evtchn() )
                pv_console_rx();
            else if ( pv_shim )
                pv_shim_inject_evtchn(port);
        }
    }

    ack_APIC_irq();
}

static int init_evtchn(void)
{
    static uint8_t evtchn_upcall_vector;
    int rc;

    if ( !evtchn_upcall_vector )
        alloc_direct_apic_vector(&evtchn_upcall_vector, xen_evtchn_upcall);

    ASSERT(evtchn_upcall_vector);

    rc = xen_hypercall_set_evtchn_upcall_vector(this_cpu(vcpu_id),
                                                evtchn_upcall_vector);
    if ( rc )
    {
        printk("Unable to set evtchn upcall vector: %d\n", rc);
        return rc;
    }

    if ( smp_processor_id() == 0 )
    {
        struct xen_hvm_param a = {
            .domid = DOMID_SELF,
            .index = HVM_PARAM_CALLBACK_IRQ,
            .value = 1,
        };

        /* Trick toolstack to think we are enlightened */
        rc = xen_hypercall_hvm_op(HVMOP_set_param, &a);
        if ( rc )
            printk("Unable to set HVM_PARAM_CALLBACK_IRQ\n");
    }

    return rc;
}

static void __init cf_check setup(void)
{
    init_memmap();

    map_shared_info();

    set_vcpu_id();
    vcpu_info = xzalloc_array(struct vcpu_info, nr_cpu_ids);
    if ( map_vcpuinfo() )
    {
        xfree(vcpu_info);
        vcpu_info = NULL;
    }
    if ( !vcpu_info && nr_cpu_ids > XEN_LEGACY_MAX_VCPUS )
    {
        unsigned int i;

        for ( i = XEN_LEGACY_MAX_VCPUS; i < nr_cpu_ids; i++ )
            __cpumask_clear_cpu(i, &cpu_present_map);
        nr_cpu_ids = XEN_LEGACY_MAX_VCPUS;
        printk(XENLOG_WARNING
               "unable to map vCPU info, limiting vCPUs to: %u\n",
               XEN_LEGACY_MAX_VCPUS);
    }

    BUG_ON(init_evtchn());
}

static int cf_check ap_setup(void)
{
    set_vcpu_id();

    return map_vcpuinfo() ?: init_evtchn();
}

int xg_alloc_unused_page(mfn_t *mfn)
{
    unsigned long m;
    int rc;

    rc = rangeset_claim_range(mem, 1, &m);
    if ( !rc )
        *mfn = _mfn(m);

    return rc;
}

int xg_free_unused_page(mfn_t mfn)
{
    return rangeset_remove_range(mem, mfn_x(mfn), mfn_x(mfn));
}

static void cf_check ap_resume(void *unused)
{
    BUG_ON(map_vcpuinfo());
    BUG_ON(init_evtchn());
}

static void cf_check resume(void)
{
    /* Reset shared info page. */
    map_shared_info();

    /*
     * Reset vcpu_info. Just clean the mapped bitmap and try to map the vcpu
     * area again. On failure to map (when it was previously mapped) panic
     * since it's impossible to safely shut down running guest vCPUs in order
     * to meet the new XEN_LEGACY_MAX_VCPUS requirement.
     */
    bitmap_zero(vcpu_info_mapped, NR_CPUS);
    if ( map_vcpuinfo() && nr_cpu_ids > XEN_LEGACY_MAX_VCPUS )
        panic("unable to remap vCPU info and vCPUs > legacy limit\n");

    /* Setup event channel upcall vector. */
    BUG_ON(init_evtchn());
    smp_call_function(ap_resume, NULL, 1);

    if ( pv_console )
        pv_console_init();
}

static void __init cf_check e820_fixup(void)
{
    if ( pv_shim )
        pv_shim_fixup_e820();
}

static int cf_check flush_tlb(
    const cpumask_t *mask, const void *va, unsigned int flags)
{
    return xen_hypercall_hvm_op(HVMOP_flush_tlbs, NULL);
}

static const struct hypervisor_ops __initconst_cf_clobber ops = {
    .name = "Xen",
    .setup = setup,
    .ap_setup = ap_setup,
    .resume = resume,
    .e820_fixup = e820_fixup,
    .flush_tlb = flush_tlb,
};

const struct hypervisor_ops *__init xg_probe(void)
{
    if ( xen_guest )
        return &ops;

    find_xen_leaves();

    if ( !xen_cpuid_base )
        return NULL;

    xen_guest = true;

    return &ops;
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
