#include <xen/console.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/init.h>
#include <xen/irq.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/shutdown.h>
#include <xen/symbols.h>
#include <xen/version.h>
#include <xen/watchdog.h>

#include <asm/current.h>
#include <asm/endbr.h>
#include <asm/event.h>
#include <asm/flushtlb.h>
#include <asm/hvm/hvm.h>
#include <asm/msr.h>
#include <asm/nmi.h>
#include <asm/page.h>
#include <asm/shared.h>
#include <asm/traps.h>


static void print_xen_info(void)
{
    char taint_str[TAINT_STRING_MAX_LEN];

    printk("----[ Xen-%d.%d%s  x86_64  %s  %s ]----\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           xen_build_info(), print_tainted(taint_str));
}

enum context { CTXT_hypervisor, CTXT_pv_guest, CTXT_hvm_guest };

/* (ab)use crs[5..7] for fs/gs bases. */
static void read_registers(struct cpu_user_regs *regs, unsigned long crs[8])
{
    crs[0] = read_cr0();
    crs[2] = read_cr2();
    crs[3] = read_cr3();
    crs[4] = read_cr4();
    read_sregs(regs);
    crs[5] = read_fs_base();
    crs[6] = read_gs_base();
    crs[7] = read_gs_shadow();
}

static void get_hvm_registers(struct vcpu *v, struct cpu_user_regs *regs,
                              unsigned long crs[8])
{
    struct segment_register sreg;

    crs[0] = v->arch.hvm.guest_cr[0];
    crs[2] = v->arch.hvm.guest_cr[2];
    crs[3] = v->arch.hvm.guest_cr[3];
    crs[4] = v->arch.hvm.guest_cr[4];

    hvm_get_segment_register(v, x86_seg_cs, &sreg);
    regs->cs = sreg.sel;

    hvm_get_segment_register(v, x86_seg_ds, &sreg);
    regs->ds = sreg.sel;

    hvm_get_segment_register(v, x86_seg_es, &sreg);
    regs->es = sreg.sel;

    hvm_get_segment_register(v, x86_seg_fs, &sreg);
    regs->fs = sreg.sel;
    crs[5] = sreg.base;

    hvm_get_segment_register(v, x86_seg_gs, &sreg);
    regs->gs = sreg.sel;
    crs[6] = sreg.base;

    hvm_get_segment_register(v, x86_seg_ss, &sreg);
    regs->ss = sreg.sel;

    crs[7] = hvm_get_reg(v, MSR_SHADOW_GS_BASE);
}

static void _show_registers(
    const struct cpu_user_regs *regs, unsigned long crs[8],
    enum context context, const struct vcpu *v)
{
    static const char *const context_names[] = {
        [CTXT_hypervisor] = "hypervisor",
        [CTXT_pv_guest]   = "pv guest",
        [CTXT_hvm_guest]  = "hvm guest"
    };

    printk("RIP:    %04x:[<%016lx>]", regs->cs, regs->rip);
    if ( context == CTXT_hypervisor )
        printk(" %pS", _p(regs->rip));
    printk("\nRFLAGS: %016lx   ", regs->rflags);
    if ( (context == CTXT_pv_guest) && v && v->vcpu_info_area.map )
        printk("EM: %d   ", !!vcpu_info(v, evtchn_upcall_mask));
    printk("CONTEXT: %s", context_names[context]);
    if ( v && !is_idle_vcpu(v) )
        printk(" (%pv)", v);

    printk("\nrax: %016lx   rbx: %016lx   rcx: %016lx\n",
           regs->rax, regs->rbx, regs->rcx);
    printk("rdx: %016lx   rsi: %016lx   rdi: %016lx\n",
           regs->rdx, regs->rsi, regs->rdi);
    printk("rbp: %016lx   rsp: %016lx   r8:  %016lx\n",
           regs->rbp, regs->rsp, regs->r8);
    printk("r9:  %016lx   r10: %016lx   r11: %016lx\n",
           regs->r9,  regs->r10, regs->r11);
    printk("r12: %016lx   r13: %016lx   r14: %016lx\n",
           regs->r12, regs->r13, regs->r14);
    printk("r15: %016lx   cr0: %016lx   cr4: %016lx\n",
           regs->r15, crs[0], crs[4]);
    printk("cr3: %016lx   cr2: %016lx\n", crs[3], crs[2]);
    printk("fsb: %016lx   gsb: %016lx   gss: %016lx\n",
           crs[5], crs[6], crs[7]);
    printk("ds: %04x   es: %04x   fs: %04x   gs: %04x   "
           "ss: %04x   cs: %04x\n",
           regs->ds, regs->es, regs->fs,
           regs->gs, regs->ss, regs->cs);
}

void show_registers(const struct cpu_user_regs *regs)
{
    struct cpu_user_regs fault_regs = *regs;
    unsigned long fault_crs[8];
    enum context context;
    struct vcpu *v = system_state >= SYS_STATE_smp_boot ? current : NULL;

    if ( guest_mode(regs) && is_hvm_vcpu(v) )
    {
        get_hvm_registers(v, &fault_regs, fault_crs);
        context = CTXT_hvm_guest;
    }
    else
    {
        read_registers(&fault_regs, fault_crs);

        if ( guest_mode(regs) )
        {
            context = CTXT_pv_guest;
            fault_crs[2] = arch_get_cr2(v);
        }
        else
        {
            context = CTXT_hypervisor;
            fault_crs[2] = read_cr2();
        }
    }

    print_xen_info();
    printk("CPU:    %d\n", smp_processor_id());
    _show_registers(&fault_regs, fault_crs, context, v);

    if ( ler_msr && !guest_mode(regs) )
    {
        u64 from, to;

        rdmsrl(ler_msr, from);
        rdmsrl(ler_msr + 1, to);

        /* Upper bits may store metadata.  Re-canonicalise for printing. */
        printk("ler: from %016"PRIx64" [%ps]\n",
               from, _p(canonicalise_addr(from)));
        printk("       to %016"PRIx64" [%ps]\n",
               to, _p(canonicalise_addr(to)));
    }
}

void vcpu_show_registers(struct vcpu *v)
{
    const struct cpu_user_regs *regs = &v->arch.user_regs;
    struct cpu_user_regs aux_regs;
    enum context context;
    unsigned long crs[8];

    if ( is_hvm_vcpu(v) )
    {
        aux_regs = *regs;
        get_hvm_registers(v, &aux_regs, crs);
        regs = &aux_regs;
        context = CTXT_hvm_guest;
    }
    else
    {
        bool kernel = guest_kernel_mode(v, regs);

        crs[0] = v->arch.pv.ctrlreg[0];
        crs[2] = arch_get_cr2(v);
        crs[3] = pagetable_get_paddr(kernel ?
                                     v->arch.guest_table :
                                     v->arch.guest_table_user);
        crs[4] = v->arch.pv.ctrlreg[4];
        crs[5] = v->arch.pv.fs_base;
        crs[6 + !kernel] = v->arch.pv.gs_base_kernel;
        crs[7 - !kernel] = v->arch.pv.gs_base_user;

        context = CTXT_pv_guest;
    }

    _show_registers(regs, crs, context, v);
}

void show_page_walk(unsigned long addr)
{
    unsigned long pfn, mfn = read_cr3() >> PAGE_SHIFT;
    l4_pgentry_t l4e, *l4t;
    l3_pgentry_t l3e, *l3t;
    l2_pgentry_t l2e, *l2t;
    l1_pgentry_t l1e, *l1t;

    printk("Pagetable walk from %016lx:\n", addr);
    if ( !is_canonical_address(addr) )
        return;

    l4t = map_domain_page(_mfn(mfn));
    l4e = l4t[l4_table_offset(addr)];
    unmap_domain_page(l4t);
    mfn = l4e_get_pfn(l4e);
    pfn = mfn_valid(_mfn(mfn)) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L4[0x%03lx] = %"PRIpte" %016lx\n",
           l4_table_offset(addr), l4e_get_intpte(l4e), pfn);
    if ( !(l4e_get_flags(l4e) & _PAGE_PRESENT) ||
         !mfn_valid(_mfn(mfn)) )
        return;

    l3t = map_domain_page(_mfn(mfn));
    l3e = l3t[l3_table_offset(addr)];
    unmap_domain_page(l3t);
    mfn = l3e_get_pfn(l3e);
    pfn = mfn_valid(_mfn(mfn)) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L3[0x%03lx] = %"PRIpte" %016lx%s\n",
           l3_table_offset(addr), l3e_get_intpte(l3e), pfn,
           (l3e_get_flags(l3e) & _PAGE_PSE) ? " (PSE)" : "");
    if ( !(l3e_get_flags(l3e) & _PAGE_PRESENT) ||
         (l3e_get_flags(l3e) & _PAGE_PSE) ||
         !mfn_valid(_mfn(mfn)) )
        return;

    l2t = map_domain_page(_mfn(mfn));
    l2e = l2t[l2_table_offset(addr)];
    unmap_domain_page(l2t);
    mfn = l2e_get_pfn(l2e);
    pfn = mfn_valid(_mfn(mfn)) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L2[0x%03lx] = %"PRIpte" %016lx%s\n",
           l2_table_offset(addr), l2e_get_intpte(l2e), pfn,
           (l2e_get_flags(l2e) & _PAGE_PSE) ? " (PSE)" : "");
    if ( !(l2e_get_flags(l2e) & _PAGE_PRESENT) ||
         (l2e_get_flags(l2e) & _PAGE_PSE) ||
         !mfn_valid(_mfn(mfn)) )
        return;

    l1t = map_domain_page(_mfn(mfn));
    l1e = l1t[l1_table_offset(addr)];
    unmap_domain_page(l1t);
    mfn = l1e_get_pfn(l1e);
    pfn = mfn_valid(_mfn(mfn)) && machine_to_phys_mapping_valid ?
          get_gpfn_from_mfn(mfn) : INVALID_M2P_ENTRY;
    printk(" L1[0x%03lx] = %"PRIpte" %016lx\n",
           l1_table_offset(addr), l1e_get_intpte(l1e), pfn);
}

void asmlinkage do_double_fault(struct cpu_user_regs *regs)
{
    unsigned int cpu;
    unsigned long crs[8];

    console_force_unlock();

    asm ( "lsll %[sel], %[limit]" : [limit] "=r" (cpu)
                                  : [sel] "r" (PER_CPU_SELECTOR) );

    /* Find information saved during fault and dump it to the console. */
    printk("*** DOUBLE FAULT ***\n");
    print_xen_info();

    read_registers(regs, crs);

    printk("CPU:    %d\n", cpu);
    _show_registers(regs, crs, CTXT_hypervisor, NULL);
    show_code(regs);
    show_stack_overflow(cpu, regs);

    panic("DOUBLE FAULT -- system shutdown\n");
}

static unsigned int write_stub_trampoline(
    unsigned char *stub, unsigned long stub_va,
    unsigned long stack_bottom, unsigned long target_va)
{
    unsigned char *p = stub;

    if ( cpu_has_xen_ibt )
    {
        place_endbr64(p);
        p += 4;
    }

    /* Store guest %rax into %ss slot */
    /* movabsq %rax, stack_bottom - 8 */
    *p++ = 0x48;
    *p++ = 0xa3;
    *(uint64_t *)p = stack_bottom - 8;
    p += 8;

    /* Store guest %rsp in %rax */
    /* movq %rsp, %rax */
    *p++ = 0x48;
    *p++ = 0x89;
    *p++ = 0xe0;

    /* Switch to Xen stack */
    /* movabsq $stack_bottom - 8, %rsp */
    *p++ = 0x48;
    *p++ = 0xbc;
    *(uint64_t *)p = stack_bottom - 8;
    p += 8;

    /* jmp target_va */
    *p++ = 0xe9;
    *(int32_t *)p = target_va - (stub_va + (p - stub) + 4);
    p += 4;

    /* Round up to a multiple of 16 bytes. */
    return ROUNDUP(p - stub, 16);
}

DEFINE_PER_CPU(struct stubs, stubs);

void nocall lstar_enter(void);
void nocall cstar_enter(void);

void subarch_percpu_traps_init(void)
{
    unsigned long stack_bottom = get_stack_bottom();
    unsigned long stub_va = this_cpu(stubs.addr);
    unsigned char *stub_page;
    unsigned int offset;

    /* No PV guests?  No need to set up SYSCALL/SYSENTER infrastructure. */
    if ( !IS_ENABLED(CONFIG_PV) )
        return;

    stub_page = map_domain_page(_mfn(this_cpu(stubs.mfn)));

    /*
     * Trampoline for SYSCALL entry from 64-bit mode.  The VT-x HVM vcpu
     * context switch logic relies on the SYSCALL trampoline being at the
     * start of the stubs.
     */
    wrmsrl(MSR_LSTAR, stub_va);
    offset = write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                   stub_va, stack_bottom,
                                   (unsigned long)lstar_enter);
    stub_va += offset;

    if ( cpu_has_sep )
    {
        /* SYSENTER entry. */
        wrmsrl(MSR_IA32_SYSENTER_ESP, stack_bottom);
        wrmsrl(MSR_IA32_SYSENTER_EIP, (unsigned long)sysenter_entry);
        wrmsr(MSR_IA32_SYSENTER_CS, __HYPERVISOR_CS, 0);
    }

    /* Trampoline for SYSCALL entry from compatibility mode. */
    wrmsrl(MSR_CSTAR, stub_va);
    offset += write_stub_trampoline(stub_page + (stub_va & ~PAGE_MASK),
                                    stub_va, stack_bottom,
                                    (unsigned long)cstar_enter);

    /* Don't consume more than half of the stub space here. */
    ASSERT(offset <= STUB_BUF_SIZE / 2);

    unmap_domain_page(stub_page);

    /* Common SYSCALL parameters. */
    wrmsrl(MSR_STAR, XEN_MSR_STAR);
    wrmsrl(MSR_SYSCALL_MASK, XEN_SYSCALL_MASK);
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
