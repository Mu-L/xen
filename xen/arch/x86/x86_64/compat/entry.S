/*
 * Compatibility hypercall routines.
 */

        .file "x86_64/compat/entry.S"

#include <asm/asm_defns.h>
#include <asm/irq-vectors.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <public/xen.h>

FUNC(entry_int82)
        ENDBR64
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        pushq $0
        movb  $HYPERCALL_VECTOR, EFRAME_entry_vector(%rsp)
        SAVE_ALL compat=1 /* DPL1 gate, restricted to 32bit PV guests only. */

        GET_STACK_END(14)

        SPEC_CTRL_ENTRY_FROM_PV /* Req: %rsp=regs/cpuinfo, %r14=end, %rdx=0, Clob: abcd */
        /* WARNING! `ret`, `call *`, `jmp *` not safe before this point. */

        sti

        CR4_PV32_RESTORE /* Clob: ac */

        movq STACK_CPUINFO_FIELD(current_vcpu)(%r14), %rbx

        mov   %rsp, %rdi
        call  do_entry_int82
END(entry_int82)

/* %rbx: struct vcpu */
FUNC(compat_test_all_events)
        ASSERT_NOT_IN_ATOMIC
        cli                             # tests must not race interrupts
/*compat_test_softirqs:*/
        movl  VCPU_processor(%rbx),%eax
        shll  $IRQSTAT_shift,%eax
        leaq  irq_stat+IRQSTAT_softirq_pending(%rip),%rcx
        cmpl  $0,(%rcx,%rax,1)
        jne   compat_process_softirqs

        /* Inject exception if pending. */
        lea   VCPU_trap_bounce(%rbx), %rdx
        testb $TBF_EXCEPTION, TRAPBOUNCE_flags(%rdx)
        jnz   .Lcompat_process_trapbounce

        cmpb  $0, VCPU_mce_pending(%rbx)
        jne   compat_process_mce
.Lcompat_test_guest_nmi:
        cmpb  $0, VCPU_nmi_pending(%rbx)
        jne   compat_process_nmi
compat_test_guest_events:
        movq  VCPU_vcpu_info(%rbx),%rax
        movzwl COMPAT_VCPUINFO_upcall_pending(%rax),%eax
        decl  %eax
        cmpl  $0xfe,%eax
        ja    compat_restore_all_guest
/*compat_process_guest_events:*/
        sti
        leaq  VCPU_trap_bounce(%rbx),%rdx
        movl  VCPU_event_addr(%rbx),%eax
        movl  %eax,TRAPBOUNCE_eip(%rdx)
        movl  VCPU_event_sel(%rbx),%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        movb  $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

/* %rbx: struct vcpu */
LABEL_LOCAL(compat_process_softirqs)
        sti
        call  do_softirq
        jmp   compat_test_all_events

/* %rbx: struct vcpu, %rdx: struct trap_bounce */
LABEL_LOCAL(.Lcompat_process_trapbounce)
        sti
.Lcompat_bounce_exception:
        call  compat_create_bounce_frame
        jmp   compat_test_all_events

/* %rbx: struct vcpu */
LABEL_LOCAL(compat_process_mce)
        testb $1 << VCPU_TRAP_MCE,VCPU_async_exception_mask(%rbx)
        jnz   .Lcompat_test_guest_nmi
        sti
        movb  $0, VCPU_mce_pending(%rbx)
        call  set_guest_machinecheck_trapbounce
        test  %al, %al
        jz    compat_test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_mce_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_MCE,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        jmp   compat_process_trap

/* %rbx: struct vcpu */
LABEL_LOCAL(compat_process_nmi)
        testb $1 << VCPU_TRAP_NMI,VCPU_async_exception_mask(%rbx)
        jnz   compat_test_guest_events
        sti
        movb  $0, VCPU_nmi_pending(%rbx)
        call  set_guest_nmi_trapbounce
        test  %al, %al
        jz    compat_test_all_events
        movzbl VCPU_async_exception_mask(%rbx),%edx # save mask for the
        movb %dl,VCPU_nmi_old_mask(%rbx)            # iret hypercall
        orl  $1 << VCPU_TRAP_NMI,%edx
        movb %dl,VCPU_async_exception_mask(%rbx)
        /* FALLTHROUGH */
compat_process_trap:
        leaq  VCPU_trap_bounce(%rbx),%rdx
        call  compat_create_bounce_frame
        jmp   compat_test_all_events
END(compat_test_all_events)

/* %rbx: struct vcpu, interrupts disabled, %rsp=regs/cpuinfo */
FUNC(compat_restore_all_guest)
        ASSERT_INTERRUPTS_DISABLED
        mov   $~(X86_EFLAGS_IOPL | X86_EFLAGS_VM), %r11d
        and   UREGS_eflags(%rsp),%r11d

.macro alt_cr4_pv32 /* %rsp=regs/cpuinfo */
        testb $3,UREGS_cs(%rsp)
        jpe   2f
        mov   CPUINFO_cr4(%rsp), %rax
        and   $~XEN_CR4_PV32_BITS, %rax
1:
        mov   %rax, CPUINFO_cr4(%rsp)
        mov   %rax, %cr4
        /*
         * An NMI or MCE may have occurred between the previous two
         * instructions, leaving register and cache in a state where
         * the next exit from the guest would trigger the BUG in
         * cr4_pv32_restore. If this happened, the cached value is no
         * longer what we just set it to, which we can utilize to
         * correct that state. Note that we do not have to fear this
         * loop to cause a live lock: If NMIs/MCEs occurred at that
         * high a rate, we'd be live locked anyway.
         */
        cmp   %rax, CPUINFO_cr4(%rsp)
        jne   1b
2:
.endm
	ALTERNATIVE_2 "", \
            alt_cr4_pv32, X86_FEATURE_XEN_SMEP, \
            alt_cr4_pv32, X86_FEATURE_XEN_SMAP

        or    $X86_EFLAGS_IF,%r11
        mov   %r11d,UREGS_eflags(%rsp)

        mov VCPU_arch_msrs(%rbx), %rax
        mov VCPUMSR_spec_ctrl_raw(%rax), %eax

        /* WARNING! `ret`, `call *`, `jmp *` not safe beyond this point. */
        SPEC_CTRL_EXIT_TO_PV    /* Req: a=spec_ctrl %rsp=regs/cpuinfo, Clob: cd */

        RESTORE_ALL adj=8, compat=1

        /* Account for ev/ec having already been popped off the stack. */
        SPEC_CTRL_COND_VERW \
            scf=STK_REL(CPUINFO_scf,      CPUINFO_rip), \
            sel=STK_REL(CPUINFO_verw_sel, CPUINFO_rip)

.Lft0:  iretq
        _ASM_PRE_EXTABLE(.Lft0, handle_exception)
END(compat_restore_all_guest)

/* Callers can cope with both %rax and %rcx being clobbered. */
FUNC(cr4_pv32_restore)
        GET_CPUINFO_FIELD(cr4, cx)
        mov   (%rcx), %rax
        test  $XEN_CR4_PV32_BITS, %eax
        jnz   0f
        or    cr4_pv32_mask(%rip), %rax
        mov   %rax, %cr4
        mov   %rax, (%rcx)
        RET
0:
#ifndef NDEBUG
        /* Check that _all_ of the bits intended to be set actually are. */
        mov   %cr4, %rax
        and   cr4_pv32_mask(%rip), %rax
        cmp   cr4_pv32_mask(%rip), %rax
        je    1f
        /* Cause cr4_pv32_mask to be visible in the BUG register dump. */
        mov   cr4_pv32_mask(%rip), %rdx
        /* Avoid coming back here while handling the #UD we cause below. */
        mov   %cr4, %rcx
        or    %rdx, %rcx
        mov   %rcx, %cr4
        BUG
1:
#endif
        xor   %eax, %eax
        RET
END(cr4_pv32_restore)

FUNC(compat_syscall)
        /* Fix up reported %cs/%ss for compat domains. */
        movl  $FLAT_COMPAT_USER_SS, UREGS_ss(%rsp)
        movl  $FLAT_COMPAT_USER_CS, UREGS_cs(%rsp)

        cmpb  $0,VCPU_syscall32_disables_events(%rbx)
        movzwl VCPU_syscall32_sel(%rbx),%esi
        movq  VCPU_syscall32_addr(%rbx),%rax
        setne %cl
        leaq  VCPU_trap_bounce(%rbx),%rdx
        testl $~3,%esi
        leal  (,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_START(z, compat_syscall_gpf)
        movq  VCPU_trap_ctxt(%rbx),%rdi
        movl  $X86_EXC_GP, UREGS_entry_vector(%rsp)
        subl  $2,UREGS_rip(%rsp)
        /* %r12 is still zero at this point. */
        mov   %r12d, TRAPBOUNCE_error_code(%rdx)
        movl  X86_EXC_GP * TRAPINFO_sizeof + TRAPINFO_eip(%rdi),%eax
        movzwl X86_EXC_GP * TRAPINFO_sizeof + TRAPINFO_cs(%rdi),%esi
        testb $4, X86_EXC_GP * TRAPINFO_sizeof + TRAPINFO_flags(%rdi)
        setnz %cl
        leal  TBF_EXCEPTION|TBF_EXCEPTION_ERRCODE(,%rcx,TBF_INTERRUPT),%ecx
UNLIKELY_END(compat_syscall_gpf)
        movq  %rax,TRAPBOUNCE_eip(%rdx)
        movw  %si,TRAPBOUNCE_cs(%rdx)
        movb  %cl,TRAPBOUNCE_flags(%rdx)
        jmp   .Lcompat_bounce_exception
END(compat_syscall)

FUNC(compat_sysenter)
        CR4_PV32_RESTORE /* Clob: ac */
        movq  VCPU_trap_ctxt(%rbx),%rcx
        cmpb  $X86_EXC_GP, UREGS_entry_vector(%rsp)
        movzwl VCPU_sysenter_sel(%rbx),%eax
        movzwl X86_EXC_GP * TRAPINFO_sizeof + TRAPINFO_cs(%rcx),%ecx
        cmovel %ecx,%eax
        testl $~3,%eax
        movl  $FLAT_COMPAT_USER_SS,UREGS_ss(%rsp)
        cmovzl %ecx,%eax
        movw  %ax,TRAPBOUNCE_cs(%rdx)
        call  compat_create_bounce_frame
        jmp   compat_test_all_events
END(compat_sysenter)

FUNC(compat_int80_direct_trap)
        CR4_PV32_RESTORE /* Clob: ac */
        call  compat_create_bounce_frame
        jmp   compat_test_all_events
END(compat_int80_direct_trap)

/* CREATE A BASIC EXCEPTION FRAME ON GUEST OS (RING-1) STACK:            */
/*   {[ERRCODE,] EIP, CS, EFLAGS, [ESP, SS]}                             */
/* %rdx: trap_bounce, %rbx: struct vcpu                                  */
/* On return only %rbx and %rdx are guaranteed non-clobbered.            */
FUNC_LOCAL(compat_create_bounce_frame)
        ASSERT_INTERRUPTS_ENABLED
        mov   %fs,%edi
        ALTERNATIVE "", stac, X86_FEATURE_XEN_SMAP
        testb $2,UREGS_cs+8(%rsp)
        jz    1f
        /* Push new frame at registered guest-OS stack base. */
        movl  VCPU_kernel_sp(%rbx),%esi
.Lft1:  mov   VCPU_kernel_ss(%rbx),%fs
        subl  $2*4,%esi
        movl  UREGS_rsp+8(%rsp),%eax
.Lft2:  movl  %eax,%fs:(%rsi)
        movl  UREGS_ss+8(%rsp),%eax
.Lft3:  movl  %eax,%fs:4(%rsi)
        jmp   2f
1:      /* In kernel context already: push new frame at existing %rsp. */
        movl  UREGS_rsp+8(%rsp),%esi
.Lft4:  mov   UREGS_ss+8(%rsp),%fs
2:
        movq  VCPU_domain(%rbx),%r8
        subl  $3*4,%esi
        movq  VCPU_vcpu_info(%rbx),%rax
        pushq COMPAT_VCPUINFO_upcall_mask(%rax)
        testb $TBF_INTERRUPT,TRAPBOUNCE_flags(%rdx)
        setnz %ch                       # TBF_INTERRUPT -> set upcall mask
        orb   %ch,COMPAT_VCPUINFO_upcall_mask(%rax)
        popq  %rax
        shll  $16,%eax                  # Bits 16-23: saved_upcall_mask
        movw  UREGS_cs+8(%rsp),%ax      # Bits  0-15: CS
.Lft5:  movl  %eax,%fs:4(%rsi)          # CS / saved_upcall_mask
        shrl  $16,%eax
        testb %al,%al                   # Bits 0-7: saved_upcall_mask
        setz  %ch                       # %ch == !saved_upcall_mask
        movl  UREGS_eflags+8(%rsp),%eax
        andl  $~(X86_EFLAGS_IF|X86_EFLAGS_IOPL),%eax
        addb  %ch,%ch                   # Bit 9 (EFLAGS.IF)
        orb   %ch,%ah                   # Fold EFLAGS.IF into %eax
        xorl  %ecx,%ecx                 # if ( VM_ASSIST(v->domain, architectural_iopl) )
        testb $1 << VMASST_TYPE_architectural_iopl,DOMAIN_vm_assist(%r8)
        cmovnzl VCPU_iopl(%rbx),%ecx    # Bits 13:12 (EFLAGS.IOPL)
        orl   %ecx,%eax                 # Fold EFLAGS.IOPL into %eax
.Lft6:  movl  %eax,%fs:2*4(%rsi)        # EFLAGS
        movl  UREGS_rip+8(%rsp),%eax
.Lft7:  movl  %eax,%fs:(%rsi)           # EIP
        testb $TBF_EXCEPTION_ERRCODE,TRAPBOUNCE_flags(%rdx)
        jz    1f
        subl  $4,%esi
        movl  TRAPBOUNCE_error_code(%rdx),%eax
.Lft8:  movl  %eax,%fs:(%rsi)           # ERROR CODE
1:
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        /* Rewrite our stack frame and return to guest-OS mode. */
        /* IA32 Ref. Vol. 3: TF, VM, RF and NT flags are cleared on trap. */
        andl  $~(X86_EFLAGS_VM|X86_EFLAGS_RF|\
                 X86_EFLAGS_NT|X86_EFLAGS_TF),UREGS_eflags+8(%rsp)
        mov   %fs,UREGS_ss+8(%rsp)
        movl  %esi,UREGS_rsp+8(%rsp)
.Lft13: mov   %edi,%fs
        movzwl TRAPBOUNCE_cs(%rdx),%eax
        /* Null selectors (0-3) are not allowed. */
        testl $~3,%eax
UNLIKELY_START(z, compat_bounce_null_selector)
        lea   UNLIKELY_DISPATCH_LABEL(compat_bounce_null_selector)(%rip), %rdi
        jmp   asm_domain_crash_synchronous  /* Does not return */
__UNLIKELY_END(compat_bounce_null_selector)
        movl  %eax,UREGS_cs+8(%rsp)
        movl  TRAPBOUNCE_eip(%rdx),%eax
        movl  %eax,UREGS_rip+8(%rsp)

        /* Trapbounce complete.  Clobber state to avoid an erroneous second injection. */
        xor   %eax, %eax
        mov   %ax,  TRAPBOUNCE_cs(%rdx)
        mov   %al,  TRAPBOUNCE_flags(%rdx)
        RET

.section .fixup,"ax"
.Lfx13:
        xorl  %edi,%edi
        jmp   .Lft13
.previous
        _ASM_EXTABLE(.Lft1,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft2,  compat_crash_page_fault)
        _ASM_EXTABLE(.Lft3,  compat_crash_page_fault_4)
        _ASM_EXTABLE(.Lft4,  dom_crash_sync_extable)
        _ASM_EXTABLE(.Lft5,  compat_crash_page_fault_4)
        _ASM_EXTABLE(.Lft6,  compat_crash_page_fault_8)
        _ASM_EXTABLE(.Lft7,  compat_crash_page_fault)
        _ASM_EXTABLE(.Lft8,  compat_crash_page_fault)
        _ASM_EXTABLE(.Lft13, .Lfx13)

compat_crash_page_fault_8:
        addl  $4,%esi
compat_crash_page_fault_4:
        addl  $4,%esi
compat_crash_page_fault:
.Lft14: mov   %edi,%fs
        ALTERNATIVE "", clac, X86_FEATURE_XEN_SMAP
        movl  %esi,%edi
        call  show_page_walk
        jmp   dom_crash_sync_extable
.section .fixup,"ax"
.Lfx14:
        xorl  %edi,%edi
        jmp   .Lft14
.previous
        _ASM_EXTABLE(.Lft14, .Lfx14)
END(compat_create_bounce_frame)
