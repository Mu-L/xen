/*
 *  linux/arch/i386/kernel/i387.c
 *
 *  Copyright (C) 1994 Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *  General FPU state handling cleanups
 *  Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <xen/sched.h>
#include <asm/current.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/asm_defns.h>
#include <asm/spec_ctrl.h>

/*******************************/
/*     FPU Restore Functions   */
/*******************************/
/* Restore x87 extended state */
static inline void fpu_xrstor(struct vcpu *v, uint64_t mask)
{
    bool ok;

    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set the accumulated feature mask before doing save/restore.
     */
    ok = set_xcr0(v->arch.xcr0_accum | XSTATE_FP_SSE);
    ASSERT(ok);
    xrstor(v, mask);
    ok = set_xcr0(v->arch.xcr0 ?: XSTATE_FP_SSE);
    ASSERT(ok);
}

/* Restore x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxrstor(struct vcpu *v)
{
    const fpusse_t *fpu_ctxt = &v->arch.xsave_area->fpu_sse;

    /*
     * Some CPUs don't save/restore FDP/FIP/FOP unless an exception
     * is pending. Clear the x87 state here by setting it to fixed
     * values. The hypervisor data segment can be sometimes 0 and
     * sometimes new user value. Both should be ok. Use the FPU saved
     * data block as a safe address because it should be in L1.
     */
    if ( cpu_bug_fpu_ptrs &&
         !(fpu_ctxt->fsw & ~fpu_ctxt->fcw & 0x003f) )
        asm volatile ( "fnclex\n\t"
                       "ffree %%st(7)\n\t" /* clear stack tag */
                       "fildl %0"          /* load to clear state */
                       : : "m" (*fpu_ctxt) );

    /*
     * FXRSTOR can fault if passed a corrupted data block. We handle this
     * possibility, which may occur if the block was passed to us by control
     * tools or through VCPUOP_initialise, by silently clearing the block.
     */
    switch ( __builtin_expect(fpu_ctxt->x[FPU_WORD_SIZE_OFFSET], 8) )
    {
    default:
        asm_inline volatile (
            "1: fxrstorq %0\n"
            ".section .fixup,\"ax\"   \n"
            "2: push %%"__OP"ax       \n"
            "   push %%"__OP"cx       \n"
            "   push %%"__OP"di       \n"
            "   lea  %0,%%"__OP"di    \n"
            "   mov  %1,%%ecx         \n"
            "   xor  %%eax,%%eax      \n"
            "   rep ; stosl           \n"
            "   pop  %%"__OP"di       \n"
            "   pop  %%"__OP"cx       \n"
            "   pop  %%"__OP"ax       \n"
            "   jmp  1b               \n"
            ".previous                \n"
            _ASM_EXTABLE(1b, 2b)
            :
            : "m" (*fpu_ctxt), "i" (sizeof(*fpu_ctxt) / 4) );
        break;
    case 4: case 2:
        asm_inline volatile (
            "1: fxrstor %0         \n"
            ".section .fixup,\"ax\"\n"
            "2: push %%"__OP"ax    \n"
            "   push %%"__OP"cx    \n"
            "   push %%"__OP"di    \n"
            "   lea  %0,%%"__OP"di \n"
            "   mov  %1,%%ecx      \n"
            "   xor  %%eax,%%eax   \n"
            "   rep ; stosl        \n"
            "   pop  %%"__OP"di    \n"
            "   pop  %%"__OP"cx    \n"
            "   pop  %%"__OP"ax    \n"
            "   jmp  1b            \n"
            ".previous             \n"
            _ASM_EXTABLE(1b, 2b)
            :
            : "m" (*fpu_ctxt), "i" (sizeof(*fpu_ctxt) / 4) );
        break;
    }
}

/*******************************/
/*      FPU Save Functions     */
/*******************************/

static inline uint64_t vcpu_xsave_mask(const struct vcpu *v)
{
    if ( v->fpu_dirtied )
        return v->arch.nonlazy_xstate_used ? XSTATE_ALL : XSTATE_LAZY;

    ASSERT(v->arch.nonlazy_xstate_used);

    /*
     * The offsets of components which live in the extended region of
     * compact xsave area are not fixed. Xsave area may be overwritten
     * when a xsave with v->fpu_dirtied set is followed by one with
     * v->fpu_dirtied clear.
     * In such case, if hypervisor uses compact xsave area and guest
     * has ever used lazy states (checking xcr0_accum excluding
     * XSTATE_FP_SSE), vcpu_xsave_mask will return XSTATE_ALL. Otherwise
     * return XSTATE_NONLAZY.
     */
    return xstate_all(v) ? XSTATE_ALL : XSTATE_NONLAZY;
}

/* Save x87 extended state */
static inline void fpu_xsave(struct vcpu *v)
{
    bool ok;
    uint64_t mask = vcpu_xsave_mask(v);

    ASSERT(mask);
    /*
     * XCR0 normally represents what guest OS set. In case of Xen itself,
     * we set the accumulated feature mask before doing save/restore.
     */
    ok = set_xcr0(v->arch.xcr0_accum | XSTATE_FP_SSE);
    ASSERT(ok);
    xsave(v, mask);
    ok = set_xcr0(v->arch.xcr0 ?: XSTATE_FP_SSE);
    ASSERT(ok);
}

/* Save x87 FPU, MMX, SSE and SSE2 state */
static inline void fpu_fxsave(struct vcpu *v)
{
    fpusse_t *fpu_ctxt = &v->arch.xsave_area->fpu_sse;
    unsigned int fip_width = v->domain->arch.x87_fip_width;

    if ( fip_width != 4 )
    {
        asm volatile ( "fxsaveq %0" : "=m" (*fpu_ctxt) );

        /*
         * Some CPUs don't save/restore FDP/FIP/FOP unless an exception is
         * pending.  In this case, the restore side will arrange safe values,
         * and there is no point trying to collect FCS/FDS in addition.
         */
        if ( cpu_bug_fpu_ptrs && !(fpu_ctxt->fsw & 0x0080) )
            return;

        /*
         * If the FIP/FDP[63:32] are both zero, it is safe to use the
         * 32-bit restore to also restore the selectors.
         */
        if ( !fip_width &&
             !((fpu_ctxt->fip.addr | fpu_ctxt->fdp.addr) >> 32) )
        {
            struct ix87_env fpu_env;

            asm volatile ( "fnstenv %0" : "=m" (fpu_env) );
            fpu_ctxt->fip.sel = fpu_env.fcs;
            fpu_ctxt->fdp.sel = fpu_env.fds;
            fip_width = 4;
        }
        else
            fip_width = 8;
    }
    else
    {
        asm volatile ( "fxsave %0" : "=m" (*fpu_ctxt) );
        fip_width = 4;
    }

    fpu_ctxt->x[FPU_WORD_SIZE_OFFSET] = fip_width;
}

/*******************************/
/*       VCPU FPU Functions    */
/*******************************/
/* Restore FPU state whenever VCPU is schduled in. */
void vcpu_restore_fpu_nonlazy(struct vcpu *v, bool need_stts)
{
    /* Restore nonlazy extended state (i.e. parts not tracked by CR0.TS). */
    if ( !v->arch.fully_eager_fpu && !v->arch.nonlazy_xstate_used )
        goto maybe_stts;

    ASSERT(!is_idle_vcpu(v));

    /* Avoid recursion */
    clts();

    /*
     * When saving full state even with !v->fpu_dirtied (see vcpu_xsave_mask()
     * above) we also need to restore full state, to prevent subsequently
     * saving state belonging to another vCPU.
     */
    if ( v->arch.fully_eager_fpu || xstate_all(v) )
    {
        if ( cpu_has_xsave )
            fpu_xrstor(v, XSTATE_ALL);
        else
            fpu_fxrstor(v);

        v->fpu_initialised = 1;
        v->fpu_dirtied = 1;

        /* Xen doesn't need TS set, but the guest might. */
        need_stts = is_pv_vcpu(v) && (v->arch.pv.ctrlreg[0] & X86_CR0_TS);
    }
    else
    {
        fpu_xrstor(v, XSTATE_NONLAZY);
        need_stts = true;
    }

 maybe_stts:
    if ( need_stts )
        stts();
}

/* 
 * Restore FPU state when #NM is triggered.
 */
void vcpu_restore_fpu_lazy(struct vcpu *v)
{
    ASSERT(!is_idle_vcpu(v));

    /* Avoid recursion. */
    clts();

    if ( v->fpu_dirtied )
        return;

    ASSERT(!v->arch.fully_eager_fpu);

    if ( cpu_has_xsave )
        fpu_xrstor(v, XSTATE_LAZY);
    else
        fpu_fxrstor(v);

    v->fpu_initialised = 1;
    v->fpu_dirtied = 1;
}

/* 
 * On each context switch, save the necessary FPU info of VCPU being switch 
 * out. It dispatches saving operation based on CPU's capability.
 */
static bool _vcpu_save_fpu(struct vcpu *v)
{
    if ( !v->fpu_dirtied && !v->arch.nonlazy_xstate_used )
        return false;

    ASSERT(!is_idle_vcpu(v));

    /* This can happen, if a paravirtualised guest OS has set its CR0.TS. */
    clts();

    if ( cpu_has_xsave )
        fpu_xsave(v);
    else
        fpu_fxsave(v);

    v->fpu_dirtied = 0;

    return true;
}

void vcpu_save_fpu(struct vcpu *v)
{
    _vcpu_save_fpu(v);
    stts();
}

void save_fpu_enable(void)
{
    if ( !_vcpu_save_fpu(current) )
        clts();
}

/* Initialize FPU's context save area */
int vcpu_init_fpu(struct vcpu *v)
{
    v->arch.fully_eager_fpu = opt_eager_fpu;

    return xstate_alloc_save_area(v);
}

void vcpu_reset_fpu(struct vcpu *v)
{
    struct xsave_struct *xsave_area = VCPU_MAP_XSAVE_AREA(v);

    v->fpu_initialised = false;
    *xsave_area = (struct xsave_struct) {
        .xsave_hdr.xstate_bv = X86_XCR0_X87,
    };

    /* Old gcc doesn't permit these to be part of the initializer. */
    xsave_area->fpu_sse.mxcsr = MXCSR_DEFAULT;
    xsave_area->fpu_sse.fcw = FCW_RESET;
    xsave_area->fpu_sse.ftw = FXSAVE_FTW_RESET;

    VCPU_UNMAP_XSAVE_AREA(v, xsave_area);
}

void vcpu_setup_fpu(struct vcpu *v, const void *data)
{
    struct xsave_struct *xsave_area = VCPU_MAP_XSAVE_AREA(v);

    v->fpu_initialised = true;
    *xsave_area = (struct xsave_struct) {
        .fpu_sse = *(const fpusse_t*)data,
        .xsave_hdr.xstate_bv = XSTATE_FP_SSE,
    };

    VCPU_UNMAP_XSAVE_AREA(v, xsave_area);
}

/* Free FPU's context save area */
void vcpu_destroy_fpu(struct vcpu *v)
{
    xstate_free_save_area(v);
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
