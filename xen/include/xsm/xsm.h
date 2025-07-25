/*
 *  This file contains the XSM hook definitions for Xen.
 *
 *  This work is based on the LSM implementation in Linux 2.6.13.4.
 *
 *  Author:  George Coker, <gscoker@alpha.ncsc.mil>
 *
 *  Contributors: Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2,
 *  as published by the Free Software Foundation.
 */

#ifndef __XSM_H__
#define __XSM_H__

#include <xen/alternative-call.h>
#include <xen/sched.h>

/* policy magic number (defined by XSM_MAGIC) */
typedef uint32_t xsm_magic_t;

#ifdef CONFIG_XSM_FLASK
#define XSM_MAGIC 0xf97cff8c
#else
#define XSM_MAGIC 0x0
#endif

/*
 * These annotations are used by callers and in dummy.h to document the
 * default actions of XSM hooks. They should be compiled out otherwise.
 */
enum xsm_default {
    XSM_HOOK,     /* Guests can normally access the hypercall */
    XSM_DM_PRIV,  /* Device model can perform on its target domain */
    XSM_TARGET,   /* Can perform on self or your target domain */
    XSM_PRIV,     /* Privileged - normally restricted to dom0 */
    XSM_XS_PRIV,  /* Xenstore domain - can do some privileged operations */
    XSM_OTHER     /* Something more complex */
};
typedef enum xsm_default xsm_default_t;

/*
 * !!! WARNING !!!
 *
 * For simplicity, xsm_fixup_ops() expects that this structure is made
 * exclusively of function pointers to non-init functions.  Think carefully
 * before deviating from the pattern.
 *
 * !!! WARNING !!!
 */
struct xsm_ops {
    int (*set_system_active)(void);
    void (*security_domaininfo)(struct domain *d,
                                struct xen_domctl_getdomaininfo *info);
    int (*domain_create)(struct domain *d, uint32_t ssidref);
    int (*getdomaininfo)(struct domain *d);
    int (*domctl_scheduler_op)(struct domain *d, int op);
#ifdef CONFIG_SYSCTL
    int (*sysctl_scheduler_op)(int op);
#endif
    int (*set_target)(struct domain *d, struct domain *e);
    int (*domctl)(struct domain *d, unsigned int cmd, uint32_t ssidref);
    int (*sysctl)(int cmd);
    int (*readconsole)(uint32_t clear);

    int (*evtchn_unbound)(struct domain *d, struct evtchn *chn, domid_t id2);
    int (*evtchn_interdomain)(struct domain *d1, struct evtchn *chn1,
                              struct domain *d2, struct evtchn *chn2);
    void (*evtchn_close_post)(struct evtchn *chn);
    int (*evtchn_send)(struct domain *d, struct evtchn *chn);
    int (*evtchn_status)(struct domain *d, struct evtchn *chn);
    int (*evtchn_reset)(struct domain *d1, struct domain *d2);

    int (*grant_mapref)(struct domain *d1, struct domain *d2, uint32_t flags);
    int (*grant_unmapref)(struct domain *d1, struct domain *d2);
    int (*grant_setup)(struct domain *d1, struct domain *d2);
    int (*grant_transfer)(struct domain *d1, struct domain *d2);
    int (*grant_copy)(struct domain *d1, struct domain *d2);
    int (*grant_query_size)(struct domain *d1, struct domain *d2);

    int (*alloc_security_domain)(struct domain *d);
    void (*free_security_domain)(struct domain *d);
    int (*alloc_security_evtchns)(struct evtchn chn[], unsigned int nr);
    void (*free_security_evtchns)(struct evtchn chn[], unsigned int nr);
    char *(*show_security_evtchn)(struct domain *d, const struct evtchn *chn);
    int (*init_hardware_domain)(struct domain *d);

    int (*get_pod_target)(struct domain *d);
    int (*set_pod_target)(struct domain *d);
    int (*memory_exchange)(struct domain *d);
    int (*memory_adjust_reservation)(struct domain *d1, struct domain *d2);
    int (*memory_stat_reservation)(struct domain *d1, struct domain *d2);
    int (*memory_pin_page)(struct domain *d1, struct domain *d2,
                           struct page_info *page);
    int (*add_to_physmap)(struct domain *d1, struct domain *d2);
    int (*remove_from_physmap)(struct domain *d1, struct domain *d2);
    int (*map_gmfn_foreign)(struct domain *d, struct domain *t);
    int (*claim_pages)(struct domain *d);

    int (*console_io)(struct domain *d, int cmd);

    int (*profile)(struct domain *d, int op);

    int (*kexec)(void);
    int (*schedop_shutdown)(struct domain *d1, struct domain *d2);

    char *(*show_irq_sid)(int irq);
    int (*map_domain_pirq)(struct domain *d);
    int (*map_domain_irq)(struct domain *d, int irq, const void *data);
    int (*unmap_domain_pirq)(struct domain *d);
    int (*unmap_domain_irq)(struct domain *d, int irq, const void *data);
    int (*bind_pt_irq)(struct domain *d, struct xen_domctl_bind_pt_irq *bind);
    int (*unbind_pt_irq)(struct domain *d, struct xen_domctl_bind_pt_irq *bind);
    int (*irq_permission)(struct domain *d, int pirq, uint8_t allow);
    int (*iomem_permission)(struct domain *d, uint64_t s, uint64_t e,
                            uint8_t allow);
    int (*iomem_mapping)(struct domain *d, uint64_t s, uint64_t e,
                         uint8_t allow);
    int (*pci_config_permission)(struct domain *d, uint32_t machine_bdf,
                                 uint16_t start, uint16_t end, uint8_t access);

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
    int (*get_device_group)(uint32_t machine_bdf);
    int (*assign_device)(struct domain *d, uint32_t machine_bdf);
    int (*deassign_device)(struct domain *d, uint32_t machine_bdf);
#endif

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE_DISCOVERY)
    int (*assign_dtdevice)(struct domain *d, const char *dtpath);
    int (*deassign_dtdevice)(struct domain *d, const char *dtpath);
#endif

    int (*resource_plug_core)(void);
    int (*resource_unplug_core)(void);
    int (*resource_plug_pci)(uint32_t machine_bdf);
    int (*resource_unplug_pci)(uint32_t machine_bdf);
    int (*resource_setup_pci)(uint32_t machine_bdf);
    int (*resource_setup_gsi)(int gsi);
    int (*resource_setup_misc)(void);

#ifdef CONFIG_SYSCTL
    int (*page_offline)(uint32_t cmd);
#endif
    int (*hypfs_op)(void);

    long (*do_xsm_op)(XEN_GUEST_HANDLE_PARAM(void) op);
#ifdef CONFIG_COMPAT
    int (*do_compat_op)(XEN_GUEST_HANDLE_PARAM(void) op);
#endif

    int (*hvm_param)(struct domain *d, unsigned long op);
    int (*hvm_param_altp2mhvm)(struct domain *d);
    int (*hvm_altp2mhvm_op)(struct domain *d, uint64_t mode, uint32_t op);
    int (*get_vnumainfo)(struct domain *d);

    int (*vm_event_control)(struct domain *d, int mode, int op);

#ifdef CONFIG_VM_EVENT
    int (*mem_access)(struct domain *d);
#endif

#ifdef CONFIG_MEM_PAGING
    int (*mem_paging)(struct domain *d);
#endif

#ifdef CONFIG_MEM_SHARING
    int (*mem_sharing)(struct domain *d);
#endif

    int (*platform_op)(uint32_t cmd);

#ifdef CONFIG_X86
    int (*do_mca)(void);
    int (*shadow_control)(struct domain *d, uint32_t op);
    int (*mem_sharing_op)(struct domain *d, struct domain *cd, int op);
    int (*apic)(struct domain *d, int cmd);
    int (*machine_memory_map)(void);
    int (*domain_memory_map)(struct domain *d);
#define XSM_MMU_UPDATE_READ      1
#define XSM_MMU_UPDATE_WRITE     2
#define XSM_MMU_NORMAL_UPDATE    4
#define XSM_MMU_MACHPHYS_UPDATE  8
    int (*mmu_update)(struct domain *d, struct domain *t,
                      struct domain *f, uint32_t flags);
    int (*mmuext_op)(struct domain *d, struct domain *f);
    int (*update_va_mapping)(struct domain *d, struct domain *f,
                             l1_pgentry_t pte);
    int (*priv_mapping)(struct domain *d, struct domain *t);
    int (*ioport_permission)(struct domain *d, uint32_t s, uint32_t e,
                             uint8_t allow);
    int (*ioport_mapping)(struct domain *d, uint32_t s, uint32_t e,
                          uint8_t allow);
    int (*pmu_op)(struct domain *d, unsigned int op);
#endif
    int (*dm_op)(struct domain *d);
    int (*xen_version)(uint32_t cmd);
    int (*domain_resource_map)(struct domain *d);
#ifdef CONFIG_ARGO
    int (*argo_enable)(const struct domain *d);
    int (*argo_register_single_source)(const struct domain *d,
                                       const struct domain *t);
    int (*argo_register_any_source)(const struct domain *d);
    int (*argo_send)(const struct domain *d, const struct domain *t);
#endif
    int (*get_domain_state)(struct domain *d);
};

#ifdef CONFIG_XSM

extern struct xsm_ops xsm_ops;

#ifndef XSM_NO_WRAPPERS

static inline int xsm_set_system_active(void)
{
    return alternative_call(xsm_ops.set_system_active);
}

static inline void xsm_security_domaininfo(
    struct domain *d, struct xen_domctl_getdomaininfo *info)
{
    alternative_vcall(xsm_ops.security_domaininfo, d, info);
}

static inline int xsm_domain_create(
    xsm_default_t def, struct domain *d, uint32_t ssidref)
{
    return alternative_call(xsm_ops.domain_create, d, ssidref);
}

static inline int xsm_getdomaininfo(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.getdomaininfo, d);
}

static inline int xsm_get_domain_state(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.get_domain_state, d);
}

static inline int xsm_domctl_scheduler_op(
    xsm_default_t def, struct domain *d, int cmd)
{
    return alternative_call(xsm_ops.domctl_scheduler_op, d, cmd);
}

#ifdef CONFIG_SYSCTL
static inline int xsm_sysctl_scheduler_op(xsm_default_t def, int cmd)
{
    return alternative_call(xsm_ops.sysctl_scheduler_op, cmd);
}
#endif

static inline int xsm_set_target(
    xsm_default_t def, struct domain *d, struct domain *e)
{
    return alternative_call(xsm_ops.set_target, d, e);
}

static inline int xsm_domctl(xsm_default_t def, struct domain *d,
                             unsigned int cmd, uint32_t ssidref)
{
    return alternative_call(xsm_ops.domctl, d, cmd, ssidref);
}

static inline int xsm_sysctl(xsm_default_t def, int cmd)
{
#ifdef CONFIG_SYSCTL
    return alternative_call(xsm_ops.sysctl, cmd);
#else
    return -EOPNOTSUPP;
#endif
}

static inline int xsm_readconsole(xsm_default_t def, uint32_t clear)
{
#ifdef CONFIG_SYSCTL
    return alternative_call(xsm_ops.readconsole, clear);
#else
    return -EOPNOTSUPP;
#endif
}

static inline int xsm_evtchn_unbound(
    xsm_default_t def, struct domain *d1, struct evtchn *chn, domid_t id2)
{
    return alternative_call(xsm_ops.evtchn_unbound, d1, chn, id2);
}

static inline int xsm_evtchn_interdomain(
    xsm_default_t def, struct domain *d1, struct evtchn *chan1,
    struct domain *d2, struct evtchn *chan2)
{
    return alternative_call(xsm_ops.evtchn_interdomain, d1, chan1, d2, chan2);
}

static inline void xsm_evtchn_close_post(struct evtchn *chn)
{
    alternative_vcall(xsm_ops.evtchn_close_post, chn);
}

static inline int xsm_evtchn_send(
    xsm_default_t def, struct domain *d, struct evtchn *chn)
{
    return alternative_call(xsm_ops.evtchn_send, d, chn);
}

static inline int xsm_evtchn_status(
    xsm_default_t def, struct domain *d, struct evtchn *chn)
{
    return alternative_call(xsm_ops.evtchn_status, d, chn);
}

static inline int xsm_evtchn_reset(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.evtchn_reset, d1, d2);
}

static inline int xsm_grant_mapref(
    xsm_default_t def, struct domain *d1, struct domain *d2, uint32_t flags)
{
    return alternative_call(xsm_ops.grant_mapref, d1, d2, flags);
}

static inline int xsm_grant_unmapref(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.grant_unmapref, d1, d2);
}

static inline int xsm_grant_setup(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.grant_setup, d1, d2);
}

static inline int xsm_grant_transfer(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.grant_transfer, d1, d2);
}

static inline int xsm_grant_copy(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.grant_copy, d1, d2);
}

static inline int xsm_grant_query_size(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.grant_query_size, d1, d2);
}

static inline int xsm_alloc_security_domain(struct domain *d)
{
    return alternative_call(xsm_ops.alloc_security_domain, d);
}

static inline void xsm_free_security_domain(struct domain *d)
{
    alternative_vcall(xsm_ops.free_security_domain, d);
}

static inline int xsm_alloc_security_evtchns(
    struct evtchn *chn, unsigned int nr)
{
    return alternative_call(xsm_ops.alloc_security_evtchns, chn, nr);
}

static inline void xsm_free_security_evtchns(
    struct evtchn *chn, unsigned int nr)
{
    alternative_vcall(xsm_ops.free_security_evtchns, chn, nr);
}

static inline char *xsm_show_security_evtchn(
    struct domain *d, const struct evtchn *chn)
{
    return alternative_call(xsm_ops.show_security_evtchn, d, chn);
}

static inline int xsm_init_hardware_domain(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.init_hardware_domain, d);
}

static inline int xsm_get_pod_target(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.get_pod_target, d);
}

static inline int xsm_set_pod_target(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.set_pod_target, d);
}

static inline int xsm_memory_exchange(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.memory_exchange, d);
}

static inline int xsm_memory_adjust_reservation(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.memory_adjust_reservation, d1, d2);
}

static inline int xsm_memory_stat_reservation(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.memory_stat_reservation, d1, d2);
}

static inline int xsm_memory_pin_page(
    xsm_default_t def, struct domain *d1, struct domain *d2,
    struct page_info *page)
{
    return alternative_call(xsm_ops.memory_pin_page, d1, d2, page);
}

static inline int xsm_add_to_physmap(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.add_to_physmap, d1, d2);
}

static inline int xsm_remove_from_physmap(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.remove_from_physmap, d1, d2);
}

static inline int xsm_map_gmfn_foreign(
    xsm_default_t def, struct domain *d, struct domain *t)
{
    return alternative_call(xsm_ops.map_gmfn_foreign, d, t);
}

static inline int xsm_claim_pages(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.claim_pages, d);
}

static inline int xsm_console_io(xsm_default_t def, struct domain *d, int cmd)
{
    return alternative_call(xsm_ops.console_io, d, cmd);
}

static inline int xsm_profile(xsm_default_t def, struct domain *d, int op)
{
    return alternative_call(xsm_ops.profile, d, op);
}

static inline int xsm_kexec(xsm_default_t def)
{
    return alternative_call(xsm_ops.kexec);
}

static inline int xsm_schedop_shutdown(
    xsm_default_t def, struct domain *d1, struct domain *d2)
{
    return alternative_call(xsm_ops.schedop_shutdown, d1, d2);
}

static inline char *xsm_show_irq_sid(int irq)
{
    return alternative_call(xsm_ops.show_irq_sid, irq);
}

static inline int xsm_map_domain_pirq(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.map_domain_pirq, d);
}

static inline int xsm_map_domain_irq(
    xsm_default_t def, struct domain *d, int irq, void *data)
{
    return alternative_call(xsm_ops.map_domain_irq, d, irq, data);
}

static inline int xsm_unmap_domain_pirq(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.unmap_domain_pirq, d);
}

static inline int xsm_unmap_domain_irq(
    xsm_default_t def, struct domain *d, int irq, void *data)
{
    return alternative_call(xsm_ops.unmap_domain_irq, d, irq, data);
}

static inline int xsm_bind_pt_irq(
    xsm_default_t def, struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return alternative_call(xsm_ops.bind_pt_irq, d, bind);
}

static inline int xsm_unbind_pt_irq(
    xsm_default_t def, struct domain *d, struct xen_domctl_bind_pt_irq *bind)
{
    return alternative_call(xsm_ops.unbind_pt_irq, d, bind);
}

static inline int xsm_irq_permission(
    xsm_default_t def, struct domain *d, int pirq, uint8_t allow)
{
    return alternative_call(xsm_ops.irq_permission, d, pirq, allow);
}

static inline int xsm_iomem_permission(
    xsm_default_t def, struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return alternative_call(xsm_ops.iomem_permission, d, s, e, allow);
}

static inline int xsm_iomem_mapping(
    xsm_default_t def, struct domain *d, uint64_t s, uint64_t e, uint8_t allow)
{
    return alternative_call(xsm_ops.iomem_mapping, d, s, e, allow);
}

static inline int xsm_pci_config_permission(
    xsm_default_t def, struct domain *d, uint32_t machine_bdf, uint16_t start,
    uint16_t end, uint8_t access)
{
    return alternative_call(xsm_ops.pci_config_permission, d, machine_bdf, start, end, access);
}

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_PCI)
static inline int xsm_get_device_group(xsm_default_t def, uint32_t machine_bdf)
{
    return alternative_call(xsm_ops.get_device_group, machine_bdf);
}

static inline int xsm_assign_device(
    xsm_default_t def, struct domain *d, uint32_t machine_bdf)
{
    return alternative_call(xsm_ops.assign_device, d, machine_bdf);
}

static inline int xsm_deassign_device(
    xsm_default_t def, struct domain *d, uint32_t machine_bdf)
{
    return alternative_call(xsm_ops.deassign_device, d, machine_bdf);
}
#endif /* HAS_PASSTHROUGH && HAS_PCI) */

#if defined(CONFIG_HAS_PASSTHROUGH) && defined(CONFIG_HAS_DEVICE_TREE_DISCOVERY)
static inline int xsm_assign_dtdevice(
    xsm_default_t def, struct domain *d, const char *dtpath)
{
    return alternative_call(xsm_ops.assign_dtdevice, d, dtpath);
}

static inline int xsm_deassign_dtdevice(
    xsm_default_t def, struct domain *d, const char *dtpath)
{
    return alternative_call(xsm_ops.deassign_dtdevice, d, dtpath);
}

#endif /* HAS_PASSTHROUGH && HAS_DEVICE_TREE_DISCOVERY */

static inline int xsm_resource_plug_pci(xsm_default_t def, uint32_t machine_bdf)
{
    return alternative_call(xsm_ops.resource_plug_pci, machine_bdf);
}

static inline int xsm_resource_unplug_pci(
    xsm_default_t def, uint32_t machine_bdf)
{
    return alternative_call(xsm_ops.resource_unplug_pci, machine_bdf);
}

static inline int xsm_resource_plug_core(xsm_default_t def)
{
    return alternative_call(xsm_ops.resource_plug_core);
}

static inline int xsm_resource_unplug_core(xsm_default_t def)
{
    return alternative_call(xsm_ops.resource_unplug_core);
}

static inline int xsm_resource_setup_pci(
    xsm_default_t def, uint32_t machine_bdf)
{
    return alternative_call(xsm_ops.resource_setup_pci, machine_bdf);
}

static inline int xsm_resource_setup_gsi(xsm_default_t def, int gsi)
{
    return alternative_call(xsm_ops.resource_setup_gsi, gsi);
}

static inline int xsm_resource_setup_misc(xsm_default_t def)
{
    return alternative_call(xsm_ops.resource_setup_misc);
}

static inline int xsm_page_offline(xsm_default_t def, uint32_t cmd)
{
#ifdef CONFIG_SYSCTL
    return alternative_call(xsm_ops.page_offline, cmd);
#else
    return -EOPNOTSUPP;
#endif
}

static inline int xsm_hypfs_op(xsm_default_t def)
{
    return alternative_call(xsm_ops.hypfs_op);
}

static inline long xsm_do_xsm_op(XEN_GUEST_HANDLE_PARAM(void) op)
{
    return alternative_call(xsm_ops.do_xsm_op, op);
}

#ifdef CONFIG_COMPAT
static inline int xsm_do_compat_op(XEN_GUEST_HANDLE_PARAM(void) op)
{
    return alternative_call(xsm_ops.do_compat_op, op);
}
#endif

static inline int xsm_hvm_param(
    xsm_default_t def, struct domain *d, unsigned long op)
{
    return alternative_call(xsm_ops.hvm_param, d, op);
}

static inline int xsm_hvm_param_altp2mhvm(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.hvm_param_altp2mhvm, d);
}

static inline int xsm_hvm_altp2mhvm_op(
    xsm_default_t def, struct domain *d, uint64_t mode, uint32_t op)
{
    return alternative_call(xsm_ops.hvm_altp2mhvm_op, d, mode, op);
}

static inline int xsm_get_vnumainfo(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.get_vnumainfo, d);
}

static inline int xsm_vm_event_control(
    xsm_default_t def, struct domain *d, int mode, int op)
{
    return alternative_call(xsm_ops.vm_event_control, d, mode, op);
}

#ifdef CONFIG_VM_EVENT
static inline int xsm_mem_access(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.mem_access, d);
}
#endif

#ifdef CONFIG_MEM_PAGING
static inline int xsm_mem_paging(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.mem_paging, d);
}
#endif

#ifdef CONFIG_MEM_SHARING
static inline int xsm_mem_sharing(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.mem_sharing, d);
}
#endif

static inline int xsm_platform_op(xsm_default_t def, uint32_t op)
{
    return alternative_call(xsm_ops.platform_op, op);
}

#ifdef CONFIG_X86
static inline int xsm_do_mca(xsm_default_t def)
{
    return alternative_call(xsm_ops.do_mca);
}

static inline int xsm_shadow_control(
    xsm_default_t def, struct domain *d, uint32_t op)
{
    return alternative_call(xsm_ops.shadow_control, d, op);
}

static inline int xsm_mem_sharing_op(
    xsm_default_t def, struct domain *d, struct domain *cd, int op)
{
    return alternative_call(xsm_ops.mem_sharing_op, d, cd, op);
}

static inline int xsm_apic(xsm_default_t def, struct domain *d, int cmd)
{
    return alternative_call(xsm_ops.apic, d, cmd);
}

static inline int xsm_machine_memory_map(xsm_default_t def)
{
    return alternative_call(xsm_ops.machine_memory_map);
}

static inline int xsm_domain_memory_map(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.domain_memory_map, d);
}

static inline int xsm_mmu_update(
    xsm_default_t def, struct domain *d, struct domain *t, struct domain *f,
    uint32_t flags)
{
    return alternative_call(xsm_ops.mmu_update, d, t, f, flags);
}

static inline int xsm_mmuext_op(
    xsm_default_t def, struct domain *d, struct domain *f)
{
    return alternative_call(xsm_ops.mmuext_op, d, f);
}

static inline int xsm_update_va_mapping(
    xsm_default_t def, struct domain *d, struct domain *f, l1_pgentry_t pte)
{
    return alternative_call(xsm_ops.update_va_mapping, d, f, pte);
}

static inline int xsm_priv_mapping(
    xsm_default_t def, struct domain *d, struct domain *t)
{
    return alternative_call(xsm_ops.priv_mapping, d, t);
}

static inline int xsm_ioport_permission(
    xsm_default_t def, struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return alternative_call(xsm_ops.ioport_permission, d, s, e, allow);
}

static inline int xsm_ioport_mapping(
    xsm_default_t def, struct domain *d, uint32_t s, uint32_t e, uint8_t allow)
{
    return alternative_call(xsm_ops.ioport_mapping, d, s, e, allow);
}

static inline int xsm_pmu_op(
    xsm_default_t def, struct domain *d, unsigned int op)
{
    return alternative_call(xsm_ops.pmu_op, d, op);
}

#endif /* CONFIG_X86 */

static inline int xsm_dm_op(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.dm_op, d);
}

static inline int xsm_xen_version(xsm_default_t def, uint32_t op)
{
    return alternative_call(xsm_ops.xen_version, op);
}

static inline int xsm_domain_resource_map(xsm_default_t def, struct domain *d)
{
    return alternative_call(xsm_ops.domain_resource_map, d);
}

#ifdef CONFIG_ARGO
static inline int xsm_argo_enable(const struct domain *d)
{
    return alternative_call(xsm_ops.argo_enable, d);
}

static inline int xsm_argo_register_single_source(
    const struct domain *d, const struct domain *t)
{
    return alternative_call(xsm_ops.argo_register_single_source, d, t);
}

static inline int xsm_argo_register_any_source(const struct domain *d)
{
    return alternative_call(xsm_ops.argo_register_any_source, d);
}

static inline int xsm_argo_send(const struct domain *d, const struct domain *t)
{
    return alternative_call(xsm_ops.argo_send, d, t);
}

#endif /* CONFIG_ARGO */

#endif /* XSM_NO_WRAPPERS */

#ifdef CONFIG_MULTIBOOT
struct boot_info;
int xsm_multiboot_init(struct boot_info *bi);
int xsm_multiboot_policy_init(
    struct boot_info *bi, void **policy_buffer, size_t *policy_size);
#endif

#ifdef CONFIG_HAS_DEVICE_TREE_DISCOVERY
/*
 * Initialize XSM
 *
 * On success, return 1 if using SILO mode else 0.
 */
int xsm_dt_init(void);
int xsm_dt_policy_init(void **policy_buffer, size_t *policy_size);
bool has_xsm_magic(paddr_t);
#endif

void xsm_fixup_ops(struct xsm_ops *ops);

#ifdef CONFIG_XSM_FLASK
extern const struct xsm_ops *flask_init(const void *policy_buffer,
                                        size_t policy_size);
#else
static const inline struct xsm_ops *flask_init(const void *policy_buffer,
                                               size_t policy_size)
{
    return NULL;
}
#endif

#ifdef CONFIG_XSM_FLASK_POLICY
extern const unsigned char xsm_flask_init_policy[];
extern const unsigned int xsm_flask_init_policy_size;
#endif

#ifdef CONFIG_XSM_SILO
extern const struct xsm_ops *silo_init(void);
#else
static const inline struct xsm_ops *silo_init(void)
{
    return NULL;
}
#endif

#else /* CONFIG_XSM */

#include <xsm/dummy.h>

#ifdef CONFIG_MULTIBOOT
struct boot_info;
static inline int xsm_multiboot_init(struct boot_info *bi)
{
    return 0;
}
#endif

#ifdef CONFIG_HAS_DEVICE_TREE_DISCOVERY
static inline int xsm_dt_init(void)
{
    return 0;
}

static inline bool has_xsm_magic(paddr_t start)
{
    return false;
}
#endif /* CONFIG_HAS_DEVICE_TREE_DISCOVERY */

#endif /* CONFIG_XSM */

#endif /* __XSM_H */
