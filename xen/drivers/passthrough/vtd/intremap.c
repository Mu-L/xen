/*
 * Copyright (c) 2006, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Xiaohui Xin <xiaohui.xin@intel.com>
 */

#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/time.h>
#include <xen/list.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include "iommu.h"
#include "dmar.h"
#include "vtd.h"
#include "extern.h"

#include <asm/apic.h>
#include <asm/io_apic.h>
#define nr_ioapic_entries(i)  nr_ioapic_entries[i]

/*
 * source validation type (SVT)
 */
#define SVT_NO_VERIFY       0x0  /* no verification is required */
#define SVT_VERIFY_SID_SQ   0x1  /* verify using SID and SQ fiels */
#define SVT_VERIFY_BUS      0x2  /* verify bus of request-id */

/*
 * source-id qualifier (SQ)
 */
#define SQ_ALL_16           0x0  /* verify all 16 bits of request-id */
#define SQ_13_IGNORE_1      0x1  /* verify most significant 13 bits, ignore
                                  * the third least significant bit
                                  */
#define SQ_13_IGNORE_2      0x2  /* verify most significant 13 bits, ignore
                                  * the second and third least significant bits
                                  */
#define SQ_13_IGNORE_3      0x3  /* verify most significant 13 bits, ignore
                                  * the least three significant bits
                                  */

/* apic_pin_2_ir_idx[apicid][pin] = interrupt remapping table index */
static int **apic_pin_2_ir_idx;

static int init_apic_pin_2_ir_idx(void)
{
    int *_apic_pin_2_ir_idx;
    unsigned int nr_pins, i;

    /* Here we shouldn't need to re-init when resuming from S3. */
    if ( apic_pin_2_ir_idx != NULL )
        return 0;

    nr_pins = 0;
    for ( i = 0; i < nr_ioapics; i++ )
        nr_pins += nr_ioapic_entries(i);

    _apic_pin_2_ir_idx = xmalloc_array(int, nr_pins);
    apic_pin_2_ir_idx = xmalloc_array(int *, nr_ioapics);
    if ( (_apic_pin_2_ir_idx == NULL) || (apic_pin_2_ir_idx == NULL) )
    {
        xfree(_apic_pin_2_ir_idx);
        xfree(apic_pin_2_ir_idx);
        return -ENOMEM;
    }

    for ( i = 0; i < nr_pins; i++ )
        _apic_pin_2_ir_idx[i] = -1;

    nr_pins = 0;
    for ( i = 0; i < nr_ioapics; i++ )
    {
        apic_pin_2_ir_idx[i] = &_apic_pin_2_ir_idx[nr_pins];
        nr_pins += nr_ioapic_entries(i);
    }

    return 0;
}

static u16 apicid_to_bdf(int apic_id)
{
    struct acpi_drhd_unit *drhd = ioapic_to_drhd(apic_id);
    struct acpi_ioapic_unit *acpi_ioapic_unit;

    list_for_each_entry ( acpi_ioapic_unit, &drhd->ioapic_list, list )
        if ( acpi_ioapic_unit->apic_id == apic_id )
            return acpi_ioapic_unit->ioapic.info;

    dprintk(XENLOG_ERR VTDPREFIX, "Didn't find the bdf for the apic_id!\n");
    return 0;
}

static u16 hpetid_to_bdf(unsigned int hpet_id)
{
    struct acpi_drhd_unit *drhd = hpet_to_drhd(hpet_id);
    struct acpi_hpet_unit *acpi_hpet_unit;

    list_for_each_entry ( acpi_hpet_unit, &drhd->hpet_list, list )
        if ( acpi_hpet_unit->id == hpet_id )
            return acpi_hpet_unit->bdf;

    dprintk(XENLOG_ERR VTDPREFIX, "Didn't find the bdf for HPET %u!\n", hpet_id);
    return 0;
}

static void set_ire_sid(struct iremap_entry *ire,
                        unsigned int svt, unsigned int sq, unsigned int sid)
{
    ire->remap.svt = svt;
    ire->remap.sq = sq;
    ire->remap.sid = sid;
}

static void set_ioapic_source_id(int apic_id, struct iremap_entry *ire)
{
    set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                apicid_to_bdf(apic_id));
}

static void set_hpet_source_id(unsigned int id, struct iremap_entry *ire)
{
    /*
     * Should really use SQ_ALL_16. Some platforms are broken.
     * While we figure out the right quirks for these broken platforms, use
     * SQ_13_IGNORE_3 for now.
     */
    set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_13_IGNORE_3, hpetid_to_bdf(id));
}

bool __init cf_check intel_iommu_supports_eim(void)
{
    struct acpi_drhd_unit *drhd;
    unsigned int apic;

    if ( !iommu_qinval || !iommu_intremap || list_empty(&acpi_drhd_units) )
        return false;

    if ( unlikely(!cpu_has_cx16) )
    {
        printk(XENLOG_ERR VTDPREFIX "no CMPXCHG16B support, disabling IOMMU\n");
        /*
         * Disable IOMMU support at once: there's no reason to check for CX16
         * yet again when attempting to initialize IOMMU DMA remapping
         * functionality or interrupt remapping without x2APIC support.
         */
        iommu_enable = false;
        iommu_intremap = iommu_intremap_off;
        return false;
    }

    /* We MUST have a DRHD unit for each IOAPIC. */
    for ( apic = 0; apic < nr_ioapics; apic++ )
        if ( !ioapic_to_drhd(IO_APIC_ID(apic)) )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "There is not a DRHD for IOAPIC %#x (id: %#x)!\n",
                    apic, IO_APIC_ID(apic));
            return false;
        }

    for_each_drhd_unit ( drhd )
        if ( !ecap_queued_inval(drhd->iommu->ecap) ||
             !ecap_intr_remap(drhd->iommu->ecap) ||
             !ecap_eim(drhd->iommu->ecap) )
            return false;

    return true;
}

/*
 * Assume iremap_lock has been acquired. It is to make sure software will not
 * change the same IRTE behind us.
 */
static void update_irte(struct vtd_iommu *iommu, struct iremap_entry *entry,
                        const struct iremap_entry *new_ire, bool atomic)
{
    __uint128_t ret;
    struct iremap_entry old_ire;

    ASSERT(spin_is_locked(&iommu->intremap.lock));

    old_ire = *entry;
    ret = cmpxchg16b(entry, &old_ire, new_ire);

    /*
     * In the above, we use cmpxchg16 to atomically update the 128-bit
     * IRTE, and the hardware cannot update the IRTE behind us, so
     * the return value of cmpxchg16 should be the same as old_ire.
     * This ASSERT validate it.
     */
    ASSERT(ret == old_ire.val);
}

/* Mark specified intr remap entry as free */
static void free_remap_entry(struct vtd_iommu *iommu, int index)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries, new_ire = { };

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
        return;

    ASSERT(spin_is_locked(&iommu->intremap.lock));

    GET_IREMAP_ENTRY(iommu->intremap.maddr, index,
                     iremap_entries, iremap_entry);

    update_irte(iommu, iremap_entry, &new_ire, false);
    iommu_sync_cache(iremap_entry, sizeof(*iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    iommu->intremap.num--;
}

/*
 * Look for a free intr remap entry (or a contiguous set thereof).
 * Need hold iremap_lock, and setup returned entry before releasing lock.
 */
static unsigned int alloc_remap_entry(struct vtd_iommu *iommu, unsigned int nr)
{
    struct iremap_entry *iremap_entries = NULL;
    unsigned int i, found;

    ASSERT(spin_is_locked(&iommu->intremap.lock));

    for ( found = i = 0; i < IREMAP_ENTRY_NR; i++ )
    {
        struct iremap_entry *p;
        if ( i % (1 << IREMAP_ENTRY_ORDER) == 0 )
        {
            /* This entry across page boundry */
            if ( iremap_entries )
                unmap_vtd_domain_page(iremap_entries);

            GET_IREMAP_ENTRY(iommu->intremap.maddr, i,
                             iremap_entries, p);
        }
        else
            p = &iremap_entries[i % (1 << IREMAP_ENTRY_ORDER)];

        if ( p->val ) /* not a free entry */
            found = 0;
        else if ( ++found == nr )
            break;
    }

    if ( iremap_entries )
        unmap_vtd_domain_page(iremap_entries);

    if ( i < IREMAP_ENTRY_NR )
        iommu->intremap.num += nr;

    return i;
}

static int remap_entry_to_ioapic_rte(
    struct vtd_iommu *iommu, int index, struct IO_xAPIC_route_entry *old_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    unsigned long flags;

    if ( index < 0 || index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "IO-APIC index (%d) for remap table is invalid\n",
                index);
        return -EFAULT;
    }

    spin_lock_irqsave(&iommu->intremap.lock, flags);

    GET_IREMAP_ENTRY(iommu->intremap.maddr, index,
                     iremap_entries, iremap_entry);

    if ( iremap_entry->val == 0 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "IO-APIC index (%d) has an empty entry\n",
                index);
        unmap_vtd_domain_page(iremap_entries);
        spin_unlock_irqrestore(&iommu->intremap.lock, flags);
        return -EFAULT;
    }

    old_rte->vector = iremap_entry->remap.vector;
    old_rte->delivery_mode = iremap_entry->remap.dlm;
    old_rte->dest_mode = iremap_entry->remap.dm;
    old_rte->trigger = iremap_entry->remap.tm;
    old_rte->__reserved_2 = 0;
    if ( x2apic_enabled )
        old_rte->dest.dest32 = iremap_entry->remap.dst;
    else
    {
        old_rte->dest.logical.__reserved_1 = 0;
        old_rte->dest.logical.logical_dest = iremap_entry->remap.dst >> 8;
    }

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&iommu->intremap.lock, flags);

    return 0;
}

static int ioapic_rte_to_remap_entry(struct vtd_iommu *iommu,
    int apic, unsigned int ioapic_pin, struct IO_xAPIC_route_entry *old_rte,
    struct IO_xAPIC_route_entry new_rte)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries;
    struct iremap_entry new_ire;
    struct IO_APIC_route_remap_entry *remap_rte;
    int index;
    unsigned long flags;
    bool init = false, masked = old_rte->mask;

    remap_rte = (struct IO_APIC_route_remap_entry *) old_rte;
    spin_lock_irqsave(&iommu->intremap.lock, flags);

    index = apic_pin_2_ir_idx[apic][ioapic_pin];
    if ( index < 0 )
    {
        index = alloc_remap_entry(iommu, 1);
        if ( index < IREMAP_ENTRY_NR )
            apic_pin_2_ir_idx[apic][ioapic_pin] = index;
        init = true;
    }

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "IO-APIC intremap index (%d) larger than maximum index (%d)\n",
                index, IREMAP_ENTRY_NR - 1);
        spin_unlock_irqrestore(&iommu->intremap.lock, flags);
        return -EFAULT;
    }

    GET_IREMAP_ENTRY(iommu->intremap.maddr, index,
                     iremap_entries, iremap_entry);

    new_ire = *iremap_entry;

    if ( x2apic_enabled )
        new_ire.remap.dst = new_rte.dest.dest32;
    else
        new_ire.remap.dst = GET_xAPIC_ID(new_rte.dest.dest32) << 8;

    new_ire.remap.dm = new_rte.dest_mode;
    new_ire.remap.tm = new_rte.trigger;
    new_ire.remap.dlm = new_rte.delivery_mode;
    /* Hardware require RH = 1 for LPR delivery mode. */
    new_ire.remap.rh = (new_ire.remap.dlm == dest_LowestPrio);
    new_ire.remap.vector = new_rte.vector;

    set_ioapic_source_id(IO_APIC_ID(apic), &new_ire);
    /* Finally, set present bit. */
    new_ire.remap.p = 1;

    /* Now construct new ioapic rte entry. */
    remap_rte->vector = new_rte.vector;
    /* Has to be 0 for remap format. */
    remap_rte->delivery_mode = 0;
    remap_rte->index_15 = (index >> 15) & 0x1;
    remap_rte->index_0_14 = index & 0x7fff;

    remap_rte->delivery_status = new_rte.delivery_status;
    remap_rte->polarity = new_rte.polarity;
    remap_rte->irr = new_rte.irr;
    remap_rte->trigger = new_rte.trigger;
    remap_rte->mask = new_rte.mask;
    remap_rte->reserved = 0;
    /* Indicate remap format. */
    remap_rte->format = 1;

    update_irte(iommu, iremap_entry, &new_ire, !init && !masked);
    iommu_sync_cache(iremap_entry, sizeof(*iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&iommu->intremap.lock, flags);
    return 0;
}

unsigned int cf_check io_apic_read_remap_rte(
    unsigned int apic, unsigned int reg)
{
    unsigned int ioapic_pin = (reg - 0x10) / 2;
    int index;
    struct IO_xAPIC_route_entry old_rte = { };
    int rte_upper = (reg & 1) ? 1 : 0;
    struct vtd_iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));

    if ( !iommu->intremap.num ||
        ( (index = apic_pin_2_ir_idx[apic][ioapic_pin]) < 0 ) )
        return __io_apic_read(apic, reg);

    old_rte = __ioapic_read_entry(apic, ioapic_pin, true);

    if ( remap_entry_to_ioapic_rte(iommu, index, &old_rte) )
        return __io_apic_read(apic, reg);

    if ( rte_upper )
        return (*(((u32 *)&old_rte) + 1));
    else
        return (*(((u32 *)&old_rte) + 0));
}

void cf_check io_apic_write_remap_rte(
    unsigned int apic, unsigned int pin, uint64_t rte)
{
    struct IO_xAPIC_route_entry old_rte = {}, new_rte;
    struct vtd_iommu *iommu = ioapic_to_iommu(IO_APIC_ID(apic));
    int rc;

    /* Not the initializer, for old gcc to cope. */
    new_rte.raw = rte;

    rc = ioapic_rte_to_remap_entry(iommu, apic, pin, &old_rte, new_rte);
    if ( rc )
        return;

    /* old_rte will contain the updated IO-APIC RTE on success. */
    __ioapic_write_entry(apic, pin, true, old_rte);
}

static int set_msi_source_id(const struct pci_dev *pdev,
                             struct iremap_entry *ire)
{
    u16 seg;
    u8 bus, devfn, secbus;
    int ret;

    seg = pdev->seg;
    bus = pdev->bus;
    devfn = pdev->devfn;
    switch ( pdev->type )
    {
        unsigned int sq;

    case DEV_TYPE_PCIe_ENDPOINT:
    case DEV_TYPE_PCIe_BRIDGE:
    case DEV_TYPE_PCIe2PCI_BRIDGE:
    case DEV_TYPE_PCI_HOST_BRIDGE:
        switch ( pdev->phantom_stride )
        {
        case 1: sq = SQ_13_IGNORE_3; break;
        case 2: sq = SQ_13_IGNORE_2; break;
        case 4: sq = SQ_13_IGNORE_1; break;
        default: sq = SQ_ALL_16; break;
        }
        set_ire_sid(ire, SVT_VERIFY_SID_SQ, sq, PCI_BDF(bus, devfn));
        break;

    case DEV_TYPE_PCI:
    case DEV_TYPE_LEGACY_PCI_BRIDGE:
    case DEV_TYPE_PCI2PCIe_BRIDGE:
        ret = find_upstream_bridge(seg, &bus, &devfn, &secbus);
        if ( ret == 0 ) /* integrated PCI device */
        {
            set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                        PCI_BDF(bus, devfn));
        }
        else if ( ret == 1 ) /* found upstream bridge */
        {
            if ( pdev_type(seg, bus, devfn) == DEV_TYPE_PCIe2PCI_BRIDGE )
                set_ire_sid(ire, SVT_VERIFY_BUS, SQ_ALL_16,
                            (bus << 8) | pdev->bus);
            else
                set_ire_sid(ire, SVT_VERIFY_SID_SQ, SQ_ALL_16,
                            PCI_BDF(bus, devfn));
        }
        else
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "%pd: no upstream bridge for %pp\n",
                    pdev->domain, &pdev->sbdf);
            return -ENXIO;
        }
        break;

    default:
        dprintk(XENLOG_WARNING VTDPREFIX, "%pd: %pp unknown device type %d\n",
                pdev->domain, &pdev->sbdf, pdev->type);
        return -EOPNOTSUPP;
    }

    return 0;
}

static int msi_msg_to_remap_entry(
    struct vtd_iommu *iommu, struct pci_dev *pdev,
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct iremap_entry *iremap_entry = NULL, *iremap_entries, new_ire = { };
    struct msi_msg_remap_entry *remap_rte;
    unsigned int index, i, nr = 1;
    unsigned long flags;
    const struct pi_desc *pi_desc = msi_desc->pi_desc;
    bool alloc = false;

    if ( pdev )
    {
        int rc = set_msi_source_id(pdev, &new_ire);

        if ( rc )
            return rc;
    }
    else
        set_hpet_source_id(msi_desc->hpet_id, &new_ire);

    if ( msi_desc->msi_attrib.type == PCI_CAP_ID_MSI )
        nr = msi_desc->msi.nvec;

    spin_lock_irqsave(&iommu->intremap.lock, flags);

    if ( msg == NULL )
    {
        /* Free specified unused IRTEs */
        for ( i = 0; i < nr; ++i )
        {
            free_remap_entry(iommu, msi_desc->remap_index + i);
            msi_desc[i].irte_initialized = false;
        }
        spin_unlock_irqrestore(&iommu->intremap.lock, flags);
        return 0;
    }

    if ( msi_desc->remap_index < 0 )
    {
        index = alloc_remap_entry(iommu, nr);
        for ( i = 0; i < nr; ++i )
            msi_desc[i].remap_index = index + i;
        alloc = true;
    }
    else
        index = msi_desc->remap_index;

    if ( index > IREMAP_ENTRY_NR - 1 )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "MSI intremap index (%d) larger than maximum index (%d)!\n",
                index, IREMAP_ENTRY_NR - 1);
        for ( i = 0; i < nr; ++i )
            msi_desc[i].remap_index = -1;
        spin_unlock_irqrestore(&iommu->intremap.lock, flags);

        return -EFAULT;
    }

    GET_IREMAP_ENTRY(iommu->intremap.maddr, index,
                     iremap_entries, iremap_entry);

    if ( !pi_desc )
    {
        new_ire.remap.dm = msg->address_lo >> MSI_ADDR_DESTMODE_SHIFT;
        new_ire.remap.tm = msg->data >> MSI_DATA_TRIGGER_SHIFT;
        new_ire.remap.dlm = msg->data >> MSI_DATA_DELIVERY_MODE_SHIFT;
        /* Hardware requires RH = 1 for lowest priority delivery mode */
        new_ire.remap.rh = (new_ire.remap.dlm == dest_LowestPrio);
        new_ire.remap.vector = (msg->data >> MSI_DATA_VECTOR_SHIFT) &
                                MSI_DATA_VECTOR_MASK;
        if ( x2apic_enabled )
            new_ire.remap.dst = msg->dest32;
        else
            new_ire.remap.dst =
                MASK_EXTR(msg->address_lo, MSI_ADDR_DEST_ID_MASK) << 8;
        new_ire.remap.p = 1;
    }
    else
    {
        new_ire.post.im = 1;
        new_ire.post.vector = msi_desc->gvec;
        new_ire.post.pda_l = virt_to_maddr(pi_desc) >> (32 - PDA_LOW_BIT);
        new_ire.post.pda_h = virt_to_maddr(pi_desc) >> 32;
        new_ire.post.p = 1;
    }

    /* now construct new MSI/MSI-X rte entry */
    remap_rte = (struct msi_msg_remap_entry *)msg;
    remap_rte->address_lo.dontcare = 0;
    i = index;
    if ( !nr )
        i -= msi_desc->msi_attrib.entry_nr;
    remap_rte->address_lo.index_15 = (i >> 15) & 0x1;
    remap_rte->address_lo.index_0_14 = i & 0x7fff;
    remap_rte->address_lo.SHV = 1;
    remap_rte->address_lo.format = 1;

    remap_rte->address_hi = 0;
    remap_rte->data = index - i;

    update_irte(iommu, iremap_entry, &new_ire, msi_desc->irte_initialized);
    msi_desc->irte_initialized = true;

    iommu_sync_cache(iremap_entry, sizeof(*iremap_entry));
    iommu_flush_iec_index(iommu, 0, index);

    unmap_vtd_domain_page(iremap_entries);
    spin_unlock_irqrestore(&iommu->intremap.lock, flags);

    return alloc;
}

int cf_check msi_msg_write_remap_rte(
    struct msi_desc *msi_desc, struct msi_msg *msg)
{
    struct pci_dev *pdev = msi_desc->dev;
    struct acpi_drhd_unit *drhd = NULL;

    drhd = pdev ? acpi_find_matched_drhd_unit(pdev)
                : hpet_to_drhd(msi_desc->hpet_id);
    return drhd ? msi_msg_to_remap_entry(drhd->iommu, pdev, msi_desc, msg)
                : -EINVAL;
}

int __init cf_check intel_setup_hpet_msi(struct msi_desc *msi_desc)
{
    struct vtd_iommu *iommu = hpet_to_iommu(msi_desc->hpet_id);
    unsigned long flags;
    int rc = 0;

    if ( !iommu->intremap.maddr )
        return 0;

    spin_lock_irqsave(&iommu->intremap.lock, flags);
    msi_desc->remap_index = alloc_remap_entry(iommu, 1);
    if ( msi_desc->remap_index >= IREMAP_ENTRY_NR )
    {
        dprintk(XENLOG_ERR VTDPREFIX,
                "HPET intremap index (%d) larger than maximum index (%d)!\n",
                msi_desc->remap_index, IREMAP_ENTRY_NR - 1);
        msi_desc->remap_index = -1;
        rc = -ENXIO;
    }
    spin_unlock_irqrestore(&iommu->intremap.lock, flags);

    return rc;
}

int enable_intremap(struct vtd_iommu *iommu, int eim)
{
    u32 sts, gcmd;
    unsigned long flags;

    ASSERT(ecap_intr_remap(iommu->ecap) && iommu_intremap);

    if ( !platform_supports_intremap() )
    {
        printk(XENLOG_ERR VTDPREFIX
               " Platform firmware does not support interrupt remapping\n");
        return -EINVAL;
    }

    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);

    /* Return if already enabled by Xen */
    if ( (sts & DMA_GSTS_IRES) && iommu->intremap.maddr )
        return 0;

    if ( !(sts & DMA_GSTS_QIES) )
    {
        printk(XENLOG_ERR VTDPREFIX
               " Queued invalidation is not enabled on IOMMU #%u:"
               " Should not enable interrupt remapping\n", iommu->index);
        return -EINVAL;
    }

    if ( !eim && (sts & DMA_GSTS_CFIS) )
        printk(XENLOG_WARNING VTDPREFIX
               " Compatibility Format Interrupts permitted on IOMMU #%u:"
               " Device pass-through will be insecure\n", iommu->index);

    if ( iommu->intremap.maddr == 0 )
    {
        iommu->intremap.maddr = alloc_pgtable_maddr(IREMAP_ARCH_PAGE_NR,
                                                    iommu->node);
        if ( iommu->intremap.maddr == 0 )
        {
            dprintk(XENLOG_WARNING VTDPREFIX,
                    "Cannot allocate memory for ir_ctrl->iremap_maddr\n");
            return -ENOMEM;
        }

        iommu->intremap.num = 0;
    }

    spin_lock_irqsave(&iommu->register_lock, flags);

    /*
     * Set size of the interrupt remapping table and optionally Extended
     * Interrupt Mode.
     */
    dmar_writeq(iommu->reg, DMAR_IRTA_REG,
                iommu->intremap.maddr | IRTA_REG_TABLE_SIZE |
                (eim ? IRTA_EIME : 0));

    /* set SIRTP */
    gcmd = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    gcmd |= DMA_GCMD_SIRTP;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, gcmd);

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_SIRTPS), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    /* After set SIRTP, must globally invalidate the interrupt entry cache */
    iommu_flush_iec_global(iommu);

    spin_lock_irqsave(&iommu->register_lock, flags);
    /* enable interrupt remapping hardware */
    gcmd |= DMA_GCMD_IRE;
    dmar_writel(iommu->reg, DMAR_GCMD_REG, gcmd);

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  (sts & DMA_GSTS_IRES), sts);
    spin_unlock_irqrestore(&iommu->register_lock, flags);

    return init_apic_pin_2_ir_idx();
}

void disable_intremap(struct vtd_iommu *iommu)
{
    u32 sts;
    u64 irta;
    unsigned long flags;

    if ( !ecap_intr_remap(iommu->ecap) )
        return;

    spin_lock_irqsave(&iommu->register_lock, flags);
    sts = dmar_readl(iommu->reg, DMAR_GSTS_REG);
    if ( !(sts & DMA_GSTS_IRES) )
        goto out;

    dmar_writel(iommu->reg, DMAR_GCMD_REG, sts & (~DMA_GCMD_IRE));

    IOMMU_WAIT_OP(iommu, DMAR_GSTS_REG, dmar_readl,
                  !(sts & DMA_GSTS_IRES), sts);

    /* If we are disabling Interrupt Remapping, make sure we dont stay in
     * Extended Interrupt Mode, as this is unaffected by the Interrupt
     * Remapping flag in each DMAR Global Control Register.
     * Specifically, local apics in xapic mode do not like interrupts delivered
     * in x2apic mode.  Any code turning interrupt remapping back on will set
     * EIME back correctly.
     */
    if ( !ecap_eim(iommu->ecap) )
        goto out;

    /* Can't read the register unless we ecaps says we can */
    irta = dmar_readl(iommu->reg, DMAR_IRTA_REG);
    if ( !(irta & IRTA_EIME) )
        goto out;

    dmar_writel(iommu->reg, DMAR_IRTA_REG, irta & ~IRTA_EIME);
    IOMMU_WAIT_OP(iommu, DMAR_IRTA_REG, dmar_readl,
                  !(irta & IRTA_EIME), irta);

out:
    spin_unlock_irqrestore(&iommu->register_lock, flags);
}

/*
 * This function is used to enable Interrupt remapping when
 * enable x2apic
 */
int cf_check intel_iommu_enable_eim(void)
{
    struct acpi_drhd_unit *drhd;
    struct vtd_iommu *iommu;

    if ( system_state < SYS_STATE_active && !platform_supports_x2apic() )
        return -ENXIO;

    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;

        /* Clear previous faults */
        clear_fault_bits(iommu);

        /*
         * Disable interrupt remapping and queued invalidation if
         * already enabled by BIOS
         */
        disable_intremap(iommu);
        disable_qinval(iommu);
    }

    /* Enable queue invalidation */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( enable_qinval(iommu) != 0 )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "Failed to enable Queued Invalidation!\n");
            return -EIO;
        }
    }

    /* Enable interrupt remapping */
    for_each_drhd_unit ( drhd )
    {
        iommu = drhd->iommu;
        if ( enable_intremap(iommu, 1) )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "Failed to enable Interrupt Remapping!\n");
            return -EIO;
        }
    }

    return 0;
}

/*
 * This function is used to disable Interrupt remapping when
 * suspend local apic
 */
void cf_check intel_iommu_disable_eim(void)
{
    struct acpi_drhd_unit *drhd;

    for_each_drhd_unit ( drhd )
        disable_intremap(drhd->iommu);

    for_each_drhd_unit ( drhd )
        disable_qinval(drhd->iommu);
}
