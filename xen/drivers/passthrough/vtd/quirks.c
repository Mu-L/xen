/*
 * Copyright (c) 2010, Intel Corporation.
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
 * Author: Allen Kay <allen.m.kay@intel.com>
 */

#include <xen/irq.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <xen/numa.h>
#include <xen/softirq.h>
#include <xen/time.h>
#include <xen/pci.h>
#include <xen/pci_ids.h>
#include <xen/pci_regs.h>
#include <xen/keyhandler.h>
#include <asm/msi.h>
#include <asm/intel-family.h>
#include <asm/irq.h>
#include <asm/pci.h>

#include "iommu.h"
#include "dmar.h"
#include "extern.h"
#include "vtd.h"

#define IOH_DEV      PCI_SBDF(0, 0, 0, 0)
#define IGD_DEV      PCI_SBDF(0, 0, 2, 0)

#define IGD_BAR_MASK 0xFFFFFFFFFFFF0000
#define GGC 0x52
#define GGC_MEMORY_VT_ENABLED  (0x8 << 8)

#define IS_CTG(id)    (id == 0x2a408086)
#define IS_ILK(id)    (id == 0x00408086 || id == 0x00448086 || id== 0x00628086 || id == 0x006A8086)
#define IS_CPT(id)    (id == 0x01008086 || id == 0x01048086)

/* SandyBridge IGD timeouts in milliseconds */
#define SNB_IGD_TIMEOUT_LEGACY    1000
#define SNB_IGD_TIMEOUT            670
static unsigned int snb_igd_timeout;

static u32 __read_mostly ioh_id;
static u32 __initdata igd_id;
bool __read_mostly rwbf_quirk;
static bool __read_mostly is_cantiga_b3;
static bool __read_mostly is_snb_gfx;
static u8 *__read_mostly igd_reg_va;
static spinlock_t igd_lock;

/*
 * QUIRK to workaround Xen boot issue on Calpella/Ironlake OEM BIOS
 * not enabling VT-d properly in IGD.  The workaround is to not enabling
 * IGD VT-d translation if VT is not enabled in IGD.
 */
int is_igd_vt_enabled_quirk(void)
{
    u16 ggc;

    if ( !IS_ILK(ioh_id) )
        return 1;

    /* integrated graphics on Intel platforms is located at 0:2.0 */
    ggc = pci_conf_read16(IGD_DEV, GGC);
    return ( ggc & GGC_MEMORY_VT_ENABLED ? 1 : 0 );
}

/*
 * QUIRK to workaround cantiga VT-d buffer flush issue.
 * The workaround is to force write buffer flush even if
 * VT-d capability indicates it is not required.
 */
static void __init cantiga_b3_errata_init(void)
{
    u16 vid;
    u8 did_hi, rid;

    vid = pci_conf_read16(IGD_DEV, 0);
    if ( vid != 0x8086 )
        return;

    did_hi = pci_conf_read8(IGD_DEV, 3);
    rid = pci_conf_read8(IGD_DEV, 8);

    if ( (did_hi == 0x2A) && (rid == 0x7) )
        is_cantiga_b3 = 1;
}

/*
 * QUIRK to work around certain BIOSes enabling the ISOCH DMAR unit for the
 * Azalia sound device, but not giving it any TLB entries, causing it to
 * deadlock.
 */
bool is_azalia_tlb_enabled(const struct acpi_drhd_unit *drhd)
{
    pci_sbdf_t sbdf;
    unsigned int vtisochctrl;

    /* Only dedicated units are of interest. */
    if ( drhd->include_all || drhd->scope.devices_cnt != 1 )
        return true;

    /* Check for the specific device. */
    sbdf = PCI_SBDF(drhd->segment, drhd->scope.devices[0]);
    if ( pci_conf_read16(sbdf, PCI_VENDOR_ID) != PCI_VENDOR_ID_INTEL ||
         pci_conf_read16(sbdf, PCI_DEVICE_ID) != 0x3a3e )
        return true;

    /* Check for the corresponding System Management Registers device. */
    sbdf = PCI_SBDF(drhd->segment, 0, 0x14, 0);
    if ( pci_conf_read16(sbdf, PCI_VENDOR_ID) != PCI_VENDOR_ID_INTEL ||
         pci_conf_read16(sbdf, PCI_DEVICE_ID) != 0x342e )
        return true;

    vtisochctrl = pci_conf_read32(sbdf, 0x188);
    if ( vtisochctrl == 0xffffffff )
    {
        printk(XENLOG_WARNING VTDPREFIX
               " Cannot access VTISOCHCTRL at this time\n");
        return true;
    }

    /*
     * If Azalia DMA is routed to the non-isoch DMAR unit, that's fine in
     * principle, but not consistent with the ACPI tables.
     */
    if ( vtisochctrl & 1 )
    {
        printk(XENLOG_WARNING VTDPREFIX
               " Inconsistency between chipset registers and ACPI tables\n");
        return true;
    }

    /* Drop all bits other than the number of TLB entries. */
    vtisochctrl &= 0x1c;

    /* If we have at least the recommended number of TLB entries, fine. */
    if ( vtisochctrl >= 16 )
        return true;

    /* Zero TLB entries? */
    if ( !vtisochctrl )
        return false;

    printk(XENLOG_WARNING VTDPREFIX
           " Recommended TLB entries for ISOCH unit is 16; firmware set %u\n",
           vtisochctrl);

    return true;
}

/* check for Sandybridge IGD device ID's */
static void __init snb_errata_init(void)
{
    is_snb_gfx = IS_SNB_GFX(igd_id);
    spin_lock_init(&igd_lock);
}

/*
 * QUIRK to workaround Cantiga IGD VT-d low power errata.
 * This errata impacts IGD assignment on Cantiga systems
 * and can potentially cause VT-d operations to hang.
 * The workaround is to access an IGD PCI config register
 * to get IGD out of low power state before VT-d translation
 * enable/disable and IOTLB flushes.
 */

/*
 * map IGD MMIO+0x2000 page to allow Xen access to IGD 3D register.
 */
static void __init map_igd_reg(void)
{
    u64 igd_mmio;

    if ( !is_cantiga_b3 && !is_snb_gfx )
        return;

    if ( igd_reg_va )
        return;

    igd_mmio   = pci_conf_read32(IGD_DEV, PCI_BASE_ADDRESS_1);
    igd_mmio <<= 32;
    igd_mmio  += pci_conf_read32(IGD_DEV, PCI_BASE_ADDRESS_0);
    igd_reg_va = ioremap(igd_mmio & IGD_BAR_MASK, 0x3000);
}

/*
 * force IGD to exit low power mode by accessing a IGD 3D regsiter.
 */
static int cantiga_vtd_ops_preamble(struct vtd_iommu *iommu)
{
    struct acpi_drhd_unit *drhd = iommu->drhd;

    if ( !is_igd_drhd(drhd) || !is_cantiga_b3 )
        return 0;

    if ( !igd_reg_va )
        return 0;

    /*
     * Read IGD register at IGD MMIO + 0x20A4 to force IGD
     * to exit low power state.
     */
    return *(volatile int *)(igd_reg_va + 0x20A4);
}

/*
 * Sandybridge RC6 power management inhibit state erratum.
 * This can cause power high power consumption.
 * Workaround is to prevent graphics get into RC6
 * state when doing VT-d IOTLB operations, do the VT-d
 * IOTLB operation, and then re-enable RC6 state.
 *
 * This quirk is enabled with the snb_igd_quirk command
 * line parameter.  Specifying snb_igd_quirk with no value
 * (or any of the standard boolean values) enables this
 * quirk and sets the timeout to the legacy timeout of
 * 1000 msec.  Setting this parameter to the string
 * "cap" enables this quirk and sets the timeout to
 * the theoretical maximum of 670 msec.  Setting this
 * parameter to a numerical value enables the quirk and
 * sets the timeout to that numerical number of msecs.
 */
static void snb_vtd_ops_preamble(struct vtd_iommu *iommu)
{
    struct acpi_drhd_unit *drhd = iommu->drhd;
    s_time_t start_time;

    if ( !is_igd_drhd(drhd) || !is_snb_gfx )
        return;

    if ( !igd_reg_va )
        return;

    *(volatile u32 *)(igd_reg_va + 0x2054) = 0x000FFFFF;
    *(volatile u32 *)(igd_reg_va + 0x2700) = 0;

    start_time = NOW();
    while ( (*(volatile u32 *)(igd_reg_va + 0x22AC) & 0xF) != 0 )
    {
        if ( NOW() > start_time + snb_igd_timeout )
        {
            dprintk(XENLOG_INFO VTDPREFIX,
                    "snb_vtd_ops_preamble: failed to disable idle handshake\n");
            break;
        }
        cpu_relax();
    }

    *(volatile u32 *)(igd_reg_va + 0x2050) = 0x10001;
}

static void snb_vtd_ops_postamble(struct vtd_iommu *iommu)
{
    struct acpi_drhd_unit *drhd = iommu->drhd;

    if ( !is_igd_drhd(drhd) || !is_snb_gfx )
        return;

    if ( !igd_reg_va )
        return;

    *(volatile u32 *)(igd_reg_va + 0x2054) = 0xA;
    *(volatile u32 *)(igd_reg_va + 0x2050) = 0x10000;
}

/*
 * call before VT-d translation enable and IOTLB flush operations.
 */

void vtd_ops_preamble_quirk(struct vtd_iommu *iommu)
{
    cantiga_vtd_ops_preamble(iommu);
    if ( snb_igd_timeout != 0 )
    {
        spin_lock(&igd_lock);

        /* match unlock in postamble */
        snb_vtd_ops_preamble(iommu);
    }
}

/*
 * call after VT-d translation enable and IOTLB flush operations.
 */
void vtd_ops_postamble_quirk(struct vtd_iommu *iommu)
{
    if ( snb_igd_timeout != 0 )
    {
        snb_vtd_ops_postamble(iommu);

        /* match the lock in preamble */
        spin_unlock(&igd_lock);
    }
}

static int __init cf_check parse_snb_timeout(const char *s)
{
    int t;
    const char *q = NULL;

    t = parse_bool(s, NULL);
    if ( t < 0 )
    {
        if ( *s == '\0' )
            t = SNB_IGD_TIMEOUT_LEGACY;
        else if ( strcmp(s, "cap") == 0 )
            t = SNB_IGD_TIMEOUT;
        else
            t = simple_strtoul(s, &q, 0);
    }
    else
        t = t ? SNB_IGD_TIMEOUT_LEGACY : 0;
    snb_igd_timeout = MILLISECS(t);

    return (q && *q) ? -EINVAL : 0;
}
custom_param("snb_igd_quirk", parse_snb_timeout);

/*
 * 5500/5520/X58 chipset interrupt remapping errata, for steppings B2 and B3.
 * Fixed in stepping C2 except on X58.
 */
static void __init tylersburg_intremap_quirk(void)
{
    unsigned int bus;
    uint8_t rev;

    for ( bus = 0; bus < 0x100; bus++ )
    {
        /* Match on DMI port (Device 0 Function 0) */
        rev = pci_conf_read8(PCI_SBDF(0, bus, 0, 0), PCI_REVISION_ID);

        switch ( pci_conf_read32(PCI_SBDF(0, bus, 0, 0), PCI_VENDOR_ID) )
        {
        default:
            continue;

        case 0x34038086: case 0x34068086:
            if ( rev >= 0x22 )
                continue;
            printk(XENLOG_WARNING VTDPREFIX
                   "Disabling IOMMU due to Intel 5500/5520 chipset errata #47 and #53\n");
            iommu_enable = false;
            break;

        case 0x34058086:
            printk(XENLOG_WARNING VTDPREFIX
                   "Disabling IOMMU due to Intel X58 chipset %s\n",
                   rev < 0x22 ? "errata #62 and #69" : "erratum #69");
            iommu_enable = false;
            break;
        }

        break;
    }
}

/* initialize platform identification flags */
void __init platform_quirks_init(void)
{
    ioh_id = pci_conf_read32(IOH_DEV, 0);
    igd_id = pci_conf_read32(IGD_DEV, 0);

    /* Mobile 4 Series Chipset neglects to set RWBF capability. */
    if ( ioh_id == 0x2a408086 )
    {
        dprintk(XENLOG_INFO VTDPREFIX, "DMAR: Forcing write-buffer flush\n");
        rwbf_quirk = 1;
    }

    /* initialize cantiga B3 identification */
    cantiga_b3_errata_init();

    snb_errata_init();

    /* ioremap IGD MMIO+0x2000 page */
    map_igd_reg();

    /* Tylersburg interrupt remap quirk */
    if ( iommu_intremap != iommu_intremap_off )
        tylersburg_intremap_quirk();
}

/*
 * QUIRK to workaround wifi direct assignment issue.  This issue
 * impacts only cases where Intel integrated wifi device is directly
 * is directly assigned to a guest.
 *
 * The workaround is to map ME phantom device 0:3.7 or 0:22.7
 * to the ME vt-d engine if detect the user is trying to directly
 * assigning Intel integrated wifi device to a guest.
 */

static int __must_check map_me_phantom_function(struct domain *domain,
                                                unsigned int dev,
                                                domid_t domid,
                                                paddr_t pgd_maddr,
                                                unsigned int mode)
{
    struct acpi_drhd_unit *drhd;
    struct pci_dev *pdev;
    int rc;

    /* find ME VT-d engine base on a real ME device */
    pdev = pci_get_pdev(NULL, PCI_SBDF(0, 0, dev, 0));
    drhd = acpi_find_matched_drhd_unit(pdev);

    /* map or unmap ME phantom function */
    if ( !(mode & UNMAP_ME_PHANTOM_FUNC) )
        rc = domain_context_mapping_one(domain, drhd->iommu, 0,
                                        PCI_DEVFN(dev, 7), NULL,
                                        domid, pgd_maddr, mode);
    else
        rc = domain_context_unmap_one(domain, drhd->iommu, 0,
                                      PCI_DEVFN(dev, 7));

    return rc;
}

int me_wifi_quirk(struct domain *domain, uint8_t bus, uint8_t devfn,
                  domid_t domid, paddr_t pgd_maddr, unsigned int mode)
{
    u32 id;
    int rc = 0;

    id = pci_conf_read32(PCI_SBDF(0, 0, 0, 0), 0);
    if ( IS_CTG(id) )
    {
        /* quit if ME does not exist */
        if ( pci_conf_read32(PCI_SBDF(0, 0, 3, 0), 0) == 0xffffffff )
            return 0;

        /* if device is WLAN device, map ME phantom device 0:3.7 */
        id = pci_conf_read32(PCI_SBDF(0, bus, devfn), 0);
        switch (id)
        {
            case 0x42328086:
            case 0x42358086:
            case 0x42368086:
            case 0x42378086:
            case 0x423a8086:
            case 0x423b8086:
            case 0x423c8086:
            case 0x423d8086:
                rc = map_me_phantom_function(domain, 3, domid, pgd_maddr, mode);
                break;
            default:
                break;
        }
    }
    else if ( IS_ILK(id) || IS_CPT(id) )
    {
        /* quit if ME does not exist */
        if ( pci_conf_read32(PCI_SBDF(0, 0, 22, 0), 0) == 0xffffffff )
            return 0;

        /* if device is WLAN device, map ME phantom device 0:22.7 */
        id = pci_conf_read32(PCI_SBDF(0, bus, devfn), 0);
        switch (id)
        {
            case 0x00878086:        /* Kilmer Peak */
            case 0x00898086:
            case 0x00828086:        /* Taylor Peak */
            case 0x00858086:
            case 0x008F8086:        /* Rainbow Peak */
            case 0x00908086:
            case 0x00918086:
            case 0x42388086:        /* Puma Peak */
            case 0x422b8086:
            case 0x422c8086:
                rc = map_me_phantom_function(domain, 22, domid, pgd_maddr, mode);
                break;
            default:
                break;
        }
    }

    return rc;
}

void pci_vtd_quirk(const struct pci_dev *pdev)
{
    int pos;
    bool ff;
    u32 val, val2;
    u64 bar;
    paddr_t pa;
    const char *action;

    if ( pci_conf_read16(pdev->sbdf, PCI_VENDOR_ID) != PCI_VENDOR_ID_INTEL )
        return;

    switch ( pci_conf_read16(pdev->sbdf, PCI_DEVICE_ID) )
    {
    /*
     * Mask reporting Intel VT-d faults to IOH core logic:
     *   - Some platform escalates VT-d faults to platform errors.
     *   - This can cause system failure upon non-fatal VT-d faults.
     *   - Potential security issue if malicious guest trigger VT-d faults.
     */
    case 0x342e: /* Tylersburg chipset (Nehalem / Westmere systems) */
    case 0x3728: /* Xeon C5500/C3500 (JasperForest) */
    case 0x3c28: /* Sandybridge */
        val = pci_conf_read32(pdev->sbdf, 0x1AC);
        pci_conf_write32(pdev->sbdf, 0x1AC, val | (1U << 31));
        printk(XENLOG_INFO "Masked VT-d error signaling on %pp\n", &pdev->sbdf);
        break;

    /* Tylersburg (EP)/Boxboro (MP) chipsets (NHM-EP/EX, WSM-EP/EX) */
    case 0x3400 ... 0x3407: /* host bridges */
    case 0x3408 ... 0x3411: case 0x3420 ... 0x3421: /* root ports */
    /* JasperForest (Intel Xeon Processor C5500/C3500 */
    case 0x3700 ... 0x370f: /* host bridges */
    case 0x3720 ... 0x3724: /* root ports */
    /* Sandybridge-EP (Romley) */
    case 0x3c00: /* host bridge */
    case 0x3c01 ... 0x3c0b: /* root ports */
        pos = pci_find_ext_capability(pdev->sbdf, PCI_EXT_CAP_ID_ERR);
        if ( !pos )
        {
            pos = pci_find_ext_capability(pdev->sbdf, PCI_EXT_CAP_ID_VNDR);
            while ( pos )
            {
                val = pci_conf_read32(pdev->sbdf, pos + PCI_VNDR_HEADER);
                if ( PCI_VNDR_HEADER_ID(val) == 4 && PCI_VNDR_HEADER_REV(val) == 1 )
                {
                    pos += PCI_VNDR_HEADER;
                    break;
                }
                pos = pci_find_next_ext_capability(pdev->sbdf, pos,
                                                   PCI_EXT_CAP_ID_VNDR);
            }
            ff = 0;
        }
        else
            ff = pcie_aer_get_firmware_first(pdev);
        if ( !pos )
        {
            printk(XENLOG_WARNING "%pp without AER capability?\n", &pdev->sbdf);
            break;
        }

        val = pci_conf_read32(pdev->sbdf, pos + PCI_ERR_UNCOR_MASK);
        val2 = pci_conf_read32(pdev->sbdf, pos + PCI_ERR_COR_MASK);
        if ( (val & PCI_ERR_UNC_UNSUP) && (val2 & PCI_ERR_COR_ADV_NFAT) )
            action = "Found masked";
        else if ( !ff )
        {
            pci_conf_write32(pdev->sbdf, pos + PCI_ERR_UNCOR_MASK,
                             val | PCI_ERR_UNC_UNSUP);
            pci_conf_write32(pdev->sbdf, pos + PCI_ERR_COR_MASK,
                             val2 | PCI_ERR_COR_ADV_NFAT);
            action = "Masked";
        }
        else
            action = "Must not mask";

        /* XPUNCERRMSK Send Completion with Unsupported Request */
        val = pci_conf_read32(pdev->sbdf, 0x20c);
        pci_conf_write32(pdev->sbdf, 0x20c, val | (1 << 4));

        printk(XENLOG_INFO "%s UR signaling on %pp\n", action, &pdev->sbdf);
        break;

    case 0x0040: case 0x0044: case 0x0048: /* Nehalem/Westmere */
    case 0x0100: case 0x0104: case 0x0108: /* Sandybridge */
    case 0x0150: case 0x0154: case 0x0158: /* Ivybridge */
    case 0x0a00: case 0x0a04: case 0x0a08: case 0x0a0f: /* Haswell ULT */
    case 0x0c00: case 0x0c04: case 0x0c08: case 0x0c0f: /* Haswell */
    case 0x0d00: case 0x0d04: case 0x0d08: case 0x0d0f: /* Haswell */
    case 0x1600: case 0x1604: case 0x1608: case 0x160f: /* Broadwell */
    case 0x1610: case 0x1614: case 0x1618: /* Broadwell */
    case 0x1900: case 0x1904: case 0x1908: case 0x190c: case 0x190f: /* Skylake */
    case 0x1910: case 0x1918: case 0x191f: /* Skylake */
        bar = pci_conf_read32(pdev->sbdf, 0x6c);
        bar = (bar << 32) | pci_conf_read32(pdev->sbdf, 0x68);
        pa = bar & 0x7ffffff000UL; /* bits 12...38 */
        if ( (bar & 1) && pa &&
             page_is_ram_type(paddr_to_pfn(pa), RAM_TYPE_RESERVED) )
        {
            u32 __iomem *va = ioremap(pa, PAGE_SIZE);

            if ( va )
            {
                __set_bit(0x1c8 * 8 + 20, va);
                iounmap(va);
                printk(XENLOG_INFO "Masked UR signaling on %pp\n", &pdev->sbdf);
            }
            else
                printk(XENLOG_ERR "Could not map %"PRIpaddr" for %pp\n",
                       pa, &pdev->sbdf);
        }
        else
            printk(XENLOG_WARNING "Bogus DMIBAR %#"PRIx64" on %pp\n",
                   bar, &pdev->sbdf);
        break;
    }
}

void __init quirk_iommu_caps(struct vtd_iommu *iommu)
{
    /*
     * IOMMU Quirks:
     *
     * SandyBridge IOMMUs claim support for 2M and 1G superpages, but don't
     * implement superpages internally.
     *
     * There are issues changing the walk length under in-flight DMA, which
     * has manifested as incompatibility between EPT/IOMMU sharing and the
     * workaround for CVE-2018-12207 / XSA-304.  Hide the superpages
     * capabilities in the IOMMU, which will prevent Xen from sharing the EPT
     * and IOMMU pagetables.
     *
     * Detection of SandyBridge unfortunately has to be done by processor
     * model because the client parts don't expose their IOMMUs as PCI devices
     * we could match with a Device ID.
     */
    if ( boot_cpu_data.vfm == INTEL_SANDYBRIDGE ||
         boot_cpu_data.vfm == INTEL_SANDYBRIDGE_X )
        iommu->cap &= ~(0xful << 34);
}
