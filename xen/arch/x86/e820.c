#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/param.h>
#include <xen/compat.h>
#include <xen/dmi.h>
#include <xen/pfn.h>
#include <asm/e820.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/mtrr.h>
#include <asm/msr.h>
#include <asm/guest.h>

/*
 * opt_mem: Limit maximum address of physical RAM.
 *          Any RAM beyond this address limit is ignored.
 */
static unsigned long long __initdata opt_mem;
size_param("mem", opt_mem);

/*
 * opt_availmem: Limit maximum usable amount of physical RAM.
 *               Any RAM beyond this limited amount is ignored.
 */
static unsigned long long __initdata opt_availmem;
size_param("availmem", opt_availmem);

/* opt_nomtrr_check: Don't clip ram to highest cacheable MTRR. */
static int8_t __initdata e820_mtrr_clip = -1;
boolean_param("e820-mtrr-clip", e820_mtrr_clip);

/* opt_e820_verbose: Be verbose about clipping, the original e820, &c */
static bool __initdata e820_verbose;
boolean_param("e820-verbose", e820_verbose);

struct e820map e820;
struct e820map __initdata e820_raw;

/*
 * This function checks if the entire range [start,end) is mapped with type.
 *
 * Note: this function only works correct if the e820 table is sorted and
 * not-overlapping, which is the case
 */
int __init e820_all_mapped(u64 start, u64 end, unsigned type)
{
	unsigned int i;

	for (i = 0; i < e820.nr_map; i++) {
		struct e820entry *ei = &e820.map[i];

		if (type && ei->type != type)
			continue;
		/* is the region (part) in overlap with the current region ?*/
		if (ei->addr >= end || ei->addr + ei->size <= start)
			continue;

		/*
		 * If the region is at the beginning of [start,end) we move
		 * start to the end of the region since it's ok until there
		 */
		if (ei->addr <= start)
			start = ei->addr + ei->size;
		/*
		 * if start is now at or beyond end, we're done, full
		 * coverage
		 */
		if (start >= end)
			return 1;
	}
	return 0;
}

static void __init add_memory_region(unsigned long long start,
                                     unsigned long long size, int type)
{
    unsigned int x = e820.nr_map;

    if (x == ARRAY_SIZE(e820.map)) {
        printk(KERN_ERR "Ooops! Too many entries in the memory map!\n");
        return;
    }

    e820.map[x].addr = start;
    e820.map[x].size = size;
    e820.map[x].type = type;
    e820.nr_map++;
}

void __init print_e820_memory_map(const struct e820entry *map,
                                  unsigned int entries)
{
    unsigned int i;

    for (i = 0; i < entries; i++) {
        printk(" [%016Lx, %016Lx] ",
               (unsigned long long)(map[i].addr),
               (unsigned long long)(map[i].addr + map[i].size) - 1);
        switch (map[i].type) {
        case E820_RAM:
            printk("(usable)\n");
            break;
        case E820_RESERVED:
            printk("(reserved)\n");
            break;
        case E820_ACPI:
            printk("(ACPI data)\n");
            break;
        case E820_NVS:
            printk("(ACPI NVS)\n");
            break;
        case E820_UNUSABLE:
            printk("(unusable)\n");
            break;
        default:
            printk("type %u\n", map[i].type);
            break;
        }
    }
}

/*
 * Sanitize the BIOS e820 map.
 *
 * Some e820 responses include overlapping entries.  The following 
 * replaces the original e820 map with a new one, removing overlaps.
 *
 */
struct change_member {
    struct e820entry *pbios; /* pointer to original bios entry */
    unsigned long long addr; /* address for this change point */
};
static struct change_member change_point_list[2*E820MAX] __initdata;
static struct change_member *change_point[2*E820MAX] __initdata;
static struct e820entry *overlap_list[E820MAX] __initdata;
static struct e820entry new_bios[E820MAX] __initdata;

int __init sanitize_e820_map(struct e820entry *biosmap, unsigned int *pnr_map)
{
    struct change_member *change_tmp;
    unsigned long current_type, last_type;
    unsigned long long last_addr;
    bool still_changing;
    unsigned int i, chgidx, overlap_entries, new_bios_entry;
    unsigned int old_nr, new_nr, chg_nr;

    /*
      Visually we're performing the following (1,2,3,4 = memory types)...

      Sample memory map (w/overlaps):
      ____22__________________
      ______________________4_
      ____1111________________
      _44_____________________
      11111111________________
      ____________________33__
      ___________44___________
      __________33333_________
      ______________22________
      ___________________2222_
      _________111111111______
      _____________________11_
      _________________4______

      Sanitized equivalent (no overlap):
      1_______________________
      _44_____________________
      ___1____________________
      ____22__________________
      ______11________________
      _________1______________
      __________3_____________
      ___________44___________
      _____________33_________
      _______________2________
      ________________1_______
      _________________4______
      ___________________2____
      ____________________33__
      ______________________4_
    */

    /* if there's only one memory region, don't bother */
    if (*pnr_map < 2)
        return -1;

    old_nr = *pnr_map;

    /* bail out if we find any unreasonable addresses in bios map */
    for (i=0; i<old_nr; i++)
        if (biosmap[i].addr + biosmap[i].size < biosmap[i].addr)
            return -1;

    /* create pointers for initial change-point information (for sorting) */
    for (i=0; i < 2*old_nr; i++)
        change_point[i] = &change_point_list[i];

    /* record all known change-points (starting and ending addresses),
       omitting those that are for empty memory regions */
    chgidx = 0;
    for (i=0; i < old_nr; i++)	{
        if (biosmap[i].size != 0) {
            change_point[chgidx]->addr = biosmap[i].addr;
            change_point[chgidx++]->pbios = &biosmap[i];
            change_point[chgidx]->addr = biosmap[i].addr + biosmap[i].size;
            change_point[chgidx++]->pbios = &biosmap[i];
        }
    }
    chg_nr = chgidx;    	/* true number of change-points */

    /* sort change-point list by memory addresses (low -> high) */
    still_changing = true;
    while (still_changing)	{
        still_changing = false;
        for (i=1; i < chg_nr; i++)  {
            /* if <current_addr> > <last_addr>, swap */
            /* or, if current=<start_addr> & last=<end_addr>, swap */
            if ((change_point[i]->addr < change_point[i-1]->addr) ||
                ((change_point[i]->addr == change_point[i-1]->addr) &&
                 (change_point[i]->addr == change_point[i]->pbios->addr) &&
                 (change_point[i-1]->addr != change_point[i-1]->pbios->addr))
                )
            {
                change_tmp = change_point[i];
                change_point[i] = change_point[i-1];
                change_point[i-1] = change_tmp;
                still_changing = true;
            }
        }
    }

    /* create a new bios memory map, removing overlaps */
    overlap_entries=0;	 /* number of entries in the overlap table */
    new_bios_entry=0;	 /* index for creating new bios map entries */
    last_type = 0;		 /* start with undefined memory type */
    last_addr = 0;		 /* start with 0 as last starting address */
    /* loop through change-points, determining affect on the new bios map */
    for (chgidx=0; chgidx < chg_nr; chgidx++)
    {
        /* keep track of all overlapping bios entries */
        if (change_point[chgidx]->addr == change_point[chgidx]->pbios->addr)
        {
            /* add map entry to overlap list (> 1 entry implies an overlap) */
            overlap_list[overlap_entries++]=change_point[chgidx]->pbios;
        }
        else
        {
            /* remove entry from list (order independent, so swap with last) */
            for (i=0; i<overlap_entries; i++)
            {
                if (overlap_list[i] == change_point[chgidx]->pbios)
                    overlap_list[i] = overlap_list[overlap_entries-1];
            }
            overlap_entries--;
        }
        /* if there are overlapping entries, decide which "type" to use */
        /* (larger value takes precedence -- 1=usable, 2,3,4,4+=unusable) */
        current_type = 0;
        for (i=0; i<overlap_entries; i++)
            if (overlap_list[i]->type > current_type)
                current_type = overlap_list[i]->type;
        /* continue building up new bios map based on this information */
        if (current_type != last_type)	{
            if (last_type != 0)	 {
                new_bios[new_bios_entry].size =
                    change_point[chgidx]->addr - last_addr;
				/* move forward only if the new size was non-zero */
                if (new_bios[new_bios_entry].size != 0)
                    if (++new_bios_entry >= ARRAY_SIZE(new_bios))
                        break; 	/* no more space left for new bios entries */
            }
            if (current_type != 0)	{
                new_bios[new_bios_entry].addr = change_point[chgidx]->addr;
                new_bios[new_bios_entry].type = current_type;
                last_addr=change_point[chgidx]->addr;
            }
            last_type = current_type;
        }
    }
    new_nr = new_bios_entry;   /* retain count for new bios entries */

    /* copy new bios mapping into original location */
    memcpy(biosmap, new_bios, new_nr*sizeof(struct e820entry));
    *pnr_map = new_nr;

    return 0;
}

/*
 * Copy the BIOS e820 map into a safe place.
 *
 * Sanity-check it while we're at it..
 *
 * If we're lucky and live on a modern system, the setup code
 * will have given us a memory map that we can use to properly
 * set up memory.  If we aren't, we'll fake a memory map.
 *
 * We check to see that the memory map contains at least 2 elements
 * before we'll use it, because the detection code in setup.S may
 * not be perfect and most every PC known to man has two memory
 * regions: one from 0 to 640k, and one from 1mb up.  (The IBM
 * thinkpad 560x, for example, does not cooperate with the memory
 * detection code.)
 */
static int __init copy_e820_map(struct e820entry * biosmap, unsigned int nr_map)
{
    /* Only one memory region? Ignore it */
    if (nr_map < 2)
        return -1;

    do {
        unsigned long long start = biosmap->addr;
        unsigned long long size = biosmap->size;
        unsigned long long end = start + size;
        unsigned long type = biosmap->type;

        /* Overflow in 64 bits? Ignore the memory map. */
        if (start > end)
            return -1;

        /*
         * Some BIOSes claim RAM in the 640k - 1M region.
         * Not right. Fix it up, but only when running on bare metal.
         */
        if (!cpu_has_hypervisor && type == E820_RAM) {
            if (start < 0x100000ULL && end > 0xA0000ULL) {
                if (start < 0xA0000ULL)
                    add_memory_region(start, 0xA0000ULL-start, type);
                if (end <= 0x100000ULL)
                    continue;
                start = 0x100000ULL;
                size = end - start;
            }
        }
        add_memory_region(start, size, type);
    } while (biosmap++,--nr_map);
    return 0;
}


/*
 * Find the highest page frame number we have available
 */
static unsigned long __init find_max_pfn(void)
{
    unsigned int i;
    unsigned long max_pfn = 0;

    for (i = 0; i < e820.nr_map; i++) {
        unsigned long start, end;
        /* RAM? */
        if (e820.map[i].type != E820_RAM)
            continue;
        start = PFN_UP(e820.map[i].addr);
        end = PFN_DOWN(e820.map[i].addr + e820.map[i].size);
        if (start >= end)
            continue;
        if (end > max_pfn)
            max_pfn = end;
    }

    return max_pfn;
}

static void __init clip_to_limit(uint64_t limit, const char *warnmsg)
{
    unsigned int i;
    char _warnmsg[160];
    uint64_t old_limit = 0;

    for ( ; ; )
    {
        /* Find a RAM region needing clipping. */
        for ( i = 0; i < e820.nr_map; i++ )
            if ( (e820.map[i].type == E820_RAM) &&
                 ((e820.map[i].addr + e820.map[i].size) > limit) )
                break;

        /* If none found, we are done. */
        if ( i == e820.nr_map )
            break;        

        old_limit = max_t(
            uint64_t, old_limit, e820.map[i].addr + e820.map[i].size);

        /* We try to convert clipped RAM areas to E820_UNUSABLE. */
        if ( e820_change_range_type(&e820, max(e820.map[i].addr, limit),
                                    e820.map[i].addr + e820.map[i].size,
                                    E820_RAM, E820_UNUSABLE) )
            continue;

        /*
         * If the type change fails (e.g., not space in table) then we clip or 
         * delete the region as appropriate.
         */
        if ( e820.map[i].addr < limit )
        {
            e820.map[i].size = limit - e820.map[i].addr;
        }
        else
        {
            memmove(&e820.map[i], &e820.map[i+1],
                    (e820.nr_map - i - 1) * sizeof(struct e820entry));
            e820.nr_map--;
        }
    }

    if ( old_limit )
    {
        if ( warnmsg )
        {
            snprintf(_warnmsg, sizeof(_warnmsg), warnmsg, (long)(limit>>30));
            printk("WARNING: %s\n", _warnmsg);
        }
        printk("Truncating RAM from %lukB to %lukB\n",
               (unsigned long)(old_limit >> 10), (unsigned long)(limit >> 10));
    }
}

/* Conservative estimate of top-of-RAM by looking for MTRR WB regions. */
static uint64_t __init mtrr_top_of_ram(void)
{
    uint64_t mtrr_cap, mtrr_def, addr_mask, base, mask, top;
    unsigned int i;

    /* By default we check only Intel systems. */
    if ( e820_mtrr_clip == -1 )
        e820_mtrr_clip = boot_cpu_data.x86_vendor == X86_VENDOR_INTEL;

    if ( !e820_mtrr_clip )
        return 0;

    if ( e820_verbose )
        printk("Checking MTRR ranges...\n");

    /* Does the CPU support architectural MTRRs? */
    if ( !cpu_has_mtrr )
         return 0;

    /* paddr_bits must have been set at this point */
    ASSERT(paddr_bits);
    addr_mask = ((1ULL << paddr_bits) - 1) & PAGE_MASK;

    rdmsrl(MSR_MTRRcap, mtrr_cap);
    rdmsrl(MSR_MTRRdefType, mtrr_def);

    if ( e820_verbose )
        printk(" MTRR cap: %"PRIx64" type: %"PRIx64"\n", mtrr_cap, mtrr_def);

    /* MTRRs enabled, and default memory type is not writeback? */
    if ( !test_bit(11, &mtrr_def) || ((uint8_t)mtrr_def == X86_MT_WB) )
        return 0;

    /*
     * Find end of highest WB-type range. This is a conservative estimate
     * of the highest WB address since overlapping UC/WT ranges dominate.
     */
    top = 0;
    for ( i = 0; i < (uint8_t)mtrr_cap; i++ )
    {
        rdmsrl(MSR_IA32_MTRR_PHYSBASE(i), base);
        rdmsrl(MSR_IA32_MTRR_PHYSMASK(i), mask);

        if ( e820_verbose )
            printk(" MTRR[%d]: base %"PRIx64" mask %"PRIx64"\n",
                   i, base, mask);

        if ( !test_bit(11, &mask) || ((uint8_t)base != X86_MT_WB) )
            continue;
        base &= addr_mask;
        mask &= addr_mask;
        top = max_t(uint64_t, top, ((base | ~mask) & addr_mask) + PAGE_SIZE);
    }

    return top;
}

static void __init reserve_dmi_region(void)
{
    for ( ; ; )
    {
        paddr_t base;
        u32 len;
        const char *what = dmi_get_table(&base, &len);

        if ( !what )
            break;
        if ( ((base + len) > base) &&
             reserve_e820_ram(&e820, base, base + len) )
            printk("WARNING: %s table located in E820 RAM %"PRIpaddr"-%"PRIpaddr". Fixed.\n",
                   what, base, base + len);
    }
}

static void __init machine_specific_memory_setup(struct e820map *raw)
{
    unsigned long mpt_limit, ro_mpt_limit;
    uint64_t top_of_ram, size;
    unsigned int i;

    sanitize_e820_map(raw->map, &raw->nr_map);
    copy_e820_map(raw->map, raw->nr_map);

    if ( opt_mem )
        clip_to_limit(opt_mem, NULL);

    if ( opt_availmem )
    {
        for ( i = size = 0; (i < e820.nr_map) && (size <= opt_availmem); i++ )
            if ( e820.map[i].type == E820_RAM )
                size += e820.map[i].size;
        if ( size > opt_availmem )
            clip_to_limit(
                e820.map[i-1].addr + e820.map[i-1].size - (size-opt_availmem),
                NULL);
    }

    mpt_limit = ((RDWR_MPT_VIRT_END - RDWR_MPT_VIRT_START)
                 / sizeof(unsigned long)) << PAGE_SHIFT;
    ro_mpt_limit = ((RO_MPT_VIRT_END - RO_MPT_VIRT_START)
                    / sizeof(unsigned long)) << PAGE_SHIFT;
    if ( mpt_limit > ro_mpt_limit )
        mpt_limit = ro_mpt_limit;
    clip_to_limit(mpt_limit,
                  "Only the first %lu GB of the physical "
                  "memory map can be accessed by Xen.");

    reserve_dmi_region();

    top_of_ram = mtrr_top_of_ram();
    if ( top_of_ram )
        clip_to_limit(top_of_ram, "MTRRs do not cover all of memory.");
}

/* This function relies on the global e820->map[] being sorted. */
int __init e820_add_range(uint64_t s, uint64_t e, uint32_t type)
{
    unsigned int i;
    struct e820entry *ei = e820.map;

    for ( i = 0; i < e820.nr_map; ++i )
    {
        uint64_t rs = ei[i].addr;
        uint64_t re = rs + ei[i].size;

        if ( rs == e && ei[i].type == type )
        {
            ei[i].addr = s;
            return 1;
        }

        if ( re == s && ei[i].type == type &&
             (i + 1 == e820.nr_map || ei[i + 1].addr >= e) )
        {
            ei[i].size += e - s;
            return 1;
        }

        if ( rs >= e )
            break;

        if ( re > s )
            return 0;
    }

    if ( e820.nr_map >= ARRAY_SIZE(e820.map) )
    {
        printk(XENLOG_WARNING "E820: overflow while adding region"
               " %"PRIx64"-%"PRIx64"\n", s, e);
        return 0;
    }

    memmove(ei + i + 1, ei + i,
            (e820.nr_map - i) * sizeof(*e820.map));

    e820.nr_map++;
    ei[i].addr = s;
    ei[i].size = e - s;
    ei[i].type = type;

    return 1;
}

int __init e820_change_range_type(
    struct e820map *map, uint64_t s, uint64_t e,
    uint32_t orig_type, uint32_t new_type)
{
    uint64_t rs = 0, re = 0;
    unsigned int i;

    for ( i = 0; i < map->nr_map; i++ )
    {
        /* Have we found the e820 region that includes the specified range? */
        rs = map->map[i].addr;
        re = rs + map->map[i].size;
        if ( (s >= rs) && (e <= re) )
            break;
    }

    if ( (i == map->nr_map) || (map->map[i].type != orig_type) )
        return 0;

    if ( (s == rs) && (e == re) )
    {
        map->map[i].type = new_type;
    }
    else if ( (s == rs) || (e == re) )
    {
        if ( (map->nr_map + 1) > ARRAY_SIZE(map->map) )
            goto overflow;

        memmove(&map->map[i+1], &map->map[i],
                (map->nr_map-i) * sizeof(map->map[0]));
        map->nr_map++;

        if ( s == rs )
        {
            map->map[i].size = e - s;
            map->map[i].type = new_type;
            map->map[i+1].addr = e;
            map->map[i+1].size = re - e;
        }
        else
        {
            map->map[i].size = s - rs;
            map->map[i+1].addr = s;
            map->map[i+1].size = e - s;
            map->map[i+1].type = new_type;
        }
    }
    else
    {
        if ( (map->nr_map + 2) > ARRAY_SIZE(map->map) )
            goto overflow;

        memmove(&map->map[i+2], &map->map[i],
                (map->nr_map-i) * sizeof(map->map[0]));
        map->nr_map += 2;

        map->map[i].size = s - rs;
        map->map[i+1].addr = s;
        map->map[i+1].size = e - s;
        map->map[i+1].type = new_type;
        map->map[i+2].addr = e;
        map->map[i+2].size = re - e;
    }

    /* Finally, look for any opportunities to merge adjacent e820 entries. */
    for ( i = 0; i < (map->nr_map - 1); i++ )
    {
        if ( (map->map[i].type != map->map[i+1].type) ||
             ((map->map[i].addr + map->map[i].size) != map->map[i+1].addr) )
            continue;
        map->map[i].size += map->map[i+1].size;
        memmove(&map->map[i+1], &map->map[i+2],
                (map->nr_map-i-2) * sizeof(map->map[0]));
        map->nr_map--;
        i--;
    }

    return 1;

 overflow:
    printk("Overflow in e820 while reserving region %"PRIx64"-%"PRIx64"\n",
           s, e);
    return 0;
}

/* Set E820_RAM area (@s,@e) as RESERVED in specified e820 map. */
int __init reserve_e820_ram(struct e820map *map, uint64_t s, uint64_t e)
{
    return e820_change_range_type(map, s, e, E820_RAM, E820_RESERVED);
}

unsigned long __init init_e820(const char *str, struct e820map *raw)
{
    if ( e820_verbose )
    {
        printk("Initial %s RAM map:\n", str);
        print_e820_memory_map(raw->map, raw->nr_map);
    }

    machine_specific_memory_setup(raw);

    if ( cpu_has_hypervisor )
        hypervisor_e820_fixup();

    printk("%s RAM map:\n", str);
    print_e820_memory_map(e820.map, e820.nr_map);

    return find_max_pfn();
}
