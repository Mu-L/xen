#include <xen/bitmap.h>
#include <xen/sections.h>
#include <xen/init.h>
#include <xen/mm.h>
#include <xen/pfn.h>
#include <xen/spinlock.h>
#include <xen/types.h>
#include <xen/vmap.h>
#include <xen/xvmalloc.h>
#include <asm/page.h>

static DEFINE_SPINLOCK(vm_lock);
static void *__read_mostly vm_base[VMAP_REGION_NR];
#define vm_bitmap(x) ((unsigned long *)vm_base[x])
/* highest allocated bit in the bitmap */
static unsigned int __read_mostly vm_top[VMAP_REGION_NR];
/* total number of bits in the bitmap */
static unsigned int __read_mostly vm_end[VMAP_REGION_NR];
/* lowest known clear bit in the bitmap */
static unsigned int vm_low[VMAP_REGION_NR];

void __init vm_init_type(enum vmap_region type, void *start, void *end)
{
    unsigned int i, nr;
    unsigned long va;

    ASSERT(!vm_base[type]);

    vm_base[type] = start;
    vm_end[type] = PFN_DOWN(end - start);
    vm_low[type]= PFN_UP((vm_end[type] + 7) / 8);
    nr = PFN_UP((vm_low[type] + 7) / 8);
    vm_top[type] = nr * PAGE_SIZE * 8;

    for ( i = 0, va = (unsigned long)vm_bitmap(type); i < nr; ++i, va += PAGE_SIZE )
    {
        mfn_t mfn;
        int rc;

        if ( system_state == SYS_STATE_early_boot )
            mfn = alloc_boot_pages(1, 1);
        else
        {
            struct page_info *pg = alloc_domheap_page(NULL, 0);

            BUG_ON(!pg);
            mfn = page_to_mfn(pg);
        }
        rc = map_pages_to_xen(va, mfn, 1, PAGE_HYPERVISOR);
        BUG_ON(rc);

        clear_page((void *)va);
    }
    bitmap_fill(vm_bitmap(type), vm_low[type]);

    /* Populate page tables for the bitmap if necessary. */
    populate_pt_range(va, vm_low[type] - nr);
}

static void *vm_alloc(unsigned int nr, unsigned int align,
                      enum vmap_region t)
{
    unsigned int start, bit;

    if ( !align )
        align = 1;
    else if ( align & (align - 1) )
        align = ISOLATE_LSB(align);

    ASSERT((t >= VMAP_DEFAULT) && (t < VMAP_REGION_NR));
    if ( !vm_base[t] )
        return NULL;

    spin_lock(&vm_lock);
    for ( ; ; )
    {
        mfn_t mfn;

        ASSERT(vm_low[t] == vm_top[t] || !test_bit(vm_low[t], vm_bitmap(t)));
        for ( start = vm_low[t]; start < vm_top[t]; )
        {
            bit = find_next_bit(vm_bitmap(t), vm_top[t], start + 1);
            if ( bit > vm_top[t] )
                bit = vm_top[t];
            /*
             * Note that this skips the first bit, making the
             * corresponding page a guard one.
             */
            start = (start + align) & ~(align - 1);
            if ( bit < vm_top[t] )
            {
                if ( start + nr < bit )
                    break;
                start = find_next_zero_bit(vm_bitmap(t), vm_top[t], bit + 1);
            }
            else
            {
                if ( start + nr <= bit )
                    break;
                start = bit;
            }
        }

        if ( start < vm_top[t] )
            break;

        spin_unlock(&vm_lock);

        if ( vm_top[t] >= vm_end[t] )
            return NULL;

        if ( system_state == SYS_STATE_early_boot )
            mfn = alloc_boot_pages(1, 1);
        else
        {
            struct page_info *pg = alloc_domheap_page(NULL, 0);

            if ( !pg )
                return NULL;
            mfn = page_to_mfn(pg);
        }

        spin_lock(&vm_lock);

        if ( start >= vm_top[t] )
        {
            unsigned long va = (unsigned long)vm_bitmap(t) + vm_top[t] / 8;

            if ( !map_pages_to_xen(va, mfn, 1, PAGE_HYPERVISOR) )
            {
                clear_page((void *)va);
                vm_top[t] += PAGE_SIZE * 8;
                if ( vm_top[t] > vm_end[t] )
                    vm_top[t] = vm_end[t];
                continue;
            }
        }

        if ( system_state == SYS_STATE_early_boot )
            init_boot_pages(mfn_to_maddr(mfn), mfn_to_maddr(mfn) + PAGE_SIZE);
        else
            free_domheap_page(mfn_to_page(mfn));

        if ( start >= vm_top[t] )
        {
            spin_unlock(&vm_lock);
            return NULL;
        }
    }

    for ( bit = start; bit < start + nr; ++bit )
        __set_bit(bit, vm_bitmap(t));
    if ( bit < vm_top[t] )
        ASSERT(!test_bit(bit, vm_bitmap(t)));
    else
        ASSERT(bit == vm_top[t]);
    if ( start <= vm_low[t] + 2 )
        vm_low[t] = bit;
    spin_unlock(&vm_lock);

    return vm_base[t] + start * PAGE_SIZE;
}

static unsigned int vm_index(const void *va, enum vmap_region type)
{
    unsigned long addr = (unsigned long)va & ~(PAGE_SIZE - 1);
    unsigned int idx;
    unsigned long start = (unsigned long)vm_base[type];

    if ( !start )
        return 0;

    if ( addr < start + (vm_end[type] / 8) ||
         addr >= start + vm_top[type] * PAGE_SIZE )
        return 0;

    idx = PFN_DOWN(va - vm_base[type]);
    return !test_bit(idx - 1, vm_bitmap(type)) &&
           test_bit(idx, vm_bitmap(type)) ? idx : 0;
}

static unsigned int vm_size(const void *va, enum vmap_region type)
{
    unsigned int start = vm_index(va, type), end;

    if ( !start )
        return 0;

    end = find_next_zero_bit(vm_bitmap(type), vm_top[type], start + 1);

    return min(end, vm_top[type]) - start;
}

static void vm_free(const void *va)
{
    enum vmap_region type = VMAP_DEFAULT;
    unsigned int bit = vm_index(va, type);

    if ( !bit )
    {
        type = VMAP_XEN;
        bit = vm_index(va, type);
    }

    if ( !bit )
    {
        WARN_ON(va != NULL);
        return;
    }

    spin_lock(&vm_lock);
    if ( bit < vm_low[type] )
    {
        vm_low[type] = bit - 1;
        while ( !test_bit(vm_low[type] - 1, vm_bitmap(type)) )
            --vm_low[type];
    }
    while ( __test_and_clear_bit(bit, vm_bitmap(type)) )
        if ( ++bit == vm_top[type] )
            break;
    spin_unlock(&vm_lock);
}

void *__vmap(const mfn_t *mfn, unsigned int granularity,
             unsigned int nr, unsigned int align, pte_attr_t flags,
             enum vmap_region type)
{
    void *va = vm_alloc(nr * granularity, align, type);
    unsigned long cur = (unsigned long)va;

    for ( ; va && nr--; ++mfn, cur += PAGE_SIZE * granularity )
    {
        if ( map_pages_to_xen(cur, *mfn, granularity, flags) )
        {
            vunmap(va);
            va = NULL;
        }
    }

    return va;
}

void *vmap(const mfn_t *mfn, unsigned int nr)
{
    return __vmap(mfn, 1, nr, 1, PAGE_HYPERVISOR, VMAP_DEFAULT);
}

void *vmap_contig(mfn_t mfn, unsigned int nr)
{
    return __vmap(&mfn, nr, 1, 1, PAGE_HYPERVISOR, VMAP_DEFAULT);
}

unsigned int vmap_size(const void *va)
{
    unsigned int pages = vm_size(va, VMAP_DEFAULT);

    if ( !pages )
        pages = vm_size(va, VMAP_XEN);

    return pages;
}

void vunmap(const void *va)
{
    unsigned long addr = (unsigned long)va;
    unsigned pages = vmap_size(va);

#ifndef _PAGE_NONE
    destroy_xen_mappings(addr, addr + PAGE_SIZE * pages);
#else /* Avoid tearing down intermediate page tables. */
    map_pages_to_xen(addr, INVALID_MFN, pages, _PAGE_NONE);
#endif
    vm_free(va);
}

static void *vmalloc_type(size_t size, enum vmap_region type)
{
    mfn_t *mfn;
    unsigned int i, pages = PFN_UP(size);
    struct page_info *pg;
    void *va;

    ASSERT(size);

    if ( PFN_DOWN(size) > pages )
        return NULL;

    mfn = xmalloc_array(mfn_t, pages);
    if ( mfn == NULL )
        return NULL;

    for ( i = 0; i < pages; i++ )
    {
        pg = alloc_domheap_page(NULL, 0);
        if ( pg == NULL )
            goto error;
        mfn[i] = page_to_mfn(pg);
    }

    va = __vmap(mfn, 1, pages, 1, PAGE_HYPERVISOR, type);
    if ( va == NULL )
        goto error;

    xfree(mfn);
    return va;

 error:
    while ( i-- )
        free_domheap_page(mfn_to_page(mfn[i]));
    xfree(mfn);
    return NULL;
}

void *vmalloc(size_t size)
{
    return vmalloc_type(size, VMAP_DEFAULT);
}

void *vmalloc_xen(size_t size)
{
    return vmalloc_type(size, VMAP_XEN);
}

void *vzalloc(size_t size)
{
    void *p = vmalloc_type(size, VMAP_DEFAULT);
    int i;

    if ( p == NULL )
        return NULL;

    for ( i = 0; i < size; i += PAGE_SIZE )
        clear_page(p + i);

    return p;
}

static void _vfree(const void *va, unsigned int pages)
{
    unsigned int i;
    struct page_info *pg;
    PAGE_LIST_HEAD(pg_list);

    ASSERT(pages);

    for ( i = 0; i < pages; i++ )
    {
        pg = vmap_to_page(va + i * PAGE_SIZE);
        ASSERT(pg);
        page_list_add(pg, &pg_list);
    }
    vunmap(va);

    while ( (pg = page_list_remove_head(&pg_list)) != NULL )
        free_domheap_page(pg);
}

void vfree(void *va)
{
    if ( !va )
        return;

    _vfree(va, vmap_size(va));
}

void xvfree(void *va)
{
    unsigned int pages = vm_size(va, VMAP_DEFAULT);

    if ( pages )
        _vfree(va, pages);
    else
        xfree(va);
}

void *_xvmalloc(size_t size, unsigned int align)
{
    ASSERT(align <= PAGE_SIZE);
    return size <= PAGE_SIZE ? _xmalloc(size, align) : vmalloc(size);
}

void *_xvzalloc(size_t size, unsigned int align)
{
    ASSERT(align <= PAGE_SIZE);
    return size <= PAGE_SIZE ? _xzalloc(size, align) : vzalloc(size);
}

void *_xvrealloc(void *va, size_t size, unsigned int align)
{
    size_t pages = vm_size(va, VMAP_DEFAULT);
    void *ptr;

    ASSERT(align <= PAGE_SIZE);

    if ( !pages )
    {
        if ( size <= PAGE_SIZE )
            return _xrealloc(va, size, align);

        ptr = vmalloc(size);
        if ( ptr && va && va != ZERO_BLOCK_PTR )
        {
            /*
             * xmalloc-based allocations up to PAGE_SIZE don't cross page
             * boundaries. Therefore, without needing to know the exact
             * prior allocation size, simply copy the entire tail of the
             * page containing the earlier allocation.
             */
            memcpy(ptr, va, PAGE_SIZE - PAGE_OFFSET(va));
            xfree(va);
        }
    }
    else if ( pages == PFN_UP(size) )
        ptr = va;
    else
    {
        ptr = _xvmalloc(size, align);
        if ( ptr )
        {
            memcpy(ptr, va, min(size, pages << PAGE_SHIFT));
            vfree(va);
        }
        else if ( pages > PFN_UP(size) )
            ptr = va;
    }

    return ptr;
}
