/******************************************************************************
 * include/xen/grant_table.h
 *
 * Mechanism for granting foreign access to page frames, and receiving
 * page-ownership transfers.
 *
 * Copyright (c) 2004-2005 K A Fraser
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XEN_GRANT_TABLE_H__
#define __XEN_GRANT_TABLE_H__

#include <xen/mm-frame.h>
#include <xen/rwlock.h>
#include <public/grant_table.h>

#ifdef CONFIG_GRANT_TABLE
#include <asm/grant_table.h>
#endif

struct grant_table;

/* Seed a gnttab entry for Hyperlaunch/dom0less. */
void gnttab_seed_entry(const struct domain *d, unsigned int idx,
                       domid_t be_domid, uint32_t frame);

#ifdef CONFIG_GRANT_TABLE

extern unsigned int opt_gnttab_max_version;
extern unsigned int opt_max_grant_frames;

/* Create/destroy per-domain grant table context. */
int grant_table_init(struct domain *d, int max_grant_frames,
                     int max_maptrack_frames, unsigned int options);
void grant_table_destroy(
    struct domain *d);
void grant_table_init_vcpu(struct vcpu *v);

/*
 * Check if domain has active grants and log first 10 of them.
 */
void grant_table_warn_active_grants(struct domain *d);

/* Domain death release of granted mappings of other domains' memory. */
int gnttab_release_mappings(struct domain *d);

int mem_sharing_gref_to_gfn(struct grant_table *gt, grant_ref_t ref,
                            gfn_t *gfn, uint16_t *status);

int gnttab_map_frame(struct domain *d, unsigned long idx, gfn_t gfn,
                     mfn_t *mfn);

unsigned int gnttab_resource_max_frames(const struct domain *d, unsigned int id);

int gnttab_acquire_resource(
    struct domain *d, unsigned int id, unsigned int frame,
    unsigned int nr_frames, xen_pfn_t mfn_list[]);

#else

#define opt_gnttab_max_version 0
#define opt_max_grant_frames 0

static inline int grant_table_init(struct domain *d,
                                   int max_grant_frames,
                                   int max_maptrack_frames,
                                   unsigned int options)
{
    if ( options )
        return -EINVAL;

    return 0;
}

static inline void grant_table_destroy(struct domain *d) {}

static inline void grant_table_init_vcpu(struct vcpu *v) {}

static inline void grant_table_warn_active_grants(struct domain *d) {}

static inline int gnttab_release_mappings(struct domain *d) { return 0; }

static inline int mem_sharing_gref_to_gfn(struct grant_table *gt,
                                          grant_ref_t ref,
                                          gfn_t *gfn, uint16_t *status)
{
    return -EINVAL;
}

static inline int gnttab_map_frame(struct domain *d, unsigned long idx,
                                   gfn_t gfn, mfn_t *mfn)
{
    return -EINVAL;
}

static inline unsigned int gnttab_resource_max_frames(
    const struct domain *d, unsigned int id)
{
    return 0;
}

static inline int gnttab_acquire_resource(
    struct domain *d, unsigned int id, unsigned int frame,
    unsigned int nr_frames, xen_pfn_t mfn_list[])
{
    return -EINVAL;
}

#endif /* CONFIG_GRANT_TABLE */

#endif /* __XEN_GRANT_TABLE_H__ */
