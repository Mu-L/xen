/*
 *  powernow - AMD Architectural P-state Driver ($Revision: 1.4 $)
 *
 *  Copyright (C) 2008 Mark Langsdorf <mark.langsdorf@amd.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/cpumask.h>
#include <xen/xmalloc.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <acpi/acpi.h>
#include <acpi/cpufreq/cpufreq.h>

#define HW_PSTATE_MASK          0x00000007U
#define HW_PSTATE_VALID_MASK    0x80000000U
#define HW_PSTATE_MAX_MASK      0x000000f0U
#define HW_PSTATE_MAX_SHIFT     4
#define MSR_PSTATE_DEF_BASE     0xc0010064U /* base of Pstate MSRs */
#define MSR_PSTATE_STATUS       0xc0010063U /* Pstate Status MSR */
#define MSR_PSTATE_CTRL         0xc0010062U /* Pstate control MSR */
#define MSR_PSTATE_CUR_LIMIT    0xc0010061U /* pstate current limit MSR */
#define MSR_HWCR_CPBDIS_MASK    0x02000000ULL

#define ARCH_CPU_FLAG_RESUME	1

static void cf_check transition_pstate(void *pstate)
{
    wrmsrl(MSR_PSTATE_CTRL, *(unsigned int *)pstate);
}

#ifdef CONFIG_PM_OP
static void cf_check update_cpb(void *data)
{
    struct cpufreq_policy *policy = data;

    if (policy->turbo != CPUFREQ_TURBO_UNSUPPORTED) {
        uint64_t msr_content;
 
        rdmsrl(MSR_K8_HWCR, msr_content);

        if (policy->turbo == CPUFREQ_TURBO_ENABLED)
            msr_content &= ~MSR_HWCR_CPBDIS_MASK;
        else
            msr_content |= MSR_HWCR_CPBDIS_MASK; 

        wrmsrl(MSR_K8_HWCR, msr_content);
    }
}

static int cf_check powernow_cpufreq_update(
    unsigned int cpu, struct cpufreq_policy *policy)
{
    if ( !cpu_online(cpu) )
        return -EINVAL;

    on_selected_cpus(cpumask_of(cpu), update_cpb, policy, 1);

    return 0;
}
#endif /* CONFIG_PM_OP */

static int cf_check powernow_cpufreq_target(
    struct cpufreq_policy *policy,
    unsigned int target_freq, unsigned int relation)
{
    struct acpi_cpufreq_data *data = cpufreq_drv_data[policy->cpu];
    struct processor_performance *perf;
    unsigned int next_state; /* Index into freq_table */
    unsigned int next_perf_state; /* Index into perf table */
    int result;

    if (unlikely(data == NULL ||
        data->acpi_data == NULL || data->freq_table == NULL)) {
        return -ENODEV;
    }

    perf = data->acpi_data;
    result = cpufreq_frequency_table_target(policy,
                                            data->freq_table,
                                            target_freq,
                                            relation, &next_state);
    if (unlikely(result))
        return result;

    next_perf_state = data->freq_table[next_state].index;
    if (perf->state == next_perf_state) {
        if (unlikely(data->arch_cpu_flags & ARCH_CPU_FLAG_RESUME)) 
            data->arch_cpu_flags &= ~ARCH_CPU_FLAG_RESUME;
        else
            return 0;
    }

    if (policy->shared_type == CPUFREQ_SHARED_TYPE_HW &&
        likely(policy->cpu == smp_processor_id())) {
        transition_pstate(&next_perf_state);
        cpufreq_statistic_update(policy->cpu, perf->state, next_perf_state);
    } else {
        cpumask_t online_policy_cpus;
        unsigned int cpu;

        cpumask_and(&online_policy_cpus, policy->cpus, &cpu_online_map);

        if (policy->shared_type == CPUFREQ_SHARED_TYPE_ALL ||
            unlikely(policy->cpu != smp_processor_id()))
            on_selected_cpus(&online_policy_cpus, transition_pstate,
                             &next_perf_state, 1);
        else
            transition_pstate(&next_perf_state);

        for_each_cpu(cpu, &online_policy_cpus)
            cpufreq_statistic_update(cpu, perf->state, next_perf_state);
    }

    perf->state = next_perf_state;
    policy->cur = data->freq_table[next_state].frequency;

    return 0;
}

static void amd_fixup_frequency(struct xen_processor_px *px)
{
    u32 hi, lo, fid, did;
    int index = px->control & 0x00000007;
    const struct cpuinfo_x86 *c = &current_cpu_data;

    if ((c->x86 != 0x10 || c->x86_model >= 10) && c->x86 != 0x11)
        return;

    rdmsr(MSR_PSTATE_DEF_BASE + index, lo, hi);
    /*
     * MSR C001_0064+:
     * Bit 63: PstateEn. Read-write. If set, the P-state is valid.
     */
    if (!(hi & (1U << 31)))
        return;

    fid = lo & 0x3f;
    did = (lo >> 6) & 7;
    if (c->x86 == 0x10)
        px->core_frequency = (100 * (fid + 16)) >> did;
    else
        px->core_frequency = (100 * (fid + 8)) >> did;
}

struct amd_cpu_data {
    struct processor_performance *perf;
    u32 max_hw_pstate;
};

static void cf_check get_cpu_data(void *arg)
{
    struct amd_cpu_data *data = arg;
    struct processor_performance *perf = data->perf;
    uint64_t msr_content;
    unsigned int i;

    rdmsrl(MSR_PSTATE_CUR_LIMIT, msr_content);
    data->max_hw_pstate = (msr_content & HW_PSTATE_MAX_MASK) >>
                          HW_PSTATE_MAX_SHIFT;

    for (i = 0; i < perf->state_count && i <= data->max_hw_pstate; i++)
        amd_fixup_frequency(&perf->states[i]);
}

static int cf_check powernow_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct acpi_cpufreq_data *data;
    struct processor_performance *perf;

    if (!policy || !(data = cpufreq_drv_data[policy->cpu]) ||
        !processor_pminfo[policy->cpu])
        return -EINVAL;

    perf = &processor_pminfo[policy->cpu]->perf;

    cpufreq_verify_within_limits(policy, 0, 
        perf->states[perf->platform_limit].core_frequency * 1000);

    return cpufreq_frequency_table_verify(policy, data->freq_table);
}

static int cf_check powernow_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    unsigned int i;
    unsigned int valid_states = 0;
    unsigned int cpu = policy->cpu;
    struct acpi_cpufreq_data *data;
    unsigned int result = 0;
    struct processor_performance *perf;
    struct amd_cpu_data info;
    struct cpuinfo_x86 *c = &cpu_data[policy->cpu];

    data = xzalloc(struct acpi_cpufreq_data);
    if (!data)
        return -ENOMEM;

    cpufreq_drv_data[cpu] = data;

    data->acpi_data = &processor_pminfo[cpu]->perf;

    info.perf = perf = data->acpi_data;
    policy->shared_type = perf->shared_type;

    if (policy->shared_type == CPUFREQ_SHARED_TYPE_ALL ||
        policy->shared_type == CPUFREQ_SHARED_TYPE_ANY) {
        cpumask_set_cpu(cpu, policy->cpus);
        if (cpumask_weight(policy->cpus) != 1) {
            printk(XENLOG_WARNING "Unsupported sharing type %d (%u CPUs)\n",
                   policy->shared_type, cpumask_weight(policy->cpus));
            result = -ENODEV;
            goto err_unreg;
        }
    } else {
        cpumask_copy(policy->cpus, cpumask_of(cpu));
    }

    /* capability check */
    if (perf->state_count <= 1) {
        printk("No P-States\n");
        result = -ENODEV;
        goto err_unreg;
    }

    if (perf->control_register.space_id != perf->status_register.space_id) {
        result = -ENODEV;
        goto err_unreg;
    }

    data->freq_table = xmalloc_array(struct cpufreq_frequency_table, 
                                    (perf->state_count+1));
    if (!data->freq_table) {
        result = -ENOMEM;
        goto err_unreg;
    }

    /* detect transition latency */
    policy->cpuinfo.transition_latency = 0;
    for (i=0; i<perf->state_count; i++) {
        if ((perf->states[i].transition_latency * 1000) >
            policy->cpuinfo.transition_latency)
            policy->cpuinfo.transition_latency =
                perf->states[i].transition_latency * 1000;
    }

    policy->governor = cpufreq_opt_governor ? : CPUFREQ_DEFAULT_GOVERNOR;

    on_selected_cpus(cpumask_of(cpu), get_cpu_data, &info, 1);

    /* table init */
    for (i = 0; i < perf->state_count && i <= info.max_hw_pstate; i++) {
        if (i > 0 && perf->states[i].core_frequency >=
            data->freq_table[valid_states-1].frequency / 1000)
            continue;

        data->freq_table[valid_states].index = perf->states[i].control & HW_PSTATE_MASK;
        data->freq_table[valid_states].frequency =
            perf->states[i].core_frequency * 1000;
        valid_states++;
    }
    data->freq_table[valid_states].frequency = CPUFREQ_TABLE_END;
    perf->state = 0;

    result = cpufreq_frequency_table_cpuinfo(policy, data->freq_table);
    if (result)
        goto err_freqfree;

    if ( cpu_has(c, X86_FEATURE_CPB) )
        policy->turbo = CPUFREQ_TURBO_ENABLED;

    /*
     * the first call to ->target() should result in us actually
     * writing something to the appropriate registers.
     */
    data->arch_cpu_flags |= ARCH_CPU_FLAG_RESUME;

    policy->cur = data->freq_table[i].frequency;
    return result;

err_freqfree:
    xfree(data->freq_table);
err_unreg:
    xfree(data);
    cpufreq_drv_data[cpu] = NULL;

    return result;
}

static int cf_check powernow_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    struct acpi_cpufreq_data *data = cpufreq_drv_data[policy->cpu];

    if (data) {
        cpufreq_drv_data[policy->cpu] = NULL;
        xfree(data->freq_table);
        xfree(data);
    }

    return 0;
}

static const struct cpufreq_driver __initconst_cf_clobber
powernow_cpufreq_driver = {
    .name   = "powernow",
    .verify = powernow_cpufreq_verify,
    .target = powernow_cpufreq_target,
    .init   = powernow_cpufreq_cpu_init,
    .exit   = powernow_cpufreq_cpu_exit,
#ifdef CONFIG_PM_OP
    .update = powernow_cpufreq_update
#endif
};

unsigned int __init powernow_register_driver(void)
{
    if ( !cpu_has_hw_pstate )
        return -ENODEV;

    return cpufreq_register_driver(&powernow_cpufreq_driver);
}
