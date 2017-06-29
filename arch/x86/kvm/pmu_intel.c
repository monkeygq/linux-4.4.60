/*
 * KVM PMU support for Intel CPUs
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@redhat.com>
 *   Gleb Natapov <gleb@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/perf_event.h>
#include <asm/perf_event.h>
#include "x86.h"
#include "cpuid.h"
#include "lapic.h"
#include "pmu.h"

static struct kvm_event_hw_type_mapping intel_arch_events[] = {
	/* Index must match CPUID 0x0A.EBX bit vector */
	[0] = { 0x3c, 0x00, PERF_COUNT_HW_CPU_CYCLES },
	[1] = { 0xc0, 0x00, PERF_COUNT_HW_INSTRUCTIONS },
	[2] = { 0x3c, 0x01, PERF_COUNT_HW_BUS_CYCLES  },
	[3] = { 0x2e, 0x4f, PERF_COUNT_HW_CACHE_REFERENCES },
	[4] = { 0x2e, 0x41, PERF_COUNT_HW_CACHE_MISSES },
	[5] = { 0xc4, 0x00, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	[6] = { 0xc5, 0x00, PERF_COUNT_HW_BRANCH_MISSES },
	[7] = { 0x00, 0x30, PERF_COUNT_HW_REF_CPU_CYCLES },
};

/* mapping between fixed pmc index and intel_arch_events array */
static int fixed_pmc_events[] = {1, 0, 7};

static void reprogram_fixed_counters(struct kvm_pmu *pmu, u64 data)// 被set_msr函数调用 
{
	int i;

	for (i = 0; i < pmu->nr_arch_fixed_counters; i++) {
    /* data表示set_msr函数中的data参数 也就是要给IA32_FIEXD_CTR_CTRL MSR 赋的值
     * fixed_ctr_ctrl这个函数获取对应的fixed计数器对应的4位控制字段
     * data中0-4位 5-7位 8-11位 分别表示第1 2 3 个fixed计数器的控制字段
     */
		u8 new_ctrl = fixed_ctrl_field(data, i);
		u8 old_ctrl = fixed_ctrl_field(pmu->fixed_ctr_ctrl, i);
		struct kvm_pmc *pmc;

		pmc = get_fixed_pmc(pmu, MSR_CORE_PERF_FIXED_CTR0 + i);

		if (old_ctrl == new_ctrl)
			continue;

		reprogram_fixed_counter(pmc, new_ctrl, i);
	}

	pmu->fixed_ctr_ctrl = data;
  printk(KERN_NOTICE "I am reprogram_fixed_counters in pmu_intel.c\n");
}

/* function is called when global control register has been updated. */
static void global_ctrl_changed(struct kvm_pmu *pmu, u64 data)// 被set_msr函数调用
{
	int bit;
	u64 diff = pmu->global_ctrl ^ data;

	pmu->global_ctrl = data;

	for_each_set_bit(bit, (unsigned long *)&diff, X86_PMC_IDX_MAX)
		reprogram_counter(pmu, bit);
  printk(KERN_NOTICE "I am global_ctrl_changed in pmu_intel.c\n");
}

static unsigned intel_find_arch_event(struct kvm_pmu *pmu,
				      u8 event_select,
				      u8 unit_mask)
{// 根据event_select和unit_mask两个字段寻找intel_arch_events数组中对应的监控事件
	int i;

  printk(KERN_NOTICE "I am intel_find_arch_event in pmu_intel.c\n");
	for (i = 0; i < ARRAY_SIZE(intel_arch_events); i++)
		if (intel_arch_events[i].eventsel == event_select
		    && intel_arch_events[i].unit_mask == unit_mask
		    && (pmu->available_event_types & (1 << i)))
			break;

	if (i == ARRAY_SIZE(intel_arch_events))// 如果执行这句 证明没有找到对应的监控事件
		return PERF_COUNT_HW_MAX;// 返回常量 10

	return intel_arch_events[i].event_type;// 返回对应的监控事件的常量值
}

static unsigned intel_find_fixed_event(int idx)
{
  printk(KERN_NOTICE "I am intel_find_fixed_event in pmu_intel.c\n");
  // fixed_pmc_event = [1,0,7] 1,0,7 对应intel_arch_events的数组下标
  // idx >= 3 表明没找到
	if (idx >= ARRAY_SIZE(fixed_pmc_events))
		return PERF_COUNT_HW_MAX;

	return intel_arch_events[fixed_pmc_events[idx]].event_type;
}

/* check if a PMC is enabled by comparising it with globl_ctrl bits. */
static bool intel_pmc_is_enabled(struct kvm_pmc *pmc)// 根据pmu中的global_ctrl中对应控制pmc的某位的值来判断是否enabled
{
	struct kvm_pmu *pmu = pmc_to_pmu(pmc);

  printk(KERN_NOTICE "I am intel_pmc_is_enabled in pmu_intel.c\n");
  //根据init函数可知 pmc->idx恰好对应pmu->global_ctrl的控制位
  //test_bit检测global_ctrl的对应位是否为1 是返回1 不是返回0
	return test_bit(pmc->idx, (unsigned long *)&pmu->global_ctrl);
}

static struct kvm_pmc *intel_pmc_idx_to_pmc(struct kvm_pmu *pmu, int pmc_idx)
{
  printk(KERN_NOTICE "I am intel_pmc_idx_to_pmc in pmu_intel.c\n");
	if (pmc_idx < INTEL_PMC_IDX_FIXED)
		return get_gp_pmc(pmu, MSR_P6_EVNTSEL0 + pmc_idx,
				  MSR_P6_EVNTSEL0);
	else {
		u32 idx = pmc_idx - INTEL_PMC_IDX_FIXED;

		return get_fixed_pmc(pmu, idx + MSR_CORE_PERF_FIXED_CTR0);
	}
}

/* returns 0 if idx's corresponding MSR exists; otherwise returns 1. */
static int intel_is_valid_msr_idx(struct kvm_vcpu *vcpu, unsigned idx)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	bool fixed = idx & (1u << 30);

	idx &= ~(3u << 30);

  printk(KERN_NOTICE "I am intel_is_valid_msr_idx in pmu_intel.c\n");
	return (!fixed && idx >= pmu->nr_arch_gp_counters) ||
		(fixed && idx >= pmu->nr_arch_fixed_counters);
}

static struct kvm_pmc *intel_msr_idx_to_pmc(struct kvm_vcpu *vcpu,
					    unsigned idx)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	bool fixed = idx & (1u << 30);
	struct kvm_pmc *counters;

  printk(KERN_NOTICE "I am intel_msr_idx_to_pmc in pmu_intel.c\n");
	idx &= ~(3u << 30);
	if (!fixed && idx >= pmu->nr_arch_gp_counters)
		return NULL;
	if (fixed && idx >= pmu->nr_arch_fixed_counters)
		return NULL;
	counters = fixed ? pmu->fixed_counters : pmu->gp_counters;

	return &counters[idx];
}

static bool intel_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	int ret;

  printk(KERN_NOTICE "I am intel_is_valid_msr in pmu_intel.c\n");
	switch (msr) {
	case MSR_CORE_PERF_FIXED_CTR_CTRL:
	case MSR_CORE_PERF_GLOBAL_STATUS:
	case MSR_CORE_PERF_GLOBAL_CTRL:
	case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
		ret = pmu->version > 1;
		break;
	default:
		ret = get_gp_pmc(pmu, msr, MSR_IA32_PERFCTR0) ||
			get_gp_pmc(pmu, msr, MSR_P6_EVNTSEL0) ||
			get_fixed_pmc(pmu, msr);
		break;
	}

	return ret;
}

static int intel_pmu_get_msr(struct kvm_vcpu *vcpu, u32 msr, u64 *data)// 读取PMU相关的msr
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct kvm_pmc *pmc;

  printk(KERN_NOTICE "I am intel_pmu_get_msr in pmu_intel.c\n");
	switch (msr) {
	case MSR_CORE_PERF_FIXED_CTR_CTRL:// 这四种case的情况都在intel的用户手册上 常量的值就是msr所在的位置
		*data = pmu->fixed_ctr_ctrl;
		return 0;
	case MSR_CORE_PERF_GLOBAL_STATUS:
		*data = pmu->global_status;
		return 0;
	case MSR_CORE_PERF_GLOBAL_CTRL:
		*data = pmu->global_ctrl;
		return 0;
	case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
		*data = pmu->global_ovf_ctrl;
		return 0;
	default:
		if ((pmc = get_gp_pmc(pmu, msr, MSR_IA32_PERFCTR0)) ||
		    (pmc = get_fixed_pmc(pmu, msr))) {// 如果不是上面四种情况 就是读取gp计数器或者fixed计数器的值
			*data = pmc_read_counter(pmc);
			return 0;
		} else if ((pmc = get_gp_pmc(pmu, msr, MSR_P6_EVNTSEL0))) {// 如果也不是计数器 那么就只能是性能事件选择器了
			*data = pmc->eventsel;// PMU结构体中并没有包含性能事件选择器这个数组 而是在每个计数器中包含了性能事件选择器字段eventsel
			return 0;
		}
	}

	return 1;
}

static int intel_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct kvm_pmc *pmc;
	u32 msr = msr_info->index;
	u64 data = msr_info->data;

  printk(KERN_NOTICE "I am intel_pmu_set_msr in pmu_intel.c\n");
	switch (msr) {
	case MSR_CORE_PERF_FIXED_CTR_CTRL:
		if (pmu->fixed_ctr_ctrl == data)
			return 0;
		if (!(data & 0xfffffffffffff444ull)) {
			reprogram_fixed_counters(pmu, data);// 根据data的4位控制字段修改相应的pmc 没完全读懂
			return 0;
		}
		break;
	case MSR_CORE_PERF_GLOBAL_STATUS:
		if (msr_info->host_initiated) {
			pmu->global_status = data;
			return 0;
		}
		break; /* RO MSR */
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (pmu->global_ctrl == data)
			return 0;
		if (!(data & pmu->global_ctrl_mask)) {
			global_ctrl_changed(pmu, data);
			return 0;
		}
		break;
	case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
		if (!(data & (pmu->global_ctrl_mask & ~(3ull<<62)))) {
			if (!msr_info->host_initiated)
				pmu->global_status &= ~data;
			pmu->global_ovf_ctrl = data;
			return 0;
		}
		break;
	default:
		if ((pmc = get_gp_pmc(pmu, msr, MSR_IA32_PERFCTR0)) ||
		    (pmc = get_fixed_pmc(pmu, msr))) {
			if (!msr_info->host_initiated)
				data = (s64)(s32)data;
			pmc->counter += data - pmc_read_counter(pmc);
			return 0;
		} else if ((pmc = get_gp_pmc(pmu, msr, MSR_P6_EVNTSEL0))) {
			if (data == pmc->eventsel)
				return 0;
			if (!(data & pmu->reserved_bits)) {
				reprogram_gp_counter(pmc, data);
				return 0;
			}
		}
	}

	return 1;
}

static void intel_pmu_refresh(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	struct kvm_cpuid_entry2 *entry;
	union cpuid10_eax eax;
	union cpuid10_edx edx;

  printk(KERN_NOTICE "I am intel_pmu_refresh in pmu_intel.c\n");
	pmu->nr_arch_gp_counters = 0;
	pmu->nr_arch_fixed_counters = 0;
	pmu->counter_bitmask[KVM_PMC_GP] = 0;
	pmu->counter_bitmask[KVM_PMC_FIXED] = 0;
	pmu->version = 0;
	pmu->reserved_bits = 0xffffffff00200000ull;

	entry = kvm_find_cpuid_entry(vcpu, 0xa, 0);
	if (!entry)
		return;
	eax.full = entry->eax;
	edx.full = entry->edx;

  /* 下面是测试 : 
   * 由于最开始打印的时候发现只有refresh函数被打印多次 所以从这里看起 真的有收获
   * 把物理机上CPUID 0AH 得到的eax和 edx的值，赋值给vcpu的eax和edx, 
   * 相当于触发了vcpu的PMU的相关功能, 在执行perf命令的时候,打印的结果中发现perf用到了get_msr和set_msr函数,
   * 正确方法应该是在vcpu初始化的时候把CPUID 0AH 加入到 vcpu->arch.cpuid_entries这个数组中,
   * 这个数组的作用应该是模拟物理机cpu的CPUID指令的行为,
   * 继续看get_msr set_msr两个函数.
   */

  if(!eax.full)
    eax.full = 120588291;
  if(!edx.full)
    edx.full = 1539;
  printk(KERN_NOTICE "eax=%d\n", eax.full);
  printk(KERN_NOTICE "edx=%d\n", edx.full);
  printk(KERN_NOTICE "version_id=%d\n", eax.split.version_id);
  printk(KERN_NOTICE "num_counters=%d\n", eax.split.num_counters);
  printk(KERN_NOTICE "bit_width=%d\n", eax.split.bit_width);
  printk(KERN_NOTICE "mask_length=%d\n", eax.split.mask_length);
  printk(KERN_NOTICE "++++++++++++++++++++++++++++++++\n");

	pmu->version = eax.split.version_id;
	if (!pmu->version)
		return;

	pmu->nr_arch_gp_counters = min_t(int, eax.split.num_counters,
					INTEL_PMC_MAX_GENERIC);// gp_counters的数量
	pmu->counter_bitmask[KVM_PMC_GP] = ((u64)1 << eax.split.bit_width) - 1;// gp_counter的长度, #{bit_width}个1 通过&操作把计数器中超过长度的数截掉
	pmu->available_event_types = ~entry->ebx &
					((1ull << eax.split.mask_length) - 1);// 所支持的性能监控事件

	if (pmu->version == 1) {
		pmu->nr_arch_fixed_counters = 0;// version 1 没有fixed counters
	} else {
		pmu->nr_arch_fixed_counters =
			min_t(int, edx.split.num_counters_fixed,
				INTEL_PMC_MAX_FIXED);// fixed_counters的数量 #{bit_width}个1 通过&操作把计数器中超过长度的数截掉
		pmu->counter_bitmask[KVM_PMC_FIXED] =
			((u64)1 << edx.split.bit_width_fixed) - 1;// fixed_counter的长度, #{bit_width}个1
	}

	pmu->global_ctrl = ((1 << pmu->nr_arch_gp_counters) - 1) |
		(((1ull << pmu->nr_arch_fixed_counters) - 1) << INTEL_PMC_IDX_FIXED);
	pmu->global_ctrl_mask = ~pmu->global_ctrl;

	entry = kvm_find_cpuid_entry(vcpu, 7, 0);
	if (entry &&
	    (boot_cpu_has(X86_FEATURE_HLE) || boot_cpu_has(X86_FEATURE_RTM)) &&
	    (entry->ebx & (X86_FEATURE_HLE|X86_FEATURE_RTM)))
		pmu->reserved_bits ^= HSW_IN_TX|HSW_IN_TX_CHECKPOINTED;
}

static void intel_pmu_init(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);

  printk(KERN_NOTICE "I am intel_pmu_init in pmu_intel.c\n");
	for (i = 0; i < INTEL_PMC_MAX_GENERIC; i++) {
		pmu->gp_counters[i].type = KVM_PMC_GP;
		pmu->gp_counters[i].vcpu = vcpu;
		pmu->gp_counters[i].idx = i;
	}

	for (i = 0; i < INTEL_PMC_MAX_FIXED; i++) {
		pmu->fixed_counters[i].type = KVM_PMC_FIXED;
		pmu->fixed_counters[i].vcpu = vcpu;
		pmu->fixed_counters[i].idx = i + INTEL_PMC_IDX_FIXED;
	}
}

static void intel_pmu_reset(struct kvm_vcpu *vcpu)// 归零
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	int i;

  printk(KERN_NOTICE "I am intel_pmu_reset in pmu_intel.c\n");
	for (i = 0; i < INTEL_PMC_MAX_GENERIC; i++) {
		struct kvm_pmc *pmc = &pmu->gp_counters[i];

		pmc_stop_counter(pmc);
		pmc->counter = pmc->eventsel = 0;
	}

	for (i = 0; i < INTEL_PMC_MAX_FIXED; i++)
		pmc_stop_counter(&pmu->fixed_counters[i]);

	pmu->fixed_ctr_ctrl = pmu->global_ctrl = pmu->global_status =
		pmu->global_ovf_ctrl = 0;
}

struct kvm_pmu_ops intel_pmu_ops = {
	.find_arch_event = intel_find_arch_event,
	.find_fixed_event = intel_find_fixed_event,
	.pmc_is_enabled = intel_pmc_is_enabled,
	.pmc_idx_to_pmc = intel_pmc_idx_to_pmc,
	.msr_idx_to_pmc = intel_msr_idx_to_pmc,
	.is_valid_msr_idx = intel_is_valid_msr_idx,
	.is_valid_msr = intel_is_valid_msr,
	.get_msr = intel_pmu_get_msr,
	.set_msr = intel_pmu_set_msr,
	.refresh = intel_pmu_refresh,
	.init = intel_pmu_init,
	.reset = intel_pmu_reset,
};
