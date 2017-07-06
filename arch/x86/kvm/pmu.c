/*
 * Kernel-based Virtual Machine -- Performance Monitoring Unit support
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Authors:
 *   Avi Kivity   <avi@redhat.com>
 *   Gleb Natapov <gleb@redhat.com>
 *   Wei Huang    <wei@redhat.com>
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
#include "linux/module.h"
#include "linux/init.h"

/* NOTE:
 * - Each perf counter is defined as "struct kvm_pmc";
 * - There are two types of perf counters: general purpose (gp) and fixed.
 *   gp counters are stored in gp_counters[] and fixed counters are stored
 *   in fixed_counters[] respectively. Both of them are part of "struct
 *   kvm_pmu";
 * - pmu.c understands the difference between gp counters and fixed counters.
 *   However AMD doesn't support fixed-counters;
 * - There are three types of index to access perf counters (PMC):
 *     1. MSR (named msr): For example Intel has MSR_IA32_PERFCTRn and AMD
 *        has MSR_K7_PERFCTRn.
 *     2. MSR Index (named idx): This normally is used by RDPMC instruction.
 *        For instance AMD RDPMC instruction uses 0000_0003h in ECX to access
 *        C001_0007h (MSR_K7_PERCTR3). Intel has a similar mechanism, except
 *        that it also supports fixed counters. idx can be used to as index to
 *        gp and fixed counters.
 *     3. Global PMC Index (named pmc): pmc is an index specific to PMU
 *        code. Each pmc, stored in kvm_pmc.idx field, is unique across
 *        all perf counters (both gp and fixed). The mapping relationship
 *        between pmc and perf counters is as the following:
 *        * Intel: [0 .. INTEL_PMC_MAX_GENERIC-1] <=> gp counters
 *                 [INTEL_PMC_IDX_FIXED .. INTEL_PMC_IDX_FIXED + 2] <=> fixed
 *        * AMD:   [0 .. AMD64_NUM_COUNTERS-1] <=> gp counters
 */

static void kvm_pmi_trigger_fn(struct irq_work *irq_work)
{
	struct kvm_pmu *pmu = container_of(irq_work, struct kvm_pmu, irq_work);
	struct kvm_vcpu *vcpu = pmu_to_vcpu(pmu);

  printk(KERN_ALERT "without perf, can I be printed?");
	kvm_pmu_deliver_pmi(vcpu);
}

static void kvm_perf_overflow(struct perf_event *perf_event,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	struct kvm_pmc *pmc = perf_event->overflow_handler_context;
	struct kvm_pmu *pmu = pmc_to_pmu(pmc);

	if (!test_and_set_bit(pmc->idx,
			      (unsigned long *)&pmu->reprogram_pmi)) {
		__set_bit(pmc->idx, (unsigned long *)&pmu->global_status);
		kvm_make_request(KVM_REQ_PMU, pmc->vcpu);//
	}
}

static void kvm_perf_overflow_intr(struct perf_event *perf_event,
				   struct perf_sample_data *data,
				   struct pt_regs *regs)
{
	struct kvm_pmc *pmc = perf_event->overflow_handler_context;
	struct kvm_pmu *pmu = pmc_to_pmu(pmc);

	if (!test_and_set_bit(pmc->idx,
			      (unsigned long *)&pmu->reprogram_pmi)) {
		__set_bit(pmc->idx, (unsigned long *)&pmu->global_status);
		kvm_make_request(KVM_REQ_PMU, pmc->vcpu);//

		/*
		 * Inject PMI. If vcpu was in a guest mode during NMI PMI
		 * can be ejected on a guest mode re-entry. Otherwise we can't
		 * be sure that vcpu wasn't executing hlt instruction at the
		 * time of vmexit and is not going to re-enter guest mode until
		 * woken up. So we should wake it, but this is impossible from
		 * NMI context. Do it from irq work instead.
		 */
		if (!kvm_is_in_guest())
			irq_work_queue(&pmc_to_pmu(pmc)->irq_work);
		else
			kvm_make_request(KVM_REQ_PMI, pmc->vcpu);
	}
}

static void pmc_reprogram_counter(struct kvm_pmc *pmc, u32 type,
				  unsigned config, bool exclude_user,
				  bool exclude_kernel, bool intr,
				  bool in_tx, bool in_tx_cp)
  /*
   * reprogram pmc中的一些控制字段 没有很仔细看
   */
{
	struct perf_event *event;
	struct perf_event_attr attr = {
		.type = type,
		.size = sizeof(attr),
		.pinned = true,
		.exclude_idle = true,
		.exclude_host = 1,
		.exclude_user = exclude_user,
		.exclude_kernel = exclude_kernel,
		.config = config,
	};

	if (in_tx)
		attr.config |= HSW_IN_TX;
	if (in_tx_cp)
		attr.config |= HSW_IN_TX_CHECKPOINTED;

	attr.sample_period = (-pmc->counter) & pmc_bitmask(pmc);

	event = perf_event_create_kernel_counter(&attr, -1, current,
						 intr ? kvm_perf_overflow_intr :
						 kvm_perf_overflow, pmc);
	if (IS_ERR(event)) {
		printk_once("kvm_pmu: event creation failed %ld\n",
			    PTR_ERR(event));
		return;
	}

	pmc->perf_event = event;
	clear_bit(pmc->idx, (unsigned long*)&pmc_to_pmu(pmc)->reprogram_pmi);
}

void reprogram_gp_counter(struct kvm_pmc *pmc, u64 eventsel)// 被set_msr调用
{
	unsigned config, type = PERF_TYPE_RAW;// type = 4
	u8 event_select, unit_mask;

	if (eventsel & ARCH_PERFMON_EVENTSEL_PIN_CONTROL)// 常量是 1ULL << 19 代表事件选择器的PC(pin control)字段
		printk_once("kvm pmu: pin control bit is ignored\n");

	pmc->eventsel = eventsel;

	pmc_stop_counter(pmc);

	if (!(eventsel & ARCH_PERFMON_EVENTSEL_ENABLE) || !pmc_is_enabled(pmc))
		return;// 如果事件选择器的EN字段为0 或者 pmc不可用 那么就返回

	event_select = eventsel & ARCH_PERFMON_EVENTSEL_EVENT;// 得到事件选择器的event_select字段
	unit_mask = (eventsel & ARCH_PERFMON_EVENTSEL_UMASK) >> 8;// 得到事件选择器的unit_mask字段

	if (!(eventsel & (ARCH_PERFMON_EVENTSEL_EDGE |
			  ARCH_PERFMON_EVENTSEL_INV |
			  ARCH_PERFMON_EVENTSEL_CMASK |
			  HSW_IN_TX |
			  HSW_IN_TX_CHECKPOINTED))) {// eventsel中这些字段的值都为0 这个if中的代码才会执行
		config = kvm_x86_ops->pmu_ops->find_arch_event(pmc_to_pmu(pmc),
						      event_select,
						      unit_mask);// 调用pmu_intel.c中的intel_find_arch_event函数 返回intel_arch_events数组中的事件常量
		if (config != PERF_COUNT_HW_MAX)// 在intel_arch_events数组中找到了
			type = PERF_TYPE_HARDWARE;// type = 0 表示这个事件是 硬件事件
	}

	if (type == PERF_TYPE_RAW)// 由于type初始值为4 也就是说在上面的数组中没找到就执行if中的代码
		config = eventsel & X86_RAW_EVENT_MASK;

	pmc_reprogram_counter(pmc, type, config,
			      !(eventsel & ARCH_PERFMON_EVENTSEL_USR),
			      !(eventsel & ARCH_PERFMON_EVENTSEL_OS),
			      eventsel & ARCH_PERFMON_EVENTSEL_INT,
			      (eventsel & HSW_IN_TX),
			      (eventsel & HSW_IN_TX_CHECKPOINTED));
}
EXPORT_SYMBOL_GPL(reprogram_gp_counter);

void reprogram_fixed_counter(struct kvm_pmc *pmc, u8 ctrl, int idx)// 被pmu_intel.c中的reprogram_fixed_counter函数调用
{
	unsigned en_field = ctrl & 0x3;// 得到IA32_FIXED_CTR_CTRL MSR 中对应fixed计数器的控制字段EN
	bool pmi = ctrl & 0x8;// 得到IA32_FIXED_CTR_CTRL MSR 中对应fixed计数器的控制字段PMI

	pmc_stop_counter(pmc);

	if (!en_field || !pmc_is_enabled(pmc))
		return;

	pmc_reprogram_counter(pmc, PERF_TYPE_HARDWARE,
			      kvm_x86_ops->pmu_ops->find_fixed_event(idx),
			      !(en_field & 0x2), /* exclude user */
			      !(en_field & 0x1), /* exclude kernel */
			      pmi, false, false);
}
EXPORT_SYMBOL_GPL(reprogram_fixed_counter);

void reprogram_counter(struct kvm_pmu *pmu, int pmc_idx)
  /*
   * 在global_ctrl变化的时候 每一个变化的位(对应一个pmc)都会执行一次该函数
   * 然后再调用相应的reprogram_gp_counter或者reprogram_fixed_counter
   */
{
	struct kvm_pmc *pmc = kvm_x86_ops->pmu_ops->pmc_idx_to_pmc(pmu, pmc_idx);

	if (!pmc)
		return;

	if (pmc_is_gp(pmc))
		reprogram_gp_counter(pmc, pmc->eventsel);
	else {
		int idx = pmc_idx - INTEL_PMC_IDX_FIXED;
		u8 ctrl = fixed_ctrl_field(pmu->fixed_ctr_ctrl, idx);

		reprogram_fixed_counter(pmc, ctrl, idx);
	}
}
EXPORT_SYMBOL_GPL(reprogram_counter);

void kvm_pmu_handle_event(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);
	u64 bitmask;
	int bit;

	bitmask = pmu->reprogram_pmi;

	for_each_set_bit(bit, (unsigned long *)&bitmask, X86_PMC_IDX_MAX) {
		struct kvm_pmc *pmc = kvm_x86_ops->pmu_ops->pmc_idx_to_pmc(pmu, bit);

		if (unlikely(!pmc || !pmc->perf_event)) {
			clear_bit(bit, (unsigned long *)&pmu->reprogram_pmi);
			continue;
		}

		reprogram_counter(pmu, bit);
	}
}

/* check if idx is a valid index to access PMU */
int kvm_pmu_is_valid_msr_idx(struct kvm_vcpu *vcpu, unsigned idx)
{
	return kvm_x86_ops->pmu_ops->is_valid_msr_idx(vcpu, idx);
}

int kvm_pmu_rdpmc(struct kvm_vcpu *vcpu, unsigned idx, u64 *data)
  /*
   * 读取pmc的值 调用pmu_intel.c中的intel_msr_idx_to_pmc
   * 成功返回0 失败返回1
   */
{
	bool fast_mode = idx & (1u << 31);
	struct kvm_pmc *pmc;
	u64 ctr_val;
  printk(KERN_NOTICE "I am kvm_pmu_rdpmc in pmu.c");

	pmc = kvm_x86_ops->pmu_ops->msr_idx_to_pmc(vcpu, idx);
	if (!pmc)
		return 1;

	ctr_val = pmc_read_counter(pmc);
	if (fast_mode)
		ctr_val = (u32)ctr_val;

	*data = ctr_val;
	return 0;
}

void kvm_pmu_deliver_pmi(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.apic)
		kvm_apic_local_deliver(vcpu->arch.apic, APIC_LVTPC);
}

bool kvm_pmu_is_valid_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	return kvm_x86_ops->pmu_ops->is_valid_msr(vcpu, msr);
}

int kvm_pmu_get_msr(struct kvm_vcpu *vcpu, u32 msr, u64 *data)
{
	return kvm_x86_ops->pmu_ops->get_msr(vcpu, msr, data);
}

int kvm_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	return kvm_x86_ops->pmu_ops->set_msr(vcpu, msr_info);
}

/* refresh PMU settings. This function generally is called when underlying
 * settings are changed (such as changes of PMU CPUID by guest VMs), which
 * should rarely happen.
 */
void kvm_pmu_refresh(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->pmu_ops->refresh(vcpu);
}

void kvm_pmu_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);

	irq_work_sync(&pmu->irq_work);
	kvm_x86_ops->pmu_ops->reset(vcpu);
}

void kvm_pmu_init(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = vcpu_to_pmu(vcpu);

	memset(pmu, 0, sizeof(*pmu));
	kvm_x86_ops->pmu_ops->init(vcpu);
	init_irq_work(&pmu->irq_work, kvm_pmi_trigger_fn);
	kvm_pmu_refresh(vcpu);
}

void kvm_pmu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_pmu_reset(vcpu);
}

static int hello_init(void)
{
  printk(KERN_NOTICE "recompile pmu.c end\n");
  return 0;
}

static void hello_exit(void)
{
  printk(KERN_NOTICE "recompile pmu.c start!\n");
}
module_init(hello_init);
module_exit(hello_exit);
