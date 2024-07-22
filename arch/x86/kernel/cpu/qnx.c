// SPDX-License-Identifier: GPL-2.0
/*
 * QNX detection support
 *
 */

#include <asm/cpufeatures.h>
#include <asm/desc.h>
#include <asm/hypervisor.h>

#define QNX_CPUID_FEATURES		0x40000000

static u32 __init qnx_detect(void)
{
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		uint32_t eax, signature[2], edx;

		cpuid(QNX_CPUID_FEATURES, &eax, &signature[0], &signature[1], &edx);

		if (!memcmp("QNXQVMBS", signature, 8))
			return 1;
	}

	return 0;
}

static void __init qnx_init_platform(void)
{
	setup_clear_cpu_cap(X86_FEATURE_TME);
	setup_clear_cpu_cap(X86_FEATURE_WAITPKG);
	setup_clear_cpu_cap(X86_FEATURE_MSR_SPEC_CTRL);
}

static bool qnx_x2apic_available(void)
{
	return boot_cpu_has(X86_FEATURE_X2APIC);
}

const __initconst struct hypervisor_x86 x86_hyper_qnx = {
	.name			= "QNX",
	.detect			= qnx_detect,
	.type			= X86_HYPER_QNX,
	.init.init_platform	= qnx_init_platform,
	.init.x2apic_available	= qnx_x2apic_available,
};
