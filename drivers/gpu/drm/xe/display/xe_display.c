// SPDX-License-Identifier: MIT
/*
 * Copyright © 2023 Intel Corporation
 */

#include "xe_display.h"
#include "regs/xe_irq_regs.h"

#include <linux/fb.h>

#include <drm/drm_drv.h>
#include <drm/drm_managed.h>
#include <drm/drm_probe_helper.h>
#include <uapi/drm/xe_drm.h>

#include "soc/intel_dram.h"
#include "intel_acpi.h"
#include "intel_audio.h"
#include "intel_bw.h"
#include "intel_display.h"
#include "intel_display_driver.h"
#include "intel_display_irq.h"
#include "intel_display_types.h"
#include "intel_dmc.h"
//#include "intel_dmc_wl.h"
#include "intel_dp.h"
//#include "intel_encoder.h"
#include "intel_fbdev.h"
#include "intel_hdcp.h"
#include "intel_hotplug.h"
#include "intel_opregion.h"
#include "xe_module.h"

#define DISPLAY_RUNTIME_INFO_XE(display)      (&(display)->info.__runtime_info)
#define HAS_DISPLAY_XE(__display)            (DISPLAY_RUNTIME_INFO_XE(__display)->pipe_mask != 0)

/* Xe device functions */
void intel_encoder_suspend_all(struct intel_display *display)
{
	struct intel_encoder *encoder;

	if (!HAS_DISPLAY_XE(display))
		return;

	/*
	 * TODO: check and remove holding the modeset locks if none of
	 * the encoders depends on this.
	 */
	drm_modeset_lock_all(display->drm);
	for_each_intel_encoder(display->drm, encoder)
		if (encoder->suspend)
			encoder->suspend(encoder);
	drm_modeset_unlock_all(display->drm);

	for_each_intel_encoder(display->drm, encoder)
		if (encoder->suspend_complete)
			encoder->suspend_complete(encoder);
}

void intel_encoder_shutdown_all(struct intel_display *display)
{
	struct intel_encoder *encoder;

	if (!HAS_DISPLAY_XE(display))
		return;

	/*
	 * TODO: check and remove holding the modeset locks if none of
	 * the encoders depends on this.
	 */
	drm_modeset_lock_all(display->drm);
	for_each_intel_encoder(display->drm, encoder)
		if (encoder->shutdown)
			encoder->shutdown(encoder);
	drm_modeset_unlock_all(display->drm);

	for_each_intel_encoder(display->drm, encoder)
		if (encoder->shutdown_complete)
			encoder->shutdown_complete(encoder);
}

static bool has_display(struct xe_device *xe)
{
	return HAS_DISPLAY_XE(&xe->display);
}

/**
 * xe_display_driver_probe_defer - Detect if we need to wait for other drivers
 *				   early on
 * @pdev: PCI device
 *
 * Returns: true if probe needs to be deferred, false otherwise
 */
bool xe_display_driver_probe_defer(struct pci_dev *pdev)
{
	if (!xe_modparam.probe_display)
		return 0;

	return intel_display_driver_probe_defer(pdev);
}

/**
 * xe_display_driver_set_hooks - Add driver flags and hooks for display
 * @driver: DRM device driver
 *
 * Set features and function hooks in @driver that are needed for driving the
 * display IP. This sets the driver's capability of driving display, regardless
 * if the device has it enabled
 */
void xe_display_driver_set_hooks(struct drm_driver *driver)
{
	if (!xe_modparam.probe_display)
		return;

	driver->driver_features |= DRIVER_MODESET | DRIVER_ATOMIC;
}

static void unset_display_features(struct xe_device *xe)
{
	xe->drm.driver_features &= ~(DRIVER_MODESET | DRIVER_ATOMIC);
}

static void display_destroy(struct drm_device *dev, void *dummy)
{
	struct xe_device *xe = to_xe_device(dev);

	destroy_workqueue(xe->display.hotplug.dp_wq);
}

/**
 * xe_display_create - create display struct
 * @xe: XE device instance
 *
 * Initialize all fields used by the display part.
 *
 * TODO: once everything can be inside a single struct, make the struct opaque
 * to the rest of xe and return it to be xe->display.
 *
 * Returns: 0 on success
 */
int xe_display_create(struct xe_device *xe)
{
	spin_lock_init(&xe->display.fb_tracking.lock);
	mutex_init(&xe->display.audio.mutex);
	mutex_init(&xe->display.wm.wm_mutex);
	mutex_init(&xe->display.pps.mutex);
	mutex_init(&xe->display.hdcp.hdcp_mutex);

	xe->display.hotplug.dp_wq = alloc_ordered_workqueue("xe-dp", 0);
	xe->enabled_irq_mask = ~0;
	xe->params.invert_brightness = 0;
	xe->params.vbt_sdvo_panel_type = -1;
	xe->params.disable_power_well = -1;
	xe->params.enable_dc = -1;
	xe->params.enable_dpcd_backlight = -1;
	xe->params.enable_dp_mst = 1;
	xe->params.enable_dpt = true;
	xe->params.enable_fbc = -1;
	xe->params.enable_psr = -1;
	xe->params.enable_psr2_sel_fetch = true;
	xe->params.enable_sagv = true;
	xe->params.panel_use_ssc = -1;

	return drmm_add_action_or_reset(&xe->drm, display_destroy, NULL);
}

static void xe_display_fini_nommio(struct drm_device *dev, void *dummy)
{
	struct xe_device *xe = to_xe_device(dev);
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_power_domains_cleanup(xe);
}

int xe_display_init_nommio(struct xe_device *xe)
{
	if (!xe->info.probe_display)
		return 0;

	/* Fake uncore lock */
	spin_lock_init(&xe->uncore.lock);

	/* This must be called before any calls to HAS_PCH_* */
	intel_detect_pch(xe);

	return drmm_add_action_or_reset(&xe->drm, xe_display_fini_nommio, xe);
}

static void xe_display_fini_noirq(void *arg)
{
	struct xe_device *xe = arg;
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_display_driver_remove_noirq(xe);
	intel_opregion_cleanup(xe);
}

int xe_display_init_noirq(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;
	int err;

	if (!xe->info.probe_display)
		return 0;

	intel_display_driver_early_probe(xe);

	/* Early display init.. */
	intel_opregion_setup(xe);

	/*
	 * Fill the dram structure to get the system dram info. This will be
	 * used for memory latency calculation.
	 */
	intel_dram_detect(xe);

	intel_bw_init_hw(xe);

	intel_display_device_info_runtime_init(xe);

	err = intel_display_driver_probe_noirq(xe);
	if (err) {
		intel_opregion_cleanup(xe);
		return err;
	}

	return devm_add_action_or_reset(xe->drm.dev, xe_display_fini_noirq, xe);
}

static void xe_display_fini_noaccel(void *arg)
{
	struct xe_device *xe = arg;
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_display_driver_remove_nogem(xe);
}

int xe_display_init_noaccel(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;
	int err;

	if (!xe->info.probe_display)
		return 0;

	err = intel_display_driver_probe_nogem(xe);
	if (err)
		return err;

	return devm_add_action_or_reset(xe->drm.dev, xe_display_fini_noaccel, xe);
}

int xe_display_init(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return 0;

	return intel_display_driver_probe(xe);
}

void xe_display_fini(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_hpd_poll_fini(xe);
	intel_fbdev_fini(xe);

	intel_hdcp_component_fini(xe);
	intel_audio_deinit(xe);
}

void xe_display_register(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_display_driver_register(xe);
	intel_power_domains_enable(xe);
	intel_register_dsm_handler();
}

void xe_display_unregister(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_unregister_dsm_handler();
	intel_power_domains_disable(xe);
	intel_display_driver_unregister(xe);
}

void xe_display_driver_remove(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	intel_display_driver_remove(xe);
}

/* IRQ-related functions */

void xe_display_irq_handler(struct xe_device *xe, u32 master_ctl)
{
	if (!xe->info.probe_display)
		return;

	if (master_ctl & DISPLAY_IRQ)
		gen11_display_irq_handler(xe);
}

void xe_display_irq_enable(struct xe_device *xe, u32 gu_misc_iir)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	if (gu_misc_iir & GU_MISC_GSE)
		intel_opregion_asle_intr(xe);
}

void xe_display_irq_reset(struct xe_device *xe)
{
	if (!xe->info.probe_display)
		return;

	gen11_display_irq_reset(xe);
}

void xe_display_irq_postinstall(struct xe_device *xe, struct xe_gt *gt)
{
	if (!xe->info.probe_display)
		return;

	if (gt->info.id == XE_GT0)
		gen11_de_irq_postinstall(xe);
}

static bool suspend_to_idle(void)
{
#if IS_ENABLED(CONFIG_ACPI_SLEEP)
	if (acpi_target_system_state() < ACPI_STATE_S3)
		return true;
#endif
	return false;
}

static void xe_display_flush_cleanup_work(struct xe_device *xe)
{
	struct intel_crtc *crtc;

	for_each_intel_crtc(&xe->drm, crtc) {
		struct drm_crtc_commit *commit;

		spin_lock(&crtc->base.commit_lock);
		commit = list_first_entry_or_null(&crtc->base.commit_list,
						  struct drm_crtc_commit, commit_entry);
		if (commit)
			drm_crtc_commit_get(commit);
		spin_unlock(&crtc->base.commit_lock);

		if (commit) {
			wait_for_completion(&commit->cleanup_done);
			drm_crtc_commit_put(commit);
		}
	}
}

/* TODO: System and runtime suspend/resume sequences will be sanitized as a follow-up. */
static void __xe_display_pm_suspend(struct xe_device *xe, bool runtime)
{
	bool s2idle = suspend_to_idle();
	if (!xe->info.probe_display)
		return;

	/*
	 * We do a lot of poking in a lot of registers, make sure they work
	 * properly.
	 */
	intel_power_domains_disable(xe);
	if (!runtime)
		intel_fbdev_set_suspend(&xe->drm, FBINFO_STATE_SUSPENDED, true);

	if (!runtime && has_display(xe)) {
		drm_kms_helper_poll_disable(&xe->drm);
		intel_display_driver_suspend(xe);
	}

	xe_display_flush_cleanup_work(xe);

	intel_hpd_cancel_work(xe);
	if (!runtime && has_display(xe)) {
		intel_encoder_suspend_all(&xe->display);
	}

	intel_opregion_suspend(xe, s2idle ? PCI_D1 : PCI_D3cold);

	intel_dmc_suspend(xe);

	if (runtime && has_display(xe))
		intel_hpd_poll_enable(xe);
}

void xe_display_pm_suspend(struct xe_device *xe)
{
	__xe_display_pm_suspend(xe, false);
}

void xe_display_pm_shutdown(struct xe_device *xe)
{

	if (!xe->info.probe_display)
		return;

	intel_power_domains_disable(xe);
	intel_fbdev_set_suspend(&xe->drm, FBINFO_STATE_SUSPENDED, true);
	if (has_display(xe)) {
		drm_kms_helper_poll_disable(&xe->drm);
		intel_display_driver_suspend(xe);
	}

	xe_display_flush_cleanup_work(xe);
	intel_dp_mst_suspend(xe);
	intel_hpd_cancel_work(xe);

	intel_encoder_suspend_all(&xe->display);
	intel_encoder_shutdown_all(&xe->display);
	intel_opregion_suspend(xe, PCI_D3cold);

	intel_dmc_suspend(xe);
}

void xe_display_pm_runtime_suspend(struct xe_device *xe)
{
	if (!xe->info.probe_display)
		return;

	if (xe->d3cold.allowed) {
		__xe_display_pm_suspend(xe, true);
		return;
	}

	intel_hpd_poll_enable(xe);
}

void xe_display_pm_suspend_late(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;
	bool s2idle = suspend_to_idle();

	if (!xe->info.probe_display)
		return;

	intel_power_domains_suspend(xe, I915_DRM_SUSPEND_MEM);
	intel_display_power_suspend_late(xe);
}

void xe_display_pm_runtime_suspend_late(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	if (xe->d3cold.allowed)
		xe_display_pm_suspend_late(xe);
}

void xe_display_pm_shutdown_late(struct xe_device *xe)
{
	struct intel_display *display = &xe->display;

	if (!xe->info.probe_display)
		return;

	/*
	 * The only requirement is to reboot with display DC states disabled,
	 * for now leaving all display power wells in the INIT power domain
	 * enabled.
	 */
	intel_power_domains_driver_remove(xe);
}

void xe_display_pm_resume_early(struct xe_device *xe)
{

	if (!xe->info.probe_display)
		return;

	intel_display_power_resume_early(xe);
	intel_power_domains_resume(xe);
}

static void __xe_display_pm_resume(struct xe_device *xe, bool runtime)
{

	if (!xe->info.probe_display)
		return;

	intel_dmc_resume(xe);

	if (has_display(xe))
		drm_mode_config_reset(&xe->drm);

	intel_display_driver_init_hw(xe);

	intel_hpd_init(xe);

	if (!runtime && has_display(xe)) {
		intel_dp_mst_resume(xe);
		intel_display_driver_resume(xe);
		drm_kms_helper_poll_enable(&xe->drm);
	}

	if (has_display(xe)) {
		intel_hpd_poll_disable(xe);
	}
	intel_opregion_resume(xe);

	if (!runtime)
		intel_fbdev_set_suspend(&xe->drm, FBINFO_STATE_RUNNING, false);

	intel_power_domains_enable(xe);
}

void xe_display_pm_resume(struct xe_device *xe)
{
	__xe_display_pm_resume(xe, false);
}

void xe_display_pm_runtime_resume(struct xe_device *xe)
{
	if (!xe->info.probe_display)
		return;

	if (xe->d3cold.allowed) {
		__xe_display_pm_resume(xe, true);
		return;
	}

	intel_hpd_init(xe);
	intel_hpd_poll_disable(xe);
}

int xe_display_probe(struct xe_device *xe)
{
	struct pci_dev *pdev = to_pci_dev(xe->drm.dev);
	struct intel_display *display;
	int err;

	if (!xe->info.probe_display)
		goto no_display;

	intel_display_device_probe(xe);
	display = &xe->display;

	if (has_display(xe))
		return 0;

no_display:
	xe->info.probe_display = false;
	unset_display_features(xe);
	return 0;
}
