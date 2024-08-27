/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2024, Intel Corporation. All rights reserved.
 */

#ifndef __INTEL_PXP_FE_H__
#define __INTEL_PXP_FE_H__

#include <linux/errno.h>
#include <linux/types.h>
#include "pxp/intel_pxp_types.h"
#include "pxp/intel_pxp.h"

struct drm_device;
struct drm_file;

struct drm_i915_gem_object;
struct drm_i915_private;
struct intel_pxp;

static inline bool intel_pxp_is_in_vf(const struct intel_pxp *pxp)
{
	return IS_ENABLED(CONFIG_DRM_I915_PXP) && pxp && pxp->vf;
}

#ifdef CONFIG_DRM_I915_PXP
bool intel_pxp_fe_is_supported(const struct intel_pxp *pxp);
bool intel_pxp_fe_is_enabled(const struct intel_pxp *pxp);
bool intel_pxp_fe_is_active(const struct intel_pxp *pxp);

int intel_pxp_fe_init(struct drm_i915_private *i915);
void intel_pxp_fe_fini(struct drm_i915_private *i915);

void intel_pxp_fe_init_hw(struct intel_pxp *pxp);
void intel_pxp_fe_fini_hw(struct intel_pxp *pxp);

void intel_pxp_fe_mark_termination_in_progress(struct intel_pxp *pxp);

int intel_pxp_fe_get_readiness_status(struct intel_pxp *pxp, int timeout_ms);
int intel_pxp_fe_get_backend_timeout_ms(struct intel_pxp *pxp);
int intel_pxp_fe_start(struct intel_pxp *pxp);
void intel_pxp_fe_end(struct intel_pxp *pxp);

int intel_pxp_fe_key_check(struct intel_pxp *pxp,
		struct drm_i915_gem_object *obj,
		bool assign);

void intel_pxp_fe_invalidate(struct intel_pxp *pxp);

int i915_pxp_fe_ops_ioctl(struct drm_device *dev, void *data, struct drm_file *drmfile);
void intel_pxp_fe_close(struct intel_pxp *pxp, struct drm_file *drmfile);

void intel_pxp_fe_suspend_prepare(struct intel_pxp *pxp);
void intel_pxp_fe_suspend(struct intel_pxp *pxp);
void intel_pxp_fe_resume_complete(struct intel_pxp *pxp);
void intel_pxp_fe_runtime_suspend(struct intel_pxp *pxp);
void intel_pxp_fe_runtime_resume(struct intel_pxp *pxp);

#else

bool intel_pxp_fe_is_supported(const struct intel_pxp *pxp)
{
	return false;
}
bool intel_pxp_fe_is_enabled(const struct intel_pxp *pxp)
{
	return false;
}
bool intel_pxp_fe_is_active(const struct intel_pxp *pxp)
{
	return false;
}
int intel_pxp_fe_init(struct drm_i915_private *i915)
{
	return 0;
}
void intel_pxp_fe_fini(struct drm_i915_private *i915)
{

}
void intel_pxp_fe_init_hw(struct intel_pxp *pxp)
{

}
void intel_pxp_fe_fini_hw(struct intel_pxp *pxp)
{

}
void intel_pxp_fe_mark_termination_in_progress(struct intel_pxp *pxp)
{

}

int intel_pxp_fe_get_readiness_status(struct intel_pxp *pxp, int timeout_ms)
{
	return 0;
}
int intel_pxp_fe_get_backend_timeout_ms(struct intel_pxp *pxp)
{
	return 0;
}
int intel_pxp_fe_start(struct intel_pxp *pxp)
{
	return 0;
}
void intel_pxp_fe_end(struct intel_pxp *pxp)
{
}

int intel_pxp_fe_key_check(struct intel_pxp *pxp,
		struct drm_i915_gem_object *obj,
		bool assign)
{
	return 0;
}

void intel_pxp_fe_invalidate(struct intel_pxp *pxp)
{
}

int i915_pxp_fe_ops_ioctl(struct drm_device *dev, void *data, struct drm_file *drmfile)
{
	return 0;
}
void intel_pxp_fe_close(struct intel_pxp *pxp, struct drm_file *drmfile)
{
}

void intel_pxp_fe_suspend_prepare(struct intel_pxp *pxp)
{

}
void intel_pxp_fe_suspend(struct intel_pxp *pxp)
{

}
void intel_pxp_fe_resume_complete(struct intel_pxp *pxp)
{

}
void intel_pxp_fe_runtime_suspend(struct intel_pxp *pxp)
{

}
void intel_pxp_fe_runtime_resume(struct intel_pxp *pxp)
{

}
#endif
#endif /* __INTEL_PXP_FE_H__ */
