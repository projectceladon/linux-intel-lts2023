#ifndef __INTEL_RUNTIME_PM_H__
#define __INTEL_RUNTIME_PM_H__

#include "intel_wakeref.h"

enum i915_drm_suspend_mode {
	I915_DRM_SUSPEND_IDLE,
	I915_DRM_SUSPEND_MEM,
	I915_DRM_SUSPEND_HIBERNATE,
};

#endif
