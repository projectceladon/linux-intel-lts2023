#ifndef I915_VMA_H
#define I915_VMA_H

#include <uapi/drm/i915_drm.h>
#include <drm/drm_mm.h>
#include "xe_ggtt_types.h"

struct xe_bo;

struct i915_vma {
	struct xe_bo *bo, *dpt;
	struct xe_ggtt_node *node;
};

#endif
