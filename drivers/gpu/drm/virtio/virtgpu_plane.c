/*
 * Copyright (C) 2015 Red Hat, Inc.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <drm/drm_atomic_helper.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_blend.h>

#include "virtgpu_drv.h"

static uint32_t virtio_gpu_formats[] = {
	DRM_FORMAT_XRGB8888,
	DRM_FORMAT_ARGB8888,
	DRM_FORMAT_BGRX8888,
	DRM_FORMAT_BGRA8888,
	DRM_FORMAT_RGBX8888,
	DRM_FORMAT_RGBA8888,
	DRM_FORMAT_XBGR8888,
	DRM_FORMAT_ABGR8888,
};

static const uint32_t virtio_gpu_cursor_formats[] = {
	DRM_FORMAT_HOST_ARGB8888,
};

static struct plane_format {
	uint32_t size;
	uint32_t format_info[128];
};

static struct output_planes_format {

	/* presumably take 5 as the max, since i915 only has 5 planes per pipe */
	struct plane_format planes[5];
	int sprite_plane_index;

} virtio_gpu_output_planes_formats[16];


uint32_t virtio_gpu_translate_format(uint32_t drm_fourcc)
{
	uint32_t format;

	switch (drm_fourcc) {
#ifdef __BIG_ENDIAN
	case DRM_FORMAT_XRGB8888:
		format = VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM;
		break;
	case DRM_FORMAT_ARGB8888:
		format = VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM;
		break;
	case DRM_FORMAT_BGRX8888:
		format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
		break;
	case DRM_FORMAT_BGRA8888:
		format = VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM;
		break;
	case DRM_FORMAT_RGBX8888:
		format = VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM;
		break;
	case DRM_FORMAT_RGBA8888:
		format = VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM;
		break;
	case DRM_FORMAT_XBGR8888:
		format = VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM;
		break;
	case DRM_FORMAT_ABGR8888:
		format = VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM;
		break;
#else
	case DRM_FORMAT_XRGB8888:
		format = VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM;
		break;
	case DRM_FORMAT_ARGB8888:
		format = VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM;
		break;
	case DRM_FORMAT_BGRX8888:
		format = VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM;
		break;
	case DRM_FORMAT_BGRA8888:
		format = VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM;
		break;
	case DRM_FORMAT_RGBX8888:
		format = VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM;
		break;
	case DRM_FORMAT_RGBA8888:
		format = VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM;
		break;
	case DRM_FORMAT_XBGR8888:
		format = VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM;
		break;
	case DRM_FORMAT_ABGR8888:
		format = VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM;
		break;
	case DRM_FORMAT_NV12:
		format = DRM_FORMAT_NV12;
		break;
#endif
	default:
		/*
		 * This should not happen, we handle everything listed
		 * in virtio_gpu_formats[].
		 */
		format = 0;
		break;
	}
	WARN_ON(format == 0);
	return format;
}

static struct drm_plane_funcs virtio_gpu_plane_funcs = {
	.update_plane		= drm_atomic_helper_update_plane,
	.disable_plane		= drm_atomic_helper_disable_plane,
	.reset			= drm_atomic_helper_plane_reset,
	.atomic_duplicate_state = drm_atomic_helper_plane_duplicate_state,
	.atomic_destroy_state	= drm_atomic_helper_plane_destroy_state,
};

static int virtio_gpu_check_plane_rotation(struct drm_plane_state *state,
						struct virtio_gpu_output *output)
{
	int index;
	index = state->plane->index;

	if(!(state->rotation & output->rotation[index])) {
		DRM_DEBUG("sprite plane rotation check failed \n");
		return -EINVAL;
	}
	return 0;
}

#define ICL_MAX_SRC_W 5120
#define ICL_MAX_SRC_H 4096
#define ICL_MAX_DST_W 5120
#define ICL_MAX_DST_H 4096
#define SKL_MIN_SRC_W 8
#define SKL_MIN_SRC_H 8
#define SKL_MIN_DST_W 8
#define SKL_MIN_DST_H 8

static int virtio_gpu_check_plane_scaling(struct drm_plane_state *state,
						struct virtio_gpu_output *output)
{
	int scaler_user = drm_plane_index(state->plane);
	int src_w, src_h, dst_w, dst_h;
	struct drm_framebuffer *fb = state->fb;
	output = drm_crtc_to_virtio_gpu_output(state->crtc);
	src_w = state->src_w >> 16;
	src_h = state->src_h >> 16;
	dst_w = state->crtc_w;
	dst_h = state->crtc_h;

	if (src_w == dst_w && src_h == dst_h)
		return 0;
	/*hard code the format and scale check as physical gpu */
	if (src_w > ICL_MAX_SRC_W || src_h > ICL_MAX_SRC_H ||
		dst_w > ICL_MAX_DST_W || dst_h > ICL_MAX_DST_H ||
		src_w < SKL_MIN_SRC_W || src_h < SKL_MIN_SRC_H ||
		dst_w < SKL_MIN_DST_W || dst_h < SKL_MIN_DST_H) {

		drm_dbg_kms(state->plane->dev,
				"scaler_user index %u: src %ux%u dst %ux%u "
				"size is out of scaler range\n",
				scaler_user, src_w, src_h,
				dst_w, dst_h);

		return -EINVAL;

	}

	if(fb) {
		switch (fb->format->format) {
			case DRM_FORMAT_RGB565:
			case DRM_FORMAT_XBGR8888:
			case DRM_FORMAT_XRGB8888:
			case DRM_FORMAT_ABGR8888:
			case DRM_FORMAT_ARGB8888:
			case DRM_FORMAT_XRGB2101010:
			case DRM_FORMAT_XBGR2101010:
			case DRM_FORMAT_ARGB2101010:
			case DRM_FORMAT_ABGR2101010:
			case DRM_FORMAT_YUYV:
			case DRM_FORMAT_YVYU:
			case DRM_FORMAT_UYVY:
			case DRM_FORMAT_VYUY:
			case DRM_FORMAT_NV12:
			case DRM_FORMAT_XYUV8888:
			case DRM_FORMAT_P010:
			case DRM_FORMAT_P012:
			case DRM_FORMAT_P016:
			case DRM_FORMAT_Y210:
			case DRM_FORMAT_Y212:
			case DRM_FORMAT_Y216:
			case DRM_FORMAT_XVYU2101010:
			case DRM_FORMAT_XVYU12_16161616:
			case DRM_FORMAT_XVYU16161616:
			case DRM_FORMAT_XBGR16161616F:
			case DRM_FORMAT_ABGR16161616F:
			case DRM_FORMAT_XRGB16161616F:
			case DRM_FORMAT_ARGB16161616F:
				break;
			default:
				drm_dbg_kms(state->plane->dev,
						"[PLANE:%d:%s] FB:%d unsupported scaling format 0x%x\n",
						state->plane->index, state->plane->name,
						fb->base.id, fb->format->format);
				return -EINVAL;
		}
	}
	output->scaler_users |= (1 << scaler_user);
	drm_dbg_kms(state->plane->dev,
		    "staged scaling request for %ux%u->%ux%u in scale check ",
		     src_w, src_h, dst_w, dst_h);

	return 0;
}

static int virtio_gpu_plane_atomic_check(struct drm_plane *plane,
					 struct drm_atomic_state *state)
{
	struct drm_plane_state *new_plane_state = drm_atomic_get_new_plane_state(state,
										 plane);
	struct drm_plane_state *old_plane_state = drm_atomic_get_old_plane_state(state,
										 plane);
	struct drm_device *dev = plane->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	bool is_cursor = 1;
	struct virtio_gpu_output *output = NULL;
	output = drm_crtc_to_virtio_gpu_output(new_plane_state->crtc);

	if(plane->type == DRM_PLANE_TYPE_PRIMARY && !vgdev->has_multi_plane)
		is_cursor = 0;

	struct drm_crtc_state *crtc_state;
	int ret;
	int min_scale = DRM_PLANE_NO_SCALING;
	int max_scale = DRM_PLANE_NO_SCALING;

	if (!new_plane_state->fb || WARN_ON(!new_plane_state->crtc))
		return 0;

	/*
	 * Ignore damage clips if the framebuffer attached to the plane's state
	 * has changed since the last plane update (page-flip). In this case, a
	 * full plane update should happen because uploads are done per-buffer.
	 */
	if (old_plane_state->fb != new_plane_state->fb)
		new_plane_state->ignore_damage_clips = true;

	crtc_state = drm_atomic_get_crtc_state(state,
					       new_plane_state->crtc);
	if (IS_ERR(crtc_state))
                return PTR_ERR(crtc_state);

	if(vgdev->has_scaling && (new_plane_state->fb->format->format != DRM_FORMAT_C8)) {
		min_scale = 1;
		max_scale = 0x30000-1;
	}
	ret = drm_atomic_helper_check_plane_state(new_plane_state, crtc_state,
						  min_scale,
						  max_scale,
						  is_cursor, true);
	if(ret) {
		DRM_DEBUG("sprite plane scaling check failed ret:%d \n", ret);
		return ret;
	}

	if(min_scale == 1) {
		ret = virtio_gpu_check_plane_scaling(new_plane_state, output);
		if(ret)
			return ret;
	}

	if(vgdev->has_rotation && new_plane_state->rotation) {
		return virtio_gpu_check_plane_rotation(new_plane_state, output);
	}
	return 0;
}

static void virtio_gpu_update_dumb_bo(struct virtio_gpu_device *vgdev,
				      struct drm_plane_state *state,
				      struct drm_rect *rect)
{
	struct virtio_gpu_object *bo =
		gem_to_virtio_gpu_obj(state->fb->obj[0]);
	struct virtio_gpu_object_array *objs;
	uint32_t w = rect->x2 - rect->x1;
	uint32_t h = rect->y2 - rect->y1;
	uint32_t x = rect->x1;
	uint32_t y = rect->y1;
	uint32_t off = x * state->fb->format->cpp[0] +
		y * state->fb->pitches[0];

	objs = virtio_gpu_array_alloc(1);
	if (!objs)
		return;
	virtio_gpu_array_add_obj(objs, &bo->base.base);

	virtio_gpu_cmd_transfer_to_host_2d(vgdev, off, w, h, x, y,
					   objs, NULL);
}

static void virtio_gpu_resource_flush(struct drm_plane *plane,
				      uint32_t x, uint32_t y,
				      uint32_t width, uint32_t height)
{
	struct drm_device *dev = plane->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_framebuffer *vgfb;
	struct virtio_gpu_object *bo;
	struct virtio_gpu_object_array *objs = NULL;
	struct virtio_gpu_fence *fence = NULL;
	int i;

	vgfb = to_virtio_gpu_framebuffer(plane->state->fb);
	bo = gem_to_virtio_gpu_obj(vgfb->base.obj[0]);
	fence = virtio_gpu_fence_alloc(vgdev, vgdev->fence_drv.context, 0);

	if (fence) {
		objs = virtio_gpu_array_alloc(1);
		if (!objs) {
			kfree(fence);
			return;
		}
		virtio_gpu_array_add_obj(objs, vgfb->base.obj[0]);
		virtio_gpu_array_lock_resv(objs);
	}

	virtio_gpu_cmd_resource_flush(vgdev, bo->hw_res_handle, x, y,
				      width, height, objs, fence);
	virtio_gpu_notify(vgdev);

	if (fence) {
		dma_fence_wait_timeout(&fence->f, true,
				       msecs_to_jiffies(50));
		dma_fence_put(&fence->f);
	}
}

static void virtio_gpu_resource_flush_sprite(struct drm_plane *plane, int indx,
				      struct drm_framebuffer *fb,
				      uint32_t x, uint32_t y,
				      uint32_t width, uint32_t height)
{
	struct drm_device *dev = plane->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_framebuffer *vgfb;
	struct virtio_gpu_object_array *objs = NULL;
	struct virtio_gpu_fence *fence = NULL;
	uint32_t resource_id[4];
	int i, cnt=0;

	vgfb = to_virtio_gpu_framebuffer(plane->state->fb);
	fence = virtio_gpu_fence_alloc(vgdev, vgdev->fence_drv.context, 0);

	if (fence) {
		objs = virtio_gpu_array_alloc(1);
		if (!objs) {
			kfree(fence);
			return;
		}

		virtio_gpu_array_add_obj(objs, vgfb->base.obj[0]);
		for(i=1; i<fb->format->num_planes; i++) {
			if(vgfb->base.obj[i] != vgfb->base.obj[0])
				virtio_gpu_array_add_obj(objs, vgfb->base.obj[i]);
		}
		virtio_gpu_array_lock_resv(objs);
	}

	for(i=0; i<4; i++) {
		if(vgfb->base.obj[i]) {
			struct virtio_gpu_object *bo;
			bo = gem_to_virtio_gpu_obj(vgfb->base.obj[i]);
			resource_id[i] = bo->hw_res_handle;
			cnt++;
		} else {
			resource_id[i] = 0;
		}
	}

	virtio_gpu_cmd_resource_flush_sprite(vgdev, indx, plane->index,fb,
			resource_id, cnt, x, y, width, height, objs, fence);

	virtio_gpu_notify(vgdev);

	if (fence) {
		dma_fence_wait_timeout(&fence->f, true,
				       msecs_to_jiffies(50));
		dma_fence_put(&fence->f);
	}
}

static void virtio_gpu_sprite_plane_update(struct drm_plane *plane,
					    struct drm_atomic_state *state)
{
	struct drm_device *dev = plane->dev;
	struct drm_plane_state *new_state = drm_atomic_get_new_plane_state(state,
									   plane);
	struct drm_plane_state *old_state = drm_atomic_get_old_plane_state(state,
									   plane);
	struct drm_framebuffer *fb = new_state->fb;

	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = NULL;
	struct virtio_gpu_cmd cmd_set[3];
	int cnt = 0;

	if (plane->state->crtc)
		output = drm_crtc_to_virtio_gpu_output(plane->state->crtc);
	if (old_state->crtc)
		output = drm_crtc_to_virtio_gpu_output(old_state->crtc);
	if (WARN_ON(!output))
		return;

	if (!plane->state->fb || !output->crtc.state->active) {
		DRM_DEBUG("sprite nofb\n");
		return;
	}

	if ((vgdev->has_rotation) && plane->state->rotation) {
		cmd_set[cnt].cmd = VIRTIO_GPU_TUNNEL_CMD_SET_ROTATION;
		cmd_set[cnt].size = 2;
		cmd_set[cnt].data64[0]= plane->state->rotation;
		cnt++;
	}
	if (vgdev->has_scaling) {
		cmd_set[cnt].cmd = VIRTIO_GPU_TUNNEL_CMD_SET_SPRITE_SCALING;
		cmd_set[cnt].size = 4;
		cmd_set[cnt].data32[0] = plane->state->crtc_x;
		cmd_set[cnt].data32[1] = plane->state->crtc_y;
		cmd_set[cnt].data32[2] = plane->state->crtc_w;
		cmd_set[cnt].data32[3] = plane->state->crtc_h;
		cnt++;
	}

	if ((vgdev->has_pixel_blend_mode) && (plane->state->fb->format->has_alpha)) {
		cmd_set[cnt].cmd = VIRTIO_GPU_TUNNEL_CMD_SET_BLEND;
		cmd_set[cnt].size = 2;
		cmd_set[cnt].data32[0]= plane->state->pixel_blend_mode;
		cmd_set[cnt].data32[1]=(uint32_t)plane->state->alpha;
		cnt++;
	}

	if(cnt) {
		virtio_gpu_cmd_send_misc(vgdev, output->index, plane->index, cmd_set, cnt);
	}
	virtio_gpu_resource_flush_sprite(plane,
				  output->index,
				  fb,
				  plane->state->src_x >> 16,
				  plane->state->src_y >> 16,
				  plane->state->src_w >> 16,
				  plane->state->src_h >> 16);
}

static void virtio_gpu_primary_plane_update(struct drm_plane *plane,
					    struct drm_atomic_state *state)
{
	struct drm_plane_state *old_state = drm_atomic_get_old_plane_state(state,
									   plane);
	struct drm_device *dev = plane->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = NULL;
	struct virtio_gpu_object *bo;
	struct drm_rect rect;
	struct virtio_gpu_cmd cmd_set[3];
	int i, cnt = 0;

	if (plane->state->crtc)
		output = drm_crtc_to_virtio_gpu_output(plane->state->crtc);
	if (old_state->crtc)
		output = drm_crtc_to_virtio_gpu_output(old_state->crtc);
	if (WARN_ON(!output))
		return;

	if (!plane->state->fb || !output->crtc.state->active) {
		DRM_DEBUG("nofb\n");
		virtio_gpu_cmd_set_scanout(vgdev, output->index, 0,
					   plane->state->src_w >> 16,
					   plane->state->src_h >> 16,
					   0, 0);
		virtio_gpu_notify(vgdev);
		return;
	}

	if (!drm_atomic_helper_damage_merged(old_state, plane->state, &rect))
		return;

	bo = gem_to_virtio_gpu_obj(plane->state->fb->obj[0]);
	if (bo->dumb)
		virtio_gpu_update_dumb_bo(vgdev, plane->state, &rect);

	if (plane->state->fb != old_state->fb ||
	    plane->state->src_w != old_state->src_w ||
	    plane->state->src_h != old_state->src_h ||
	    plane->state->src_x != old_state->src_x ||
	    plane->state->src_y != old_state->src_y ||
	    output->needs_modeset) {
		output->needs_modeset = false;
		DRM_DEBUG("handle 0x%x, crtc %dx%d+%d+%d, src %dx%d+%d+%d\n",
			  bo->hw_res_handle,
			  plane->state->crtc_w, plane->state->crtc_h,
			  plane->state->crtc_x, plane->state->crtc_y,
			  plane->state->src_w >> 16,
			  plane->state->src_h >> 16,
			  plane->state->src_x >> 16,
			  plane->state->src_y >> 16);

		if (bo->host3d_blob || bo->guest_blob) {
			if (vgdev->has_modifier)
				virtio_gpu_cmd_set_modifier(vgdev, output->index, bo, plane->state->fb);
			virtio_gpu_cmd_set_scanout_blob
						(vgdev, output->index, bo,
						 plane->state->fb,
						 plane->state->src_w >> 16,
						 plane->state->src_h >> 16,
						 plane->state->src_x >> 16,
						 plane->state->src_y >> 16);

		} else {
			virtio_gpu_cmd_set_scanout(vgdev, output->index,
						   bo->hw_res_handle,
						   plane->state->src_w >> 16,
						   plane->state->src_h >> 16,
						   plane->state->src_x >> 16,
						   plane->state->src_y >> 16);
		}
	}

	if(vgdev->has_scaling) {
		struct drm_rect rect_dst;

		rect_dst.x1 = plane->state->crtc_x;
		rect_dst.y1 = plane->state->crtc_y;
		rect_dst.x2 = plane->state->crtc_w;
		rect_dst.y2 = plane->state->crtc_h;

		virtio_gpu_cmd_set_scaling(vgdev, output->index, &rect_dst);
	}

	if ((vgdev->has_rotation) && plane->state->rotation) {
		cmd_set[cnt].cmd = VIRTIO_GPU_TUNNEL_CMD_SET_ROTATION;
		cmd_set[cnt].size = 2;
		cmd_set[cnt].data64[0]= plane->state->rotation;
		cnt++;
	}

	if ((vgdev->has_pixel_blend_mode) && (plane->state->fb->format->has_alpha)) {
		cmd_set[cnt].cmd = VIRTIO_GPU_TUNNEL_CMD_SET_BLEND ;
		cmd_set[cnt].size = 2;
		cmd_set[cnt].data32[0]= plane->state->pixel_blend_mode;
		cmd_set[cnt].data32[1]=(uint32_t)plane->state->alpha;
		cnt++;
	}
	if ((vgdev->has_multi_planar) && (plane->state->fb->format->num_planes > 1)) {
		struct virtio_gpu_framebuffer *vgfb;
		cmd_set[cnt].cmd = VIRTIO_GPU_TUNNEL_CMD_SET_PLANARS;
		cmd_set[cnt].size = plane->state->fb->format->num_planes-1;
		vgfb = to_virtio_gpu_framebuffer(plane->state->fb);
		for(i=1; i< plane->state->fb->format->num_planes; i++) {
			struct virtio_gpu_object *bo;
			bo = gem_to_virtio_gpu_obj(vgfb->base.obj[i]);
			cmd_set[cnt].data32[i-1] = bo->hw_res_handle;
		}
		cnt++;
	}
	if(cnt) {
		virtio_gpu_cmd_send_misc(vgdev, output->index, plane->index, cmd_set, cnt);
	}

	virtio_gpu_resource_flush(plane,
				  rect.x1,
				  rect.y1,
				  rect.x2 - rect.x1,
				  rect.y2 - rect.y1);
}

static void virtio_gpu_cursor_plane_update(struct drm_plane *plane,
					   struct drm_atomic_state *state)
{
	struct drm_plane_state *old_state = drm_atomic_get_old_plane_state(state,
									   plane);
	struct drm_device *dev = plane->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = NULL;
	struct virtio_gpu_framebuffer *vgfb;
	struct virtio_gpu_object *bo = NULL;
	uint32_t handle;

	if (plane->state->crtc)
		output = drm_crtc_to_virtio_gpu_output(plane->state->crtc);
	if (old_state->crtc)
		output = drm_crtc_to_virtio_gpu_output(old_state->crtc);
	if (WARN_ON(!output))
		return;

	if (plane->state->fb) {
		vgfb = to_virtio_gpu_framebuffer(plane->state->fb);
		bo = gem_to_virtio_gpu_obj(vgfb->base.obj[0]);
		handle = bo->hw_res_handle;
	} else {
		handle = 0;
	}

	if (bo && bo->dumb && (plane->state->fb != old_state->fb)) {
		/* new cursor -- update & wait */
		struct virtio_gpu_object_array *objs = NULL;
		struct virtio_gpu_fence *fence = NULL;

		fence = virtio_gpu_fence_alloc(vgdev, vgdev->fence_drv.context,
					       0);
		objs = virtio_gpu_array_alloc(1);
		if (!objs) {
			if (fence)
				kfree(fence);

			return;
		}

		virtio_gpu_array_add_obj(objs, vgfb->base.obj[0]);
		virtio_gpu_array_lock_resv(objs);
		virtio_gpu_cmd_transfer_to_host_2d
			(vgdev, 0,
			 plane->state->crtc_w,
			 plane->state->crtc_h,
			 0, 0, objs, fence);
		virtio_gpu_notify(vgdev);

		if (fence) {
			dma_fence_wait(&fence->f, true);
			dma_fence_put(&fence->f);
		}
	}

	if (plane->state->fb != old_state->fb) {
		DRM_DEBUG("update, handle %d, pos +%d+%d, hot %d,%d\n", handle,
			  plane->state->crtc_x,
			  plane->state->crtc_y,
			  plane->state->fb ? plane->state->fb->hot_x : 0,
			  plane->state->fb ? plane->state->fb->hot_y : 0);
		output->cursor.hdr.type =
			cpu_to_le32(VIRTIO_GPU_CMD_UPDATE_CURSOR);
		output->cursor.resource_id = cpu_to_le32(handle);
		if (plane->state->fb) {
			output->cursor.hot_x =
				cpu_to_le32(plane->state->fb->hot_x);
			output->cursor.hot_y =
				cpu_to_le32(plane->state->fb->hot_y);
		} else {
			output->cursor.hot_x = cpu_to_le32(0);
			output->cursor.hot_y = cpu_to_le32(0);
		}
	} else {
		DRM_DEBUG("move +%d+%d\n",
			  plane->state->crtc_x,
			  plane->state->crtc_y);
		output->cursor.hdr.type =
			cpu_to_le32(VIRTIO_GPU_CMD_MOVE_CURSOR);
	}
	output->cursor.pos.x = cpu_to_le32(plane->state->crtc_x);
	output->cursor.pos.y = cpu_to_le32(plane->state->crtc_y);
	virtio_gpu_cursor_ping(vgdev, output);
}

static const struct drm_plane_helper_funcs virtio_gpu_primary_helper_funcs = {
	.atomic_check		= virtio_gpu_plane_atomic_check,
	.atomic_update		= virtio_gpu_primary_plane_update,
};

static const struct drm_plane_helper_funcs virtio_gpu_cursor_helper_funcs = {
	.atomic_check		= virtio_gpu_plane_atomic_check,
	.atomic_update		= virtio_gpu_cursor_plane_update,
};

static const struct drm_plane_helper_funcs virtio_gpu_sprite_helper_funcs = {
	.atomic_check		= virtio_gpu_plane_atomic_check,
	.atomic_update		= virtio_gpu_sprite_plane_update,
};

static const uint64_t virtio_gpu_format_modifiers[] = {
	DRM_FORMAT_MOD_LINEAR,
	I915_FORMAT_MOD_X_TILED,
	I915_FORMAT_MOD_Y_TILED,
	I915_FORMAT_MOD_4_TILED,
	DRM_FORMAT_MOD_INVALID
};


static bool virtio_gpu_plane_format_mod_supported(struct drm_plane *_plane,
						  u32 format, u64 modifier)
{
	switch (modifier) {
	case DRM_FORMAT_MOD_LINEAR:
	case I915_FORMAT_MOD_X_TILED:
	case I915_FORMAT_MOD_Y_TILED:
	case I915_FORMAT_MOD_4_TILED:
		return true;
	default:
		return false;
        }
}

void virtio_update_planes_info(int index, int num, u32 *info)
{
	int plane_indx, format_indx;
	int size = 0;
	int pos = 0;

	for(plane_indx=0; plane_indx<num; plane_indx++) {

		size = info[pos];
		pos++;
		virtio_gpu_output_planes_formats[index].planes[plane_indx]
				.size = size;

		for(format_indx = 0; format_indx < size; format_indx++,pos++) {
			virtio_gpu_output_planes_formats[index].planes[plane_indx]
				.format_info[format_indx] = info[pos];
		}
	}
	virtio_gpu_output_planes_formats[index].sprite_plane_index = 0;
}

static void virtio_gpu_get_plane_rotation(struct virtio_gpu_device *vgdev, uint32_t plane_id,
						uint32_t scanout_indx)
{
	virtio_gpu_cmd_get_plane_rotation(vgdev, plane_id, scanout_indx);
	virtio_gpu_notify(vgdev);

	wait_event_timeout(vgdev->resp_wq,
                               vgdev->outputs[scanout_indx].rotation[plane_id], 5 * HZ);

}

struct drm_plane *virtio_gpu_plane_init(struct virtio_gpu_device *vgdev,
					enum drm_plane_type type,
					int index)
{
	struct drm_device *dev = vgdev->ddev;
	const struct drm_plane_helper_funcs *funcs;
	struct drm_plane *plane;
	const uint32_t *formats;
	int nformats;

	if (type == DRM_PLANE_TYPE_CURSOR) {
		formats = virtio_gpu_cursor_formats;
		nformats = ARRAY_SIZE(virtio_gpu_cursor_formats);
		funcs = &virtio_gpu_cursor_helper_funcs;

	} else if (type == DRM_PLANE_TYPE_OVERLAY) {
		formats = virtio_gpu_output_planes_formats[index].
			planes[virtio_gpu_output_planes_formats[index].sprite_plane_index].format_info;
		nformats = virtio_gpu_output_planes_formats[index].
			planes[virtio_gpu_output_planes_formats[index].sprite_plane_index].size;
		funcs = &virtio_gpu_sprite_helper_funcs;
		virtio_gpu_output_planes_formats[index].sprite_plane_index++;

	} else {
		formats = virtio_gpu_formats;
		nformats = ARRAY_SIZE(virtio_gpu_formats);
		if(vgdev->has_multi_planar) {
			virtio_gpu_formats[nformats] = DRM_FORMAT_NV12;
			nformats++;
		}
		funcs = &virtio_gpu_primary_helper_funcs;
	}

	if (vgdev->has_modifier) {
		const uint64_t *modifiers = virtio_gpu_format_modifiers;
		virtio_gpu_plane_funcs.format_mod_supported = virtio_gpu_plane_format_mod_supported;
		plane = drmm_universal_plane_alloc(dev, struct drm_plane, dev,
						   1 << index, &virtio_gpu_plane_funcs,
						   formats, nformats, modifiers, type, NULL);
	} else {
		plane = drmm_universal_plane_alloc(dev, struct drm_plane, dev,
						   1 << index, &virtio_gpu_plane_funcs,
						   formats, nformats, NULL, type, NULL);
	}

	if (vgdev->has_rotation) {
		vgdev->outputs[index].rotation[plane->index] = 0;
		virtio_gpu_get_plane_rotation(vgdev, plane->index, index);
		vgdev->outputs[index].rotation[plane->index] =
			DRM_MODE_ROTATE_0|vgdev->outputs[index].rotation[plane->index];

		drm_plane_create_rotation_property(plane,
						   DRM_MODE_ROTATE_0,
						   vgdev->outputs[index].rotation[plane->index]);
	}

	if(vgdev->has_pixel_blend_mode) {
		drm_plane_create_alpha_property(plane);
		drm_plane_create_blend_mode_property(plane,
                                              BIT(DRM_MODE_BLEND_PIXEL_NONE) |
                                              BIT(DRM_MODE_BLEND_PREMULTI) |
                                              BIT(DRM_MODE_BLEND_COVERAGE));
	}

	if (IS_ERR(plane))
		return plane;

	drm_plane_helper_add(plane, funcs);

	if (type == DRM_PLANE_TYPE_PRIMARY)
		drm_plane_enable_fb_damage_clips(plane);

	return plane;
}
