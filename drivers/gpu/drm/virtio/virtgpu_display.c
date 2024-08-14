/*
 * Copyright (C) 2015 Red Hat, Inc.
 * All Rights Reserved.
 *
 * Authors:
 *    Dave Airlie
 *    Alon Levy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <drm/drm_atomic_helper.h>
#include <drm/drm_damage_helper.h>
#include <drm/drm_edid.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_simple_kms_helper.h>
#include <drm/drm_vblank.h>

#include "virtgpu_drv.h"

#define XRES_MIN    32
#define YRES_MIN    32

#define XRES_DEF  1024
#define YRES_DEF   768

#define XRES_MAX  8192
#define YRES_MAX  8192

#define drm_connector_to_virtio_gpu_output(x) \
	container_of(x, struct virtio_gpu_output, conn)

static int virtio_irq_enable_vblank(struct drm_crtc *crtc)
{

	struct drm_device *dev = crtc->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = drm_crtc_to_virtio_gpu_output(crtc);

	virtio_gpu_vblank_poll_arm(vgdev->vblank[output->index].vblank.vq);
	virtqueue_enable_cb(vgdev->vblank[output->index].vblank.vq);
	return 0;
}

static void virtio_irq_disable_vblank(struct drm_crtc *crtc)
{
	struct drm_device *dev = crtc->dev;
	struct virtio_gpu_device *vgdev;
	vgdev = dev->dev_private;
	struct virtio_gpu_output *output = drm_crtc_to_virtio_gpu_output(crtc);

	virtqueue_disable_cb(vgdev->vblank[output->index].vblank.vq);
}

static const struct drm_crtc_funcs virtio_gpu_crtc_funcs = {
	.set_config             = drm_atomic_helper_set_config,
	.destroy                = drm_crtc_cleanup,

	.page_flip              = drm_atomic_helper_page_flip,
	.reset                  = drm_atomic_helper_crtc_reset,
	.atomic_duplicate_state = drm_atomic_helper_crtc_duplicate_state,
	.atomic_destroy_state   = drm_atomic_helper_crtc_destroy_state,
	.enable_vblank = virtio_irq_enable_vblank,
	.disable_vblank = virtio_irq_disable_vblank,
};

static const struct drm_framebuffer_funcs virtio_gpu_fb_funcs = {
	.create_handle = drm_gem_fb_create_handle,
	.destroy = drm_gem_fb_destroy,
	.dirty = drm_atomic_helper_dirtyfb,
};

static void virtio_gpu_crtc_mode_set_nofb(struct drm_crtc *crtc)
{
	struct drm_device *dev = crtc->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = drm_crtc_to_virtio_gpu_output(crtc);

	virtio_gpu_cmd_set_scanout(vgdev, output->index, 0,
				   crtc->mode.hdisplay,
				   crtc->mode.vdisplay, 0, 0);
	virtio_gpu_notify(vgdev);
}

static void virtio_gpu_crtc_atomic_enable(struct drm_crtc *crtc,
					  struct drm_atomic_state *state)
{
	struct drm_device *dev = crtc->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	if(vgdev->has_vblank) {
		drm_crtc_vblank_on(crtc);
	}
}

static void virtio_gpu_crtc_atomic_disable(struct drm_crtc *crtc,
					   struct drm_atomic_state *state)
{
	struct drm_device *dev = crtc->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = drm_crtc_to_virtio_gpu_output(crtc);

	if(vgdev->has_vblank) {
		drm_crtc_vblank_off(crtc);
	}
	virtio_gpu_cmd_set_scanout(vgdev, output->index, 0, 0, 0, 0, 0);
	virtio_gpu_notify(vgdev);
}

static int virtio_gpu_crtc_atomic_check(struct drm_crtc *crtc,
					struct drm_atomic_state *state)
{
	struct virtio_gpu_output *output = NULL;
	struct drm_device *dev = crtc->dev;
	int num_scalers_need;
	struct virtio_gpu_device *vgdev = dev->dev_private;

	output = drm_crtc_to_virtio_gpu_output(crtc);
	if(vgdev->has_scaling) {
		num_scalers_need = hweight32(output->scaler_users);
		if(num_scalers_need > SKL_NUM_SCALERS) {
			drm_dbg_kms(dev, "Too many scaling requests %d > %d\n", num_scalers_need, SKL_NUM_SCALERS);
			output->scaler_users = 0;
			return -EINVAL;
		}
	}
	return 0;
}

static void virtio_gpu_resource_flush_sync(struct drm_crtc *crtc)
{
	struct drm_device *dev = crtc->dev;
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_output *output = drm_crtc_to_virtio_gpu_output(crtc);
	virtio_gpu_cmd_flush_sync(vgdev, output->index);
	virtio_gpu_notify(vgdev);
}

static void virtio_gpu_crtc_atomic_flush(struct drm_crtc *crtc,
					 struct drm_atomic_state *state)
{
	struct drm_crtc_state *crtc_state = drm_atomic_get_new_crtc_state(state,
									  crtc);
	struct virtio_gpu_output *output = drm_crtc_to_virtio_gpu_output(crtc);
	struct drm_device *drm = crtc->dev;
	struct virtio_gpu_device *vgdev = drm->dev_private;

	if(vgdev->has_vblank) {
		if (crtc->state->event) {
			spin_lock_irq(&drm->event_lock);
			if (drm_crtc_vblank_get(crtc) != 0)
				drm_crtc_send_vblank_event(crtc, crtc->state->event);
			else
				drm_crtc_arm_vblank_event(crtc, crtc->state->event);
			spin_unlock_irq(&drm->event_lock);
			crtc->state->event = NULL;
		}
	}
	if(vgdev->has_multi_plane)
		virtio_gpu_resource_flush_sync(crtc);

	if(vgdev->has_scaling)
		output->scaler_users = 0;

	/*
	 * virtio-gpu can't do modeset and plane update operations
	 * independent from each other.  So the actual modeset happens
	 * in the plane update callback, and here we just check
	 * whenever we must force the modeset.
	 */
	if (drm_atomic_crtc_needs_modeset(crtc_state)) {
		output->needs_modeset = true;
	}
}

static const struct drm_crtc_helper_funcs virtio_gpu_crtc_helper_funcs = {
	.mode_set_nofb = virtio_gpu_crtc_mode_set_nofb,
	.atomic_check  = virtio_gpu_crtc_atomic_check,
	.atomic_flush  = virtio_gpu_crtc_atomic_flush,
	.atomic_enable = virtio_gpu_crtc_atomic_enable,
	.atomic_disable = virtio_gpu_crtc_atomic_disable,
};

static void virtio_gpu_enc_mode_set(struct drm_encoder *encoder,
				    struct drm_display_mode *mode,
				    struct drm_display_mode *adjusted_mode)
{
}

static void virtio_gpu_enc_enable(struct drm_encoder *encoder)
{
}

static void virtio_gpu_enc_disable(struct drm_encoder *encoder)
{
}

static int virtio_gpu_conn_get_modes(struct drm_connector *connector)
{
	struct virtio_gpu_output *output =
		drm_connector_to_virtio_gpu_output(connector);
	struct drm_display_mode *mode = NULL;
	int count, width, height;

	if (output->edid) {
		count = drm_add_edid_modes(connector, output->edid);
		if (count)
			return count;
	}

	width  = le32_to_cpu(output->info.r.width);
	height = le32_to_cpu(output->info.r.height);
	count = drm_add_modes_noedid(connector, XRES_MAX, YRES_MAX);

	if (width == 0 || height == 0) {
		drm_set_preferred_mode(connector, XRES_DEF, YRES_DEF);
	} else {
		DRM_DEBUG("add mode: %dx%d\n", width, height);
		mode = drm_cvt_mode(connector->dev, width, height, 60,
				    false, false, false);
		if (!mode)
			return count;
		mode->type |= DRM_MODE_TYPE_PREFERRED;
		drm_mode_probed_add(connector, mode);
		count++;
	}

	return count;
}

static enum drm_mode_status virtio_gpu_conn_mode_valid(struct drm_connector *connector,
				      struct drm_display_mode *mode)
{
	struct virtio_gpu_output *output =
		drm_connector_to_virtio_gpu_output(connector);
	int width, height;

	width  = le32_to_cpu(output->info.r.width);
	height = le32_to_cpu(output->info.r.height);

	if (!(mode->type & DRM_MODE_TYPE_PREFERRED))
		return MODE_OK;
	if (mode->hdisplay == XRES_DEF && mode->vdisplay == YRES_DEF)
		return MODE_OK;
	if (mode->hdisplay <= width  && mode->hdisplay >= width - 16 &&
	    mode->vdisplay <= height && mode->vdisplay >= height - 16)
		return MODE_OK;

	DRM_DEBUG("del mode: %dx%d\n", mode->hdisplay, mode->vdisplay);
	return MODE_BAD;
}

static const struct drm_encoder_helper_funcs virtio_gpu_enc_helper_funcs = {
	.mode_set   = virtio_gpu_enc_mode_set,
	.enable     = virtio_gpu_enc_enable,
	.disable    = virtio_gpu_enc_disable,
};

static const struct drm_connector_helper_funcs virtio_gpu_conn_helper_funcs = {
	.get_modes    = virtio_gpu_conn_get_modes,
	.mode_valid   = virtio_gpu_conn_mode_valid,
};

static enum drm_connector_status virtio_gpu_conn_detect(
			struct drm_connector *connector,
			bool force)
{
	struct virtio_gpu_output *output =
		drm_connector_to_virtio_gpu_output(connector);

	if (output->info.enabled)
		return connector_status_connected;
	else
		return connector_status_disconnected;
}

static void virtio_gpu_conn_destroy(struct drm_connector *connector)
{
	drm_connector_unregister(connector);
	drm_connector_cleanup(connector);
}

static const struct drm_connector_funcs virtio_gpu_connector_funcs = {
	.detect = virtio_gpu_conn_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = virtio_gpu_conn_destroy,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static int vgdev_output_init(struct virtio_gpu_device *vgdev, int index)
{
	struct drm_device *dev = vgdev->ddev;
	struct virtio_gpu_output *output = vgdev->outputs + index;
	struct drm_connector *connector = &output->conn;
	struct drm_encoder *encoder = &output->enc;
	struct drm_crtc *crtc = &output->crtc;
	struct drm_plane *primary, *cursor;

	output->index = index;
	if (index == 0) {
		output->info.enabled = cpu_to_le32(true);
		output->info.r.width = cpu_to_le32(XRES_DEF);
		output->info.r.height = cpu_to_le32(YRES_DEF);
	}

	if(vgdev->has_scaling)
		output->scaler_users = 0;
	primary = virtio_gpu_plane_init(vgdev, DRM_PLANE_TYPE_PRIMARY, index);
	if (IS_ERR(primary))
		return PTR_ERR(primary);
	cursor = virtio_gpu_plane_init(vgdev, DRM_PLANE_TYPE_CURSOR, index);
	if (IS_ERR(cursor))
		return PTR_ERR(cursor);

	if(vgdev->has_multi_plane) {
		struct drm_plane *sprite;
		int i;
		for(i=0; i< vgdev->outputs[index].plane_num; i++) {
			sprite = virtio_gpu_plane_init(vgdev, DRM_PLANE_TYPE_OVERLAY, index);
			if (IS_ERR(sprite))
				return PTR_ERR(sprite);
		}
	}

	drm_crtc_init_with_planes(dev, crtc, primary, cursor,
				  &virtio_gpu_crtc_funcs, NULL);
	drm_crtc_helper_add(crtc, &virtio_gpu_crtc_helper_funcs);

	drm_connector_init(dev, connector, &virtio_gpu_connector_funcs,
			   DRM_MODE_CONNECTOR_VIRTUAL);
	drm_connector_helper_add(connector, &virtio_gpu_conn_helper_funcs);
	if (vgdev->has_edid)
		drm_connector_attach_edid_property(connector);

	drm_simple_encoder_init(dev, encoder, DRM_MODE_ENCODER_VIRTUAL);
	drm_encoder_helper_add(encoder, &virtio_gpu_enc_helper_funcs);
	encoder->possible_crtcs = 1 << index;

	drm_connector_attach_encoder(connector, encoder);
	drm_connector_register(connector);
	return 0;
}

static struct drm_framebuffer *
virtio_gpu_user_framebuffer_create(struct drm_device *dev,
				   struct drm_file *file_priv,
				   const struct drm_mode_fb_cmd2 *mode_cmd)
{
	struct drm_gem_object *obj = NULL;
	struct virtio_gpu_framebuffer *virtio_gpu_fb;

	const struct drm_format_info *info;
	struct drm_gem_object *objs[DRM_FORMAT_MAX_PLANES];

	unsigned int i;
	int ret;

	info = drm_get_format_info(dev, mode_cmd);
	if (!info) {
		drm_dbg_kms(dev, "Failed to get FB format info\n");
		return ERR_PTR(-EINVAL);
	}

	virtio_gpu_fb = kzalloc(sizeof(*virtio_gpu_fb), GFP_KERNEL);
	if (virtio_gpu_fb == NULL) {
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < info->num_planes; i++) {
		objs[i] = drm_gem_object_lookup(file_priv, mode_cmd->handles[i]);
		if (!objs[i]) {
			drm_dbg_kms(dev, "Failed to lookup GEM object\n");
			goto error;
		}
		virtio_gpu_fb->base.obj[i] = objs[i];
	}

	drm_helper_mode_fill_fb_struct(dev, &virtio_gpu_fb->base, mode_cmd);
	ret = drm_framebuffer_init(dev, &virtio_gpu_fb->base, &virtio_gpu_fb_funcs);
	if (ret)
		goto error;

	return &virtio_gpu_fb->base;
error:
	kfree(virtio_gpu_fb);
	while (i > 0) {
		--i;
		drm_gem_object_put(objs[i]);
	}
	return ERR_PTR(ret);
}

static const struct drm_mode_config_funcs virtio_gpu_mode_funcs = {
	.fb_create = virtio_gpu_user_framebuffer_create,
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
};

int virtio_gpu_modeset_init(struct virtio_gpu_device *vgdev)
{
	int i, ret;

	if (!vgdev->num_scanouts)
		return 0;

	ret = drmm_mode_config_init(vgdev->ddev);
	if (ret)
		return ret;

	vgdev->ddev->mode_config.funcs = &virtio_gpu_mode_funcs;

	/* modes will be validated against the framebuffer size */
	vgdev->ddev->mode_config.min_width = XRES_MIN;
	vgdev->ddev->mode_config.min_height = YRES_MIN;
	vgdev->ddev->mode_config.max_width = XRES_MAX;
	vgdev->ddev->mode_config.max_height = YRES_MAX;

	if (!vgdev->has_modifier)
		vgdev->ddev->mode_config.fb_modifiers_not_supported = true;

	for (i = 0 ; i < vgdev->num_scanouts; ++i)
		vgdev_output_init(vgdev, i);

	drm_mode_config_reset(vgdev->ddev);
	return 0;
}

void virtio_gpu_modeset_fini(struct virtio_gpu_device *vgdev)
{
	int i;

	if (!vgdev->num_scanouts)
		return;

	for (i = 0 ; i < vgdev->num_scanouts; ++i)
		kfree(vgdev->outputs[i].edid);
}
