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

#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>

#include <drm/drm_file.h>
#include <drm/drm_managed.h>

#include "virtgpu_drv.h"

static void virtio_gpu_config_changed_work_func(struct work_struct *work)
{
	struct virtio_gpu_device *vgdev =
		container_of(work, struct virtio_gpu_device,
			     config_changed_work);
	u32 events_read, events_clear = 0;

	/* read the config space */
	virtio_cread_le(vgdev->vdev, struct virtio_gpu_config,
			events_read, &events_read);
	if (events_read & VIRTIO_GPU_EVENT_DISPLAY) {
		if (vgdev->num_scanouts) {
			if (vgdev->has_edid)
				virtio_gpu_cmd_get_edids(vgdev);
			virtio_gpu_cmd_get_display_info(vgdev);
			virtio_gpu_notify(vgdev);
			drm_helper_hpd_irq_event(vgdev->ddev);
		}
		events_clear |= VIRTIO_GPU_EVENT_DISPLAY;
	}
	virtio_cwrite_le(vgdev->vdev, struct virtio_gpu_config,
			 events_clear, &events_clear);
}

static void virtio_gpu_init_vq(struct virtio_gpu_queue *vgvq,
			       void (*work_func)(struct work_struct *work))
{
	spin_lock_init(&vgvq->qlock);
	init_waitqueue_head(&vgvq->ack_queue);
	INIT_WORK(&vgvq->dequeue_work, work_func);
}

static void virtio_gpu_get_capsets(struct virtio_gpu_device *vgdev,
				   int num_capsets)
{
	int i, ret;
	bool invalid_capset_id = false;
	struct drm_device *drm = vgdev->ddev;

	vgdev->capsets = drmm_kcalloc(drm, num_capsets,
				      sizeof(struct virtio_gpu_drv_capset),
				      GFP_KERNEL);
	if (!vgdev->capsets) {
		DRM_ERROR("failed to allocate cap sets\n");
		return;
	}
	for (i = 0; i < num_capsets; i++) {
		virtio_gpu_cmd_get_capset_info(vgdev, i);
		virtio_gpu_notify(vgdev);
		ret = wait_event_timeout(vgdev->resp_wq,
					 vgdev->capsets[i].id > 0, 5 * HZ);
		/*
		 * Capability ids are defined in the virtio-gpu spec and are
		 * between 1 to 63, inclusive.
		 */
		if (!vgdev->capsets[i].id ||
		    vgdev->capsets[i].id > MAX_CAPSET_ID)
			invalid_capset_id = true;

		if (ret == 0)
			DRM_ERROR("timed out waiting for cap set %d\n", i);
		else if (invalid_capset_id)
			DRM_ERROR("invalid capset id %u", vgdev->capsets[i].id);

		if (ret == 0 || invalid_capset_id) {
			spin_lock(&vgdev->display_info_lock);
			drmm_kfree(drm, vgdev->capsets);
			vgdev->capsets = NULL;
			spin_unlock(&vgdev->display_info_lock);
			return;
		}

		vgdev->capset_id_mask |= 1 << vgdev->capsets[i].id;
		DRM_INFO("cap set %d: id %d, max-version %d, max-size %d\n",
			 i, vgdev->capsets[i].id,
			 vgdev->capsets[i].max_version,
			 vgdev->capsets[i].max_size);
	}

	vgdev->num_capsets = num_capsets;
}

static void virtio_gpu_get_planes(struct virtio_gpu_device *vgdev)
{
	int i;
	for(i=0; i < vgdev->num_scanouts; i++) {
		vgdev->outputs[i].plane_num = 0;
		virtio_gpu_cmd_get_planes_info(vgdev, i);
		virtio_gpu_notify(vgdev);
		wait_event_timeout(vgdev->resp_wq,
				vgdev->outputs[i].plane_num, 5 * HZ);
	}
}

int virtio_gpu_find_vqs(struct virtio_gpu_device *vgdev)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	int i, total_vqs, err;
	const char **names;
	int ret = 0;

	total_vqs = vgdev->num_vblankq + 2;
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	callbacks = kmalloc_array(total_vqs, sizeof(vq_callback_t *),
				  GFP_KERNEL);
	names = kmalloc_array(total_vqs, sizeof(char *), GFP_KERNEL);

	if (!callbacks || !vqs || !names) {
		err = -ENOMEM;
		goto out;
	}

	callbacks[0] = virtio_gpu_ctrl_ack;
	callbacks[1] = virtio_gpu_cursor_ack;
	names[0] = "control";
	names[1] = "cursor";
	for (i = 2; i < total_vqs; i++) {
		callbacks[i] = virtio_gpu_vblank_ack;
		names[i] = "vblank";
	}

	ret = virtio_find_vqs(vgdev->vdev, total_vqs, vqs, callbacks, names, NULL);
	if (ret)
		goto out;

	vgdev->ctrlq.vq = vqs[0];
	vgdev->cursorq.vq = vqs[1];

	for (i = 2; i < total_vqs; i++)
		vgdev->vblank[i-2].vblank.vq = vqs[i];

	ret = 0;
out:
	kfree(names);

	kfree(callbacks);
	kfree(vqs);
	return ret;
}

int virtio_gpu_init(struct virtio_device *vdev, struct drm_device *dev)
{
	struct virtio_gpu_device *vgdev;
	u32 num_scanouts, num_capsets;
	int ret = 0;
	int i;

	if (!virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		return -ENODEV;

	vgdev = drmm_kzalloc(dev, sizeof(struct virtio_gpu_device), GFP_KERNEL);
	if (!vgdev)
		return -ENOMEM;

	vgdev->ddev = dev;
	dev->dev_private = vgdev;
	vgdev->vdev = vdev;

	spin_lock_init(&vgdev->display_info_lock);
	spin_lock_init(&vgdev->resource_export_lock);
	spin_lock_init(&vgdev->host_visible_lock);
	ida_init(&vgdev->ctx_id_ida);
	ida_init(&vgdev->resource_ida);
	init_waitqueue_head(&vgdev->resp_wq);
	virtio_gpu_init_vq(&vgdev->ctrlq, virtio_gpu_dequeue_ctrl_func);
	virtio_gpu_init_vq(&vgdev->cursorq, virtio_gpu_dequeue_cursor_func);

	vgdev->fence_drv.context = dma_fence_context_alloc(1);
	spin_lock_init(&vgdev->fence_drv.lock);
	INIT_LIST_HEAD(&vgdev->fence_drv.fences);
	INIT_LIST_HEAD(&vgdev->obj_rec);
	INIT_LIST_HEAD(&vgdev->cap_cache);
	INIT_WORK(&vgdev->config_changed_work,
		  virtio_gpu_config_changed_work_func);

	INIT_WORK(&vgdev->obj_free_work,
		  virtio_gpu_array_put_free_work);
	INIT_LIST_HEAD(&vgdev->obj_free_list);
	spin_lock_init(&vgdev->obj_free_lock);

#ifdef __LITTLE_ENDIAN
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_VIRGL))
		vgdev->has_virgl_3d = true;
#endif
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_EDID)) {
		vgdev->has_edid = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_RING_F_INDIRECT_DESC)) {
		vgdev->has_indirect = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_RESOURCE_UUID)) {
		vgdev->has_resource_assign_uuid = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_SCALING)) {
		vgdev->has_scaling = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_VBLANK)) {
		vgdev->has_vblank = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_ALLOW_P2P)) {
		vgdev->has_allow_p2p = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_MULTI_PLANE)) {
		vgdev->has_multi_plane = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_ROTATION)) {
		vgdev->has_rotation = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_PIXEL_BLEND_MODE)) {
		vgdev->has_pixel_blend_mode = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_MULTI_PLANAR_FORMAT)) {
		vgdev->has_multi_planar = true;
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_RESOURCE_BLOB)) {
		vgdev->has_resource_blob = true;
		if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_MODIFIER)) {
			vgdev->has_modifier = true;
		}
	}
	if (virtio_get_shm_region(vgdev->vdev, &vgdev->host_visible_region,
				  VIRTIO_GPU_SHM_ID_HOST_VISIBLE)) {
		if (!devm_request_mem_region(&vgdev->vdev->dev,
					     vgdev->host_visible_region.addr,
					     vgdev->host_visible_region.len,
					     dev_name(&vgdev->vdev->dev))) {
			DRM_ERROR("Could not reserve host visible region\n");
			ret = -EBUSY;
			goto err_vqs;
		}

		DRM_INFO("Host memory window: 0x%lx +0x%lx\n",
			 (unsigned long)vgdev->host_visible_region.addr,
			 (unsigned long)vgdev->host_visible_region.len);
		vgdev->has_host_visible = true;
		drm_mm_init(&vgdev->host_visible_mm,
			    (unsigned long)vgdev->host_visible_region.addr,
			    (unsigned long)vgdev->host_visible_region.len);
	}
	if (virtio_has_feature(vgdev->vdev, VIRTIO_GPU_F_CONTEXT_INIT)) {
		vgdev->has_context_init = true;
	}

	DRM_INFO("features: %cvirgl %cedid %cresource_blob %chost_visible",
		 vgdev->has_virgl_3d    ? '+' : '-',
		 vgdev->has_edid        ? '+' : '-',
		 vgdev->has_resource_blob ? '+' : '-',
		 vgdev->has_host_visible ? '+' : '-');

	DRM_INFO("features: %cscaling %cvblank %cmodifier %cmulti_plane",
		 vgdev->has_scaling ? '+' : '-',
		 vgdev->has_vblank ? '+' : '-',
		 vgdev->has_modifier ? '+' : '-',
		 vgdev->has_multi_plane ? '+' : '-');

	DRM_INFO("features: %ccontext_init\n",
		 vgdev->has_context_init ? '+' : '-');

	/* get display info */
	virtio_cread_le(vgdev->vdev, struct virtio_gpu_config,
			num_scanouts, &num_scanouts);
	vgdev->num_scanouts = min_t(uint32_t, num_scanouts,
				    VIRTIO_GPU_MAX_SCANOUTS);

	if (!IS_ENABLED(CONFIG_DRM_VIRTIO_GPU_KMS) || !vgdev->num_scanouts) {
		DRM_INFO("KMS disabled\n");
		vgdev->num_scanouts = 0;
		vgdev->has_edid = false;
		dev->driver_features &= ~(DRIVER_MODESET | DRIVER_ATOMIC);
	} else {
		DRM_INFO("number of scanouts: %d\n", num_scanouts);
	}

	virtio_cread_le(vgdev->vdev, struct virtio_gpu_config,
			num_capsets, &num_capsets);
	DRM_INFO("number of cap sets: %d\n", num_capsets);

	vgdev->num_vblankq = 0;
	if(vgdev->has_vblank)
		virtio_cread_le(vgdev->vdev, struct virtio_gpu_config,
                               num_pipe, &vgdev->num_vblankq);
	if (vgdev->num_vblankq > vgdev->num_scanouts) {
		DRM_WARN("virtio gpu has wrong vblank number\n");
		vgdev->num_vblankq = vgdev->num_scanouts;
	}

	for(i=0; i<vgdev->num_vblankq; i++)
		spin_lock_init(&vgdev->vblank[i].vblank.qlock);

	ret = virtio_gpu_find_vqs(vgdev);
	if (ret) {
		DRM_ERROR("failed to find virt queues\n");
		goto err_vqs;
	}
	ret = virtio_gpu_alloc_vbufs(vgdev);
	if (ret) {
		DRM_ERROR("failed to alloc vbufs\n");
		goto err_vbufs;
	}

	virtio_device_ready(vgdev->vdev);

	if (num_capsets)
		virtio_gpu_get_capsets(vgdev, num_capsets);

	if(vgdev->has_multi_plane)
		virtio_gpu_get_planes(vgdev);

	ret = virtio_gpu_modeset_init(vgdev);
	if (ret) {
		DRM_ERROR("modeset init failed\n");
		goto err_scanouts;
	}

	virtio_gpu_vblankq_notify(vgdev);

	for(i=0; i < vgdev->num_vblankq; i++)
		virtqueue_disable_cb(vgdev->vblank[i].vblank.vq);


	if (vgdev->num_scanouts) {
		if (vgdev->has_edid)
			virtio_gpu_cmd_get_edids(vgdev);
		virtio_gpu_cmd_get_display_info(vgdev);
		virtio_gpu_notify(vgdev);
		wait_event_timeout(vgdev->resp_wq, !vgdev->display_info_pending,
				   5 * HZ);
	}
	return 0;

err_scanouts:
	virtio_gpu_free_vbufs(vgdev);
err_vbufs:
	vgdev->vdev->config->del_vqs(vgdev->vdev);
err_vqs:
	dev->dev_private = NULL;
	return ret;
}

static void virtio_gpu_cleanup_cap_cache(struct virtio_gpu_device *vgdev)
{
	struct virtio_gpu_drv_cap_cache *cache_ent, *tmp;

	list_for_each_entry_safe(cache_ent, tmp, &vgdev->cap_cache, head) {
		kfree(cache_ent->caps_cache);
		kfree(cache_ent);
	}
}

void virtio_gpu_deinit(struct drm_device *dev)
{
	struct virtio_gpu_device *vgdev = dev->dev_private;

	flush_work(&vgdev->obj_free_work);
	flush_work(&vgdev->ctrlq.dequeue_work);
	flush_work(&vgdev->cursorq.dequeue_work);
	flush_work(&vgdev->config_changed_work);
	virtio_reset_device(vgdev->vdev);
	vgdev->vdev->config->del_vqs(vgdev->vdev);
}

void virtio_gpu_release(struct drm_device *dev)
{
	struct virtio_gpu_device *vgdev = dev->dev_private;

	if (!vgdev)
		return;

	virtio_gpu_modeset_fini(vgdev);
	virtio_gpu_free_vbufs(vgdev);
	virtio_gpu_cleanup_cap_cache(vgdev);

	if (vgdev->has_host_visible)
		drm_mm_takedown(&vgdev->host_visible_mm);
}

int virtio_gpu_driver_open(struct drm_device *dev, struct drm_file *file)
{
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_fpriv *vfpriv;
	int handle;

	/* can't create contexts without 3d renderer */
	if (!vgdev->has_virgl_3d)
		return 0;

	/* allocate a virt GPU context for this opener */
	vfpriv = kzalloc(sizeof(*vfpriv), GFP_KERNEL);
	if (!vfpriv)
		return -ENOMEM;

	mutex_init(&vfpriv->context_lock);

	handle = ida_alloc(&vgdev->ctx_id_ida, GFP_KERNEL);
	if (handle < 0) {
		kfree(vfpriv);
		return handle;
	}

	vfpriv->ctx_id = handle + 1;
	file->driver_priv = vfpriv;
	return 0;
}

void virtio_gpu_driver_postclose(struct drm_device *dev, struct drm_file *file)
{
	struct virtio_gpu_device *vgdev = dev->dev_private;
	struct virtio_gpu_fpriv *vfpriv = file->driver_priv;

	if (!vgdev->has_virgl_3d)
		return;

	if (vfpriv->context_created) {
		virtio_gpu_cmd_context_destroy(vgdev, vfpriv->ctx_id);
		virtio_gpu_notify(vgdev);
	}

	ida_free(&vgdev->ctx_id_ida, vfpriv->ctx_id - 1);
	mutex_destroy(&vfpriv->context_lock);
	kfree(vfpriv);
	file->driver_priv = NULL;
}
