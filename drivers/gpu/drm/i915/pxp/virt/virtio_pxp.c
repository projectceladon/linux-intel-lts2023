/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2024, Intel Corporation. All rights reserved.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include "virtpxp_drv.h"

static DEFINE_SPINLOCK(pxp_lock);
static LIST_HEAD(pxp_devices);
static LIST_HEAD(gpu_devices);
struct gpu_device {
	int card;
	int vfid;
	struct list_head node;
	void *priv;
	struct virtio_pxp *vpxp;
	int (*bind)(void *gpu_priv, void *pxp_priv);
	void (*unbind)(void *gpu_priv);
};

static void virtpxp_queue_evtbuf(struct virtio_pxp *vpxp)
{
	struct scatterlist sg[1];

	sg_init_one(sg, &vpxp->evtbuf, sizeof(vpxp->evtbuf));
	virtqueue_add_inbuf(vpxp->event_vq, sg, 1, &vpxp->evtbuf, GFP_ATOMIC);
}

static void virtpxp_recv_events(struct virtqueue *vq)
{
	struct virtio_pxp *vpxp = vq->vdev->priv;
	unsigned int *event;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vpxp->event_lock, flags);
	while ((event = virtqueue_get_buf(vq, &len)) != NULL) {
		spin_unlock_irqrestore(&vpxp->event_lock, flags);
		spin_lock_irqsave(&pxp_lock, flags);
		if (vpxp->irq_recv)
			vpxp->irq_recv(*event, vpxp->cb_priv);
		spin_unlock_irqrestore(&pxp_lock, flags);
		virtpxp_queue_evtbuf(vpxp);
		spin_lock_irqsave(&vpxp->event_lock, flags);
	}
	virtqueue_kick(vq);
	spin_unlock_irqrestore(&vpxp->event_lock, flags);
}

static void virtpxp_control(struct virtqueue *vq)
{
	struct virtio_pxp *vpxp = vq->vdev->priv;
	struct virtio_pxp_base_request *request;
	unsigned long flags;
	unsigned int len;

	spin_lock_irqsave(&vpxp->control_lock, flags);
	while ((request = virtqueue_get_buf(vq, &len)) != NULL) {
		spin_unlock_irqrestore(&vpxp->control_lock, flags);
		request->rxlen = len;
		complete(&request->completion);
		spin_lock_irqsave(&vpxp->control_lock, flags);
	}
	spin_unlock_irqrestore(&vpxp->control_lock, flags);
}

static int virtpxp_init_vqs(struct virtio_pxp *vpxp)
{
	struct virtqueue *vqs[2];
	vq_callback_t *cbs[] = { virtpxp_control,
		virtpxp_recv_events };
	static const char * const names[] = { "control", "event" };
	int err;

	err = virtio_find_vqs(vpxp->vdev, 2, vqs, cbs, names, NULL);
	if (err)
		return err;
	vpxp->control_vq = vqs[0];
	vpxp->event_vq = vqs[1];

	return 0;
}

static void vpxp_free(struct kref *kref)
{
	struct virtio_pxp *vpxp;
	vpxp  = container_of(kref, typeof(*vpxp), ref);
	kfree(vpxp);
	vpxp = NULL;
}

void put_virtio_pxp(struct virtio_pxp *vpxp)
{
	if (vpxp) {
		kref_put(&vpxp->ref, vpxp_free);
	}
}

int virtpxp_register_intel_gpu_device(int device_idx, int device_vfid, void *gpu_priv,
			int (*bind)(void *gpu_priv, void *pxp_priv), void (*unbind)(void *gpu_priv))
{
	struct gpu_device *gdev = NULL;
	struct virtio_pxp *device = NULL;
	struct virtio_pxp *found_device = NULL;
	unsigned long flags;
	gdev = kzalloc(sizeof(*gdev), GFP_KERNEL);
	if (!gdev) {
		return -ENOMEM;
	}
	gdev->card = device_idx;
	gdev->vfid = device_vfid;
	gdev->priv = gpu_priv;
	gdev->bind = bind;
	gdev->unbind = unbind;
	spin_lock_irqsave(&pxp_lock, flags);
	list_add_tail(&gdev->node, &gpu_devices);
	list_for_each_entry(device, &pxp_devices, node) {
		if (device && !gdev->vpxp
				&& device->device_idx == device_idx
				&& device->device_vfid == device_vfid) {
			found_device = device;
			break;
		}
	}
	if (found_device) {
		kref_get(&device->ref);
		gdev->bind(gdev->priv, found_device);
		gdev->vpxp = found_device;
	}
	spin_unlock_irqrestore(&pxp_lock, flags);
	return 0;
}

void virtpxp_unregister_intel_gpu_device(int device_idx, int device_vfid, void *gpu_priv)
{
	unsigned long flags;
	struct gpu_device *device = NULL;
	struct gpu_device *gdev = NULL;
	spin_lock_irqsave(&pxp_lock, flags);
	list_for_each_entry(device, &gpu_devices, node) {
		if (device && device->card == device_idx && device->vfid == device_vfid &&
						device->priv == gpu_priv) {
			gdev = device;
		}
	}
	if (gdev) {
		list_del(&gdev->node);
		if (gdev->vpxp) {
			gdev->unbind(gdev->priv);
			gdev->vpxp->irq_recv = NULL;
			put_virtio_pxp(gdev->vpxp);
		}
	}
	spin_unlock_irqrestore(&pxp_lock, flags);
}

int virtio_set_session(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_set_session_status_params *params)
{
	struct virtio_pxp_set_session_request *request;
	struct scatterlist *sgs[2], req_sg, res_sg;
	int ret = 0;
	if (!vpxp)
		return -1;
	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request) {
		printk("%s, alloc mem failure\n", __FUNCTION__);
		return -ENOMEM;
	}
	init_completion(&request->base.completion);
	request->req.action = cpu_to_le32(PRELIM_DRM_I915_PXP_ACTION_SET_SESSION_STATUS);
	request->req.pxp_tag = cpu_to_le32(params->pxp_tag);
	request->req.session_type = cpu_to_le32(params->session_type);
	request->req.session_mode = cpu_to_le32(params->session_mode);
	request->req.req_session_state = cpu_to_le32(params->req_session_state);
	sg_init_one(&req_sg, &request->req, sizeof(request->req));
	sg_init_one(&res_sg, &request->resp, sizeof(request->resp));
	sgs[0] = &req_sg;
	sgs[1] = &res_sg;
	mutex_lock(&vpxp->dev_mutex);
	if (!vpxp->ready) {
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_add_sgs(vpxp->control_vq, sgs, 1, 1, &request->base, GFP_KERNEL);
	if (ret) {
		printk("%s, failed to add request to vq:%d\n", __FUNCTION__, ret);
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_kick(vpxp->control_vq);
	mutex_unlock(&vpxp->dev_mutex);
	ret = wait_for_completion_interruptible_timeout(&request->base.completion, msecs_to_jiffies(2000));
	if (ret < 0) {
		printk("failed to set session status:%d, ret:%d\n", request->resp.status, ret);
		kfree(request);
		return -ETIME;
	}
	params->pxp_tag = request->resp.pxp_tag;
	ret = request->resp.status;
	kfree(request);
	return ret;
}

int virtio_io_msg(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_tee_io_message_params *params)
{
	struct virtio_pxp_io_message_request *request;
	struct scatterlist *sgs[4], req_sg, req_data_sg, res_data_sg, res_sg;
	int ret = 0;
	if (!vpxp)
		return -1;
	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request) {
		printk("%s, alloc mem failure\n", __FUNCTION__);
		return -ENOMEM;
	}
	init_completion(&request->base.completion);
	request->req.action = cpu_to_le32(PRELIM_DRM_I915_PXP_ACTION_TEE_IO_MESSAGE);
	request->req.msg_in_size = cpu_to_le32(params->msg_in_size);
	request->req.msg_out_buf_size = cpu_to_le32(params->msg_out_buf_size);
	sg_init_one(&req_sg, &request->req, sizeof(request->req));
	sg_init_one(&req_data_sg, (char *)params->msg_in, params->msg_in_size);
	sg_init_one(&res_data_sg, (char *)params->msg_out, params->msg_out_buf_size);
	sg_init_one(&res_sg, &request->resp, sizeof(request->resp));
	sgs[0] = &req_sg;
	sgs[1] = &req_data_sg;
	sgs[2] = &res_data_sg;
	sgs[3] = &res_sg;
	mutex_lock(&vpxp->dev_mutex);
	if (!vpxp->ready) {
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_add_sgs(vpxp->control_vq, sgs, 2, 2, &request->base, GFP_KERNEL);
	if (ret) {
		printk("%s, failed to add request to vq:%d\n", __FUNCTION__, ret);
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_kick(vpxp->control_vq);
	mutex_unlock(&vpxp->dev_mutex);
	ret = wait_for_completion_interruptible_timeout(&request->base.completion, msecs_to_jiffies(2000));
	if (ret < 0) {
		printk("failed to io message status:%d, ret:%d\n", request->resp.status, ret);
		kfree(request);
		return -ETIME;
	}
	params->msg_out_ret_size = request->resp.msg_out_ret_size;
	ret = request->resp.status;
	kfree(request);
	return ret;
}

int virtio_query_tag(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_query_tag *params)
{
	struct virtio_pxp_query_tag_request *request ;
	struct scatterlist *sgs[2], req_sg, res_sg;
	int ret = 0;
	if (!vpxp)
		return -1;
	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request) {
		printk("%s, alloc mem failure\n", __FUNCTION__);
		return -ENOMEM;
	}
	init_completion(&request->base.completion);
	request->req.action = cpu_to_le32(PRELIM_DRM_I915_PXP_ACTION_QUERY_PXP_TAG);
	request->req.session_is_alive = cpu_to_le32(params->session_is_alive);
	request->req.pxp_tag = cpu_to_le32(params->pxp_tag);
	sg_init_one(&req_sg, &request->req, sizeof(request->req));
	sg_init_one(&res_sg, &request->resp, sizeof(request->resp));
	sgs[0] = &req_sg;
	sgs[1] = &res_sg;
	mutex_lock(&vpxp->dev_mutex);
	if (!vpxp->ready) {
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_add_sgs(vpxp->control_vq, sgs, 1, 1, &request->base, GFP_KERNEL);
	if (ret) {
		printk("%s, failed to add request to vq:%d\n", __FUNCTION__, ret);
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_kick(vpxp->control_vq);
	mutex_unlock(&vpxp->dev_mutex);
	ret = wait_for_completion_interruptible_timeout(&request->base.completion, msecs_to_jiffies(2000));
	if (ret < 0) {
		printk("failed to query tag status:%d, ret:%d\n", request->resp.status, ret);
		kfree(request);
		return -ETIME;
	}
	params->pxp_tag = request->resp.pxp_tag;
	params->session_is_alive = request->resp.session_is_alive;
	ret = request->resp.status;
	kfree(request);
	return ret;
}

int virtio_host_session_handle_request(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_host_session_handle_request *params)
{
	struct virtio_pxp_host_session_handle_request_request *request;
	struct scatterlist *sgs[2], req_sg, res_sg;
	int ret = 0;
	if (!vpxp)
		return -1;
	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request) {
		printk("%s, alloc mem failure\n", __FUNCTION__);
		return -ENOMEM;
	}
	init_completion(&request->base.completion);
	request->req.action = cpu_to_le32(PRELIM_DRM_I915_PXP_ACTION_HOST_SESSION_HANDLE_REQ);
	request->req.request_type = cpu_to_le32(params->request_type);
	request->req.host_session_handle = cpu_to_le64(params->host_session_handle);
	sg_init_one(&req_sg, &request->req, sizeof(request->req));
	sg_init_one(&res_sg, &request->resp, sizeof(request->resp));
	sgs[0] = &req_sg;
	sgs[1] = &res_sg;
	mutex_lock(&vpxp->dev_mutex);
	if (!vpxp->ready) {
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_add_sgs(vpxp->control_vq, sgs, 1, 1, &request->base, GFP_KERNEL);
	if (ret) {
		printk("%s, failed to add request to vq:%d\n", __FUNCTION__, ret);
		mutex_unlock(&vpxp->dev_mutex);
		kfree(request);
		return -1;
	}
	virtqueue_kick(vpxp->control_vq);
	mutex_unlock(&vpxp->dev_mutex);
	ret = wait_for_completion_interruptible_timeout(&request->base.completion, msecs_to_jiffies(2000));
	if (ret < 0) {
		printk("failed to host session handle status:%d, ret:%d\n", request->resp.status, ret);
		kfree(request);
		return -ETIME;
	}
	params->host_session_handle = request->resp.host_session_handle;
	ret = request->resp.status;
	kfree(request);
	return ret;
}

static int virtpxp_probe(struct virtio_device *vdev)
{
	struct virtio_pxp *vpxp;
	unsigned long flags;
	u32 device_idx = 0;
	u32 device_vfid = 0;
	u32 sessions = 0;
	int err;
	struct gpu_device *device = NULL;
	struct gpu_device *gdev = NULL;


	vpxp = kzalloc(sizeof(*vpxp), GFP_KERNEL);
	if (!vpxp)
		return -ENOMEM;

	vdev->priv = vpxp;
	vpxp->vdev = vdev;
	spin_lock_init(&vpxp->control_lock);
	spin_lock_init(&vpxp->event_lock);
	kref_init(&vpxp->ref);
	INIT_LIST_HEAD(&vpxp->node);
	mutex_init(&vpxp->dev_mutex);
	err = virtpxp_init_vqs(vpxp);
	if (err)
		goto err_init_vq;

	virtio_cread_le(vdev, struct virtio_pxp_config,
			device_idx, &device_idx);
	vpxp->device_idx = device_idx;
	virtio_cread_le(vdev, struct virtio_pxp_config,
			device_vfid, &device_vfid);
	vpxp->device_vfid = device_vfid;
	virtio_cread_le(vdev, struct virtio_pxp_config,
			sessions, &sessions);
	vpxp->sessions = sessions;

	virtio_device_ready(vdev);

	virtpxp_queue_evtbuf(vpxp);

	mutex_lock(&vpxp->dev_mutex);
	vpxp->ready = true;
	mutex_unlock(&vpxp->dev_mutex);

	spin_lock_irqsave(&pxp_lock, flags);
	list_add_tail(&vpxp->node, &pxp_devices);
	list_for_each_entry(device, &gpu_devices, node) {
		if (device && device->card == device_idx && device->vfid == device_vfid &&
						!device->vpxp) {
			gdev = device;
		}
	}
	if (gdev) {
		kref_get(&vpxp->ref);
		gdev->bind(gdev->priv, vpxp);
		gdev->vpxp = vpxp;
	}
	spin_unlock_irqrestore(&pxp_lock, flags);
	printk("virtio_pxp:vpxp:%p  device idx:%d, vfid:%d, sessions:%d\n", vpxp, device_idx, device_vfid, sessions);

	return 0;

err_init_vq:
	kfree(vpxp);
	return err;
}

static void virtpxp_remove(struct virtio_device *vdev)
{
	struct virtio_pxp *vpxp = vdev->priv;
	unsigned long flags;
	struct gpu_device *device = NULL;
	struct gpu_device *gdev = NULL;
	if (!vpxp)
		return;
	printk("%s\n", __FUNCTION__);
	mutex_lock(&vpxp->dev_mutex);
	vpxp->ready = false;
	mutex_unlock(&vpxp->dev_mutex);

	//vdev->config->reset(vdev);
	virtio_reset_device(vdev);

	vdev->config->del_vqs(vdev);
	spin_lock_irqsave(&pxp_lock, flags);
	list_del(&vpxp->node);
	list_for_each_entry(device, &gpu_devices, node) {
		if (device && device->vpxp == vpxp) {
			gdev = device;
		}
	}
	if (gdev) {
		gdev->unbind(gdev->priv);
		gdev->vpxp = NULL;
		put_virtio_pxp(gdev->vpxp);
	}

	spin_unlock_irqrestore(&pxp_lock, flags);
	put_virtio_pxp(vpxp);
}

#ifdef CONFIG_PM_SLEEP
static int virtpxp_freeze(struct virtio_device *vdev)
{
	struct virtio_pxp *vpxp = vdev->priv;
	if (!vpxp)
		return 0;
	printk("%s\n", __FUNCTION__);
	mutex_lock(&vpxp->dev_mutex);
	vpxp->ready = false;
	mutex_unlock(&vpxp->dev_mutex);

	//vdev->config->reset(vdev);
	virtio_reset_device(vdev);

	vdev->config->del_vqs(vdev);
	return 0;
}

static int virtpxp_restore(struct virtio_device *vdev)
{
	struct virtio_pxp *vpxp = vdev->priv;
	int err;
	if (!vpxp)
		return 0;
	printk("%s\n", __FUNCTION__);
	err = virtpxp_init_vqs(vpxp);
	if (err)
		return err;
	virtio_device_ready(vdev);
	virtpxp_queue_evtbuf(vpxp);
	mutex_lock(&vpxp->dev_mutex);
	vpxp->ready = true;
	mutex_unlock(&vpxp->dev_mutex);
	return 0;
}
#endif

static unsigned int features[] = {
	/* none */
};
static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PXP, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_pxp_driver = {
	.driver.name         = KBUILD_MODNAME,
	.driver.owner        = THIS_MODULE,
	.feature_table       = features,
	.feature_table_size  = ARRAY_SIZE(features),
	.id_table            = id_table,
	.probe               = virtpxp_probe,
	.remove              = virtpxp_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze	             = virtpxp_freeze,
	.restore             = virtpxp_restore,
#endif
};

int virtio_pxp_init(void)
{
	register_virtio_driver(&virtio_pxp_driver);
	return 0;
}

void virtio_pxp_exit(void)
{
	unregister_virtio_driver(&virtio_pxp_driver);
}
