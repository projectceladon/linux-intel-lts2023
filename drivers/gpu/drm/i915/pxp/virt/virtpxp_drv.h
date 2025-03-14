/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2024, Intel Corporation. All rights reserved.
 */

#ifndef VIRTPXP_DRV_H
#define VIRTPXP_DRV_H

#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/rwsem.h>
#include <linux/virtio_pxp.h>
#include <uapi/drm/i915_drm_prelim.h>

#define VIRTIO_ID_PXP                   60 /* virtio pxp */

struct virtio_pxp_base_request {
	struct completion completion;
	int rxlen;
};

struct virtio_pxp_set_session_request {
	struct virtio_pxp_base_request base;
	struct virtio_pxp_set_session_req req;
	struct virtio_pxp_set_session_resp resp;
};

struct virtio_pxp_io_message_request {
	struct virtio_pxp_base_request base;
	struct virtio_pxp_io_message_req req;
	struct virtio_pxp_io_message_resp resp;
	char *msg_in;
	char *msg_out;
};

struct virtio_pxp_query_tag_request {
	struct virtio_pxp_base_request base;
	struct virtio_pxp_query_tag_req req;
	struct virtio_pxp_query_tag_resp resp;
};

struct virtio_pxp_host_session_handle_request_request {
	struct virtio_pxp_base_request base;
	struct virtio_pxp_host_session_handle_req req;
	struct virtio_pxp_host_session_handle_resp resp;
};

struct virtio_pxp {
	struct virtio_device *vdev;
	struct kref ref;
	bool ready;
	spinlock_t control_lock;
	spinlock_t event_lock;
	struct virtqueue *control_vq;
	struct virtqueue *event_vq;
	int device_idx;
	int device_vfid;
	int sessions;
	void (*irq_recv)(int event, void *priv);
	void *cb_priv;
//	int (*bind)(void *gpu_priv, void *pxp_priv);
//	void (*unbind)(void *gpu_priv);
	unsigned int evtbuf;
	struct list_head node;
	struct mutex dev_mutex;
};

#ifdef CONFIG_DRM_I915_PXP
void put_virtio_pxp(struct virtio_pxp *vpxp);
int virtio_set_session(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_set_session_status_params *params);
int virtio_io_msg(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_tee_io_message_params *params);
int virtio_query_tag(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_query_tag *params);
int virtio_host_session_handle_request(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_host_session_handle_request *params);
int virtpxp_register_intel_gpu_device(int device_idx, int device_vfid, void *gpu_priv,
			int (*bind)(void *gpu_priv, void *pxp_priv), void (*unbind)(void *gpu_priv));
void virtpxp_unregister_intel_gpu_device(int device_idx, int device_vfid, void *gpu_priv);
int virtio_pxp_init(void);
void virtio_pxp_exit(void);
#elif
void put_virtio_pxp(struct virtio_pxp *vpxp)
{
}
int virtio_set_session(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_set_session_status_params *params)
{
	return -1;
}
int virtio_io_msg(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_tee_io_message_params *params)
{
	return -1;
}
int virtio_query_tag(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_query_tag *params)
{
	return -1;
}
int virtio_host_session_handle_request(struct virtio_pxp *vpxp, struct prelim_drm_i915_pxp_host_session_handle_request *params)
{
	return -1;
}
int virtpxp_register_intel_gpu_device(int device_idx, int device_vfid, void *gpu_priv,
			int (*bind)(void *gpu_priv, void *pxp_priv), void (*unbind)(void *gpu_priv))
{
	return -1;
}
void virtpxp_unregister_intel_gpu_device(int device_idx, int device_vfid, void *gpu_priv)
{
}
int virtio_pxp_init(void)
{
	return -1;
}
void virtio_pxp_exit(void)
{
}

#endif

#endif
