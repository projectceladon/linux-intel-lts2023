/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2024, Intel Corporation. All rights reserved.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <drm/drm_print.h>
#include <drm/i915_drm_prelim.h>
#include "gem/i915_gem_context.h"
#include "gt/intel_context.h"
#include "gt/intel_gt.h"
#include "i915_drv.h"
#include "intel_pxp_fe.h"
#include "gt/iov/intel_iov_query.h"

int intel_pxp_fe_sm_ioctl_reserve_session(struct intel_pxp *pxp, struct drm_file *drmfile,
		int protection_mode, u32 *pxp_tag);

int intel_pxp_fe_sm_ioctl_mark_session_in_play(struct intel_pxp *pxp,
		struct drm_file *drmfile,
		u32 session_id);

int intel_pxp_fe_sm_ioctl_terminate_session(struct intel_pxp *pxp,
		struct drm_file *drmfile,
		u32 session_id);

int intel_pxp_fe_io_message(struct intel_pxp *pxp,
		void *msg_in, u32 msg_in_size,
		void *msg_out, u32 msg_out_max_size,
		u32 *msg_out_rcv_size);

int intel_pxp_fe_sm_ioctl_query_pxp_tag(struct intel_pxp *pxp,
		u32 *session_is_alive, u32 *pxp_tag);

int intel_pxp_fe_gsccs_get_client_host_session_handle(struct intel_pxp *pxp, struct drm_file *drmfile,
		u32 request_type, u64 *host_session_handle);

bool intel_pxp_fe_is_supported(const struct intel_pxp *pxp)
{
	return IS_ENABLED(CONFIG_DRM_I915_PXP) && pxp;
}

bool intel_pxp_fe_is_enabled(const struct intel_pxp *pxp)
{
	return IS_ENABLED(CONFIG_DRM_I915_PXP) && pxp && pxp->fe.enabled;
}

bool intel_pxp_fe_is_active(const struct intel_pxp *pxp)
{
	return IS_ENABLED(CONFIG_DRM_I915_PXP) && pxp && pxp->fe.active;
}

void pxp_key_instance_update(struct intel_pxp *pxp)
{
	if (!++pxp->fe.key_instance)
		++pxp->fe.key_instance;
}

static bool check_session_id(struct intel_pxp *pxp, int id)
{
	int index;
	for (index = 0; index < INTEL_PXP_MAX_HWDRM_SESSIONS; index++) {
		if (pxp->fe.hwdrm_sessions[index].index >= 0 && (pxp->fe.hwdrm_sessions[index].index == id)) {
			return true;
		}
	}
	return false;
}

static void event_cb(int event, void *priv)
{
	struct intel_pxp *pxp = (struct intel_pxp *)priv;
	unsigned long flags;
	if (!pxp)
		return;
	printk("PXP FE: event receive: %d\n", event);
	spin_lock_irqsave(&pxp->fe.irq_lock, flags);
	pxp->session_events |= event;
	spin_unlock_irqrestore(&pxp->fe.irq_lock, flags);

	queue_work(system_unbound_wq, &pxp->fe.session_work);
}

void intel_pxp_fe_terminate(struct intel_pxp *pxp)
{
	pxp->fe.active = false;
	mutex_lock(&pxp->fe.session_mutex);
	for (int index = 0; index < INTEL_PXP_MAX_HWDRM_SESSIONS; index++) {
		if (pxp->fe.hwdrm_sessions[index].index >= 0) {
			printk("%s, PXP FE: session terminate:%d\n", __FUNCTION__, index);
			intel_pxp_fe_sm_ioctl_terminate_session(pxp, pxp->fe.hwdrm_sessions[index].drmfile, index);
		}
	}
	mutex_unlock(&pxp->fe.session_mutex);
}

void intel_pxp_fe_terminate_complete(struct intel_pxp *pxp)
{
	pxp_key_instance_update(pxp);
	pxp->fe.active = true;
}

static void pxp_fe_session_work(struct work_struct *work)
{
	struct intel_pxp_fe *pxp_fe = container_of(work, typeof(*pxp_fe), session_work);
	intel_wakeref_t wakeref;
	unsigned long flags;
	u32 events = 0;
	if (!pxp_fe)
		return;
	spin_lock_irqsave(&pxp_fe->irq_lock, flags);
	events = fetch_and_zero(&pxp_fe->session_events);
	spin_unlock_irqrestore(&pxp_fe->irq_lock, flags);

	if (!events)
		return;

	//printk("PXP FE: processing event-flags 0x%08x", events);

	if (events & PXP_INVAL_REQUIRED) {
		intel_pxp_invalidate(pxp_fe->i915->pxp);
	}

	wakeref = intel_runtime_pm_get_if_in_use(&pxp_fe->i915->runtime_pm);
	if (!wakeref)
		return;

	if (events & PXP_TERMINATION_REQUEST) {
		events &= ~PXP_TERMINATION_COMPLETE;
		intel_pxp_fe_terminate(pxp_fe->i915->pxp);
	}

	if (events & PXP_TERMINATION_COMPLETE)
		intel_pxp_fe_terminate_complete(pxp_fe->i915->pxp);

	intel_runtime_pm_put(&pxp_fe->i915->runtime_pm, wakeref);
}

int pxp_bind(void *gpu_priv, void *pxp_priv)
{
	struct intel_pxp *pxp = (struct intel_pxp *)gpu_priv;
	struct virtio_pxp *vpxp = (struct virtio_pxp *)pxp_priv;
	if (!pxp || !vpxp)
		return -1;
	printk("%s\n", __FUNCTION__);
	pxp->fe.vpxp = vpxp;
	pxp->fe.enabled = true;
	pxp->fe.max_sessions = vpxp->sessions;
	pxp->fe.avail_sessions = vpxp->sessions;

	vpxp->irq_recv = event_cb;
	vpxp->cb_priv = pxp;
	return -1;
}

void pxp_unbind(void *gpu_priv)
{
	struct intel_pxp *pxp = (struct intel_pxp *)gpu_priv;
	if (!pxp)
		return;
	printk("%s\n", __FUNCTION__);
	pxp->fe.enabled = false;
}

int intel_pxp_fe_init(struct drm_i915_private *i915)
{
	struct intel_gt *gt;
	struct virtio_pxp *vpxp;
	intel_wakeref_t wakeref;
	int ret = 0;
	int device_idx = 0;
	int device_vfid = 1;
	int i = 0;
	int index = 0;
	if (intel_gt_is_wedged(to_gt(i915)))
		return -ENOTCONN;
	i915->pxp = kzalloc(sizeof(*i915->pxp), GFP_KERNEL);
	if (!i915->pxp)
		return -ENOMEM;
	i915->pxp->vf = true;
	i915->pxp->fe.enabled = false;
	i915->pxp->fe.active = false;
	i915->pxp->fe.i915 = i915;
	i915->pxp->fe.key_instance = 0;

	wakeref = intel_runtime_pm_get(&i915->runtime_pm);
	for_each_gt(gt, i915, i) {
		ret = pxp_info_query(&gt->iov,  &device_idx, &device_vfid);
		if (ret < 0) {
			DRM_ERROR("PXP FE: pxp info query failure\n");
			intel_runtime_pm_put(&i915->runtime_pm, wakeref);
			return -1;
		} else {
			break;
		}
	}
	intel_runtime_pm_put(&i915->runtime_pm, wakeref);
	INIT_WORK(&i915->pxp->fe.session_work, pxp_fe_session_work);
	mutex_init(&i915->pxp->fe.session_mutex);
	spin_lock_init(&i915->pxp->fe.irq_lock);
	for (int index = 0; index < INTEL_PXP_MAX_HWDRM_SESSIONS; index++) {
		i915->pxp->fe.hwdrm_sessions[index].index = -1;
		i915->pxp->fe.hwdrm_sessions[index].is_valid = false;
		i915->pxp->fe.hwdrm_sessions[index].drmfile = NULL;
	}
	virtpxp_register_intel_gpu_device(device_idx, device_vfid, i915->pxp, pxp_bind, pxp_unbind);

	DRM_INFO("PXP FE: protected content support initialized\n");
	return 0;
}

void intel_pxp_fe_fini(struct drm_i915_private *i915)
{
	if (!i915 || !i915->pxp)
		return;
	DRM_INFO("PXP FE:  protected content support uninitialized\n");
	flush_work(&i915->pxp->fe.session_work);
	virtpxp_unregister_intel_gpu_device(i915->pxp->fe.device_idx, i915->pxp->fe.device_vfid, i915->pxp);
	i915->pxp->fe.enabled = false;
	i915->pxp->fe.active = false;
	kfree(i915->pxp);
	i915->pxp = NULL;
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
	if (!intel_pxp_fe_is_enabled(pxp))
		return -ENODEV;
	return 1;
}

int intel_pxp_fe_get_backend_timeout_ms(struct intel_pxp *pxp)
{
	return 250;
}

int intel_pxp_fe_start(struct intel_pxp *pxp)
{
	if (!intel_pxp_fe_is_enabled(pxp))
		return 0;
	if (intel_pxp_is_active(pxp))
		return 0;
	printk("%s\n", __FUNCTION__);
	pxp_key_instance_update(pxp);

	pxp->fe.active = true;

	return 0;

}
void intel_pxp_fe_end(struct intel_pxp *pxp)
{
	if (!intel_pxp_fe_is_enabled(pxp))
		return;
	if (!intel_pxp_is_active(pxp))
		return ;
	printk("%s\n", __FUNCTION__);
	flush_work(&pxp->fe.session_work);
	pxp->fe.active = false;
}

int intel_pxp_fe_key_check(struct intel_pxp *pxp,
		struct drm_i915_gem_object *obj,
		bool assign)
{
	if (!intel_pxp_is_active(pxp))
		return -ENODEV;

	if (!i915_gem_object_is_protected(obj))
		return -EINVAL;

	GEM_BUG_ON(!pxp->fe.key_instance);

	/*
	 * If this is the first time we're using this object, it's not
	 * encrypted yet; it will be encrypted with the current key, so mark it
	 * as such. If the object is already encrypted, check instead if the
	 * used key is still valid.
	 */
	if (!obj->pxp_key_instance && assign)
		obj->pxp_key_instance = pxp->fe.key_instance;

	if (obj->pxp_key_instance != pxp->fe.key_instance)
		return -ENOEXEC;
	return 0;
}

void intel_pxp_fe_invalidate(struct intel_pxp *pxp)
{

}

int intel_pxp_fe_sm_ioctl_reserve_session(struct intel_pxp *pxp, struct drm_file *drmfile,
		int protection_mode, u32 *pxp_tag)
{
	int ret = 0;
	int session_id = 0;
	struct prelim_drm_i915_pxp_set_session_status_params params;
	memset(&params, 0, sizeof(params));
	if (!drmfile || !pxp_tag || pxp->fe.avail_sessions <= 0)
		return -EINVAL;
	params.session_mode = protection_mode;
	params.req_session_state = PRELIM_DRM_I915_PXP_REQ_SESSION_ID_INIT;
	ret = virtio_set_session(pxp->fe.vpxp, &params);
	*pxp_tag = params.pxp_tag;
	session_id = *pxp_tag & PRELIM_DRM_I915_PXP_TAG_SESSION_ID_MASK;
	//printk("%s, session_id:%d, ret:%d\n",__FUNCTION__, session_id, ret);
	if (session_id >= INTEL_PXP_MAX_HWDRM_SESSIONS || session_id < 0) {
		DRM_ERROR("PXP FE: invalid session id:%d", session_id);
		return -1;
	}
	pxp->fe.avail_sessions--;
	pxp->fe.hwdrm_sessions[session_id].index = session_id;
	pxp->fe.hwdrm_sessions[session_id].protection_mode = protection_mode;
	pxp->fe.hwdrm_sessions[session_id].drmfile = drmfile;
	pxp->fe.hwdrm_sessions[session_id].tag = *pxp_tag;
	pxp->fe.hwdrm_sessions[session_id].is_valid = false;

	return ret;
}

int intel_pxp_fe_sm_ioctl_mark_session_in_play(struct intel_pxp *pxp,
		struct drm_file *drmfile,
		u32 session_id)
{
	int ret = 0;
	struct prelim_drm_i915_pxp_set_session_status_params params;
	memset(&params, 0, sizeof(params));
	if (session_id >= INTEL_PXP_MAX_HWDRM_SESSIONS || session_id < 0)
		return -EINVAL;
	if (!check_session_id(pxp, session_id))
		return -EINVAL;
	params.pxp_tag = session_id;
	params.req_session_state = PRELIM_DRM_I915_PXP_REQ_SESSION_IN_PLAY;
	ret = virtio_set_session(pxp->fe.vpxp, &params);
	//printk("%s, session_id:%d, ret:%d\n",__FUNCTION__, session_id, ret);
	if (ret < 0)
		return ret;
	pxp->fe.hwdrm_sessions[session_id].is_valid = true;
	return ret;
}

int intel_pxp_fe_sm_ioctl_terminate_session(struct intel_pxp *pxp,
		struct drm_file *drmfile,
		u32 session_id)
{
	int ret = 0;
	struct prelim_drm_i915_pxp_set_session_status_params params;
	memset(&params, 0, sizeof(params));
	if (session_id >= INTEL_PXP_MAX_HWDRM_SESSIONS)
		return -EINVAL;
	if (!check_session_id(pxp, session_id))
		return -EINVAL;
	pxp->fe.hwdrm_sessions[session_id].is_valid = false;
	pxp->fe.hwdrm_sessions[session_id].index = -1;
	pxp->fe.hwdrm_sessions[session_id].drmfile = NULL;
	pxp->fe.avail_sessions++;
	params.pxp_tag = session_id;
	params.req_session_state = PRELIM_DRM_I915_PXP_REQ_SESSION_TERMINATE;
	ret = virtio_set_session(pxp->fe.vpxp, &params);
	//printk("%s, session_id:%d, ret:%d\n",__FUNCTION__, session_id, ret);
	return ret;
}

int intel_pxp_fe_io_message(struct intel_pxp *pxp,
		void *msg_in, u32 msg_in_size,
		void *msg_out, u32 msg_out_max_size,
		u32 *msg_out_rcv_size)
{
	int ret = 0;
	struct prelim_drm_i915_pxp_tee_io_message_params params;
	memset(&params, 0, sizeof(params));
	if (msg_in == NULL || msg_out == NULL) {
		return -EINVAL;
	}
	params.msg_in = (u64)msg_in;
	params.msg_in_size = msg_in_size;
	params.msg_out = (u64)msg_out;
	params.msg_out_buf_size = msg_out_max_size;
	ret = virtio_io_msg(pxp->fe.vpxp, &params);
	//printk("%s, ret:%d, ret size:%d\n",__FUNCTION__,  ret, params.msg_out_ret_size);
	*msg_out_rcv_size = params.msg_out_ret_size;
	return ret;
}

int intel_pxp_fe_sm_ioctl_query_pxp_tag(struct intel_pxp *pxp,
		u32 *session_is_alive, u32 *pxp_tag)
{
	int ret = 0;
	int session_id;
	struct prelim_drm_i915_pxp_query_tag params;
	memset(&params, 0, sizeof(params));
	if (!session_is_alive || !pxp_tag)
		return -EINVAL;
	session_id = *pxp_tag & PRELIM_DRM_I915_PXP_TAG_SESSION_ID_MASK;
	if (!check_session_id(pxp, session_id))
		return -EINVAL;

	params.pxp_tag = *pxp_tag;
	ret = virtio_query_tag(pxp->fe.vpxp, &params);
	*pxp_tag = params.pxp_tag;
	*session_is_alive = params.session_is_alive;
	//printk("%s, ret:%d\n",__FUNCTION__,  ret);
	return ret;
}

int intel_pxp_fe_gsccs_get_client_host_session_handle(struct intel_pxp *pxp, struct drm_file *drmfile
		, u32 request_type, u64 *host_session_handle)
{
	int ret = 0;
	struct prelim_drm_i915_pxp_host_session_handle_request params;
	memset(&params, 0, sizeof(params));
	if (!host_session_handle)
		return -EINVAL;
	params.request_type = request_type;
	ret = virtio_host_session_handle_request(pxp->fe.vpxp, &params);
	*host_session_handle = params.host_session_handle;
	return ret;
}

static int pxp_fe_set_session_status(struct intel_pxp *pxp,
		struct prelim_drm_i915_pxp_ops *pxp_ops,
		struct drm_file *drmfile)
{
	struct prelim_drm_i915_pxp_set_session_status_params params;
	struct prelim_drm_i915_pxp_set_session_status_params __user *uparams =
		u64_to_user_ptr(pxp_ops->params);
	u32 session_id;
	int ret = 0;

	if (copy_from_user(&params, uparams, sizeof(params)) != 0)
		return -EFAULT;

	session_id = params.pxp_tag & PRELIM_DRM_I915_PXP_TAG_SESSION_ID_MASK;

	switch (params.req_session_state) {
		case PRELIM_DRM_I915_PXP_REQ_SESSION_ID_INIT:
			ret = intel_pxp_fe_sm_ioctl_reserve_session(pxp, drmfile,
					params.session_mode,
					&params.pxp_tag);

			break;
		case PRELIM_DRM_I915_PXP_REQ_SESSION_IN_PLAY:
			ret = intel_pxp_fe_sm_ioctl_mark_session_in_play(pxp, drmfile,
					session_id);
			break;
		case PRELIM_DRM_I915_PXP_REQ_SESSION_TERMINATE:
			ret = intel_pxp_fe_sm_ioctl_terminate_session(pxp, drmfile,
					session_id);
			break;
		default:
			ret = -EINVAL;
	}

	if (ret >= 0) {
		pxp_ops->status = ret;

		if (copy_to_user(uparams, &params, sizeof(params)))
			ret = -EFAULT;
		else
			ret = 0;
	}

	return ret;
}

static bool ioctl_buffer_size_valid(u32 size)
{
	return size > 0 && size <= SZ_64K;
}

static int
intel_pxp_fe_ioctl_io_message(struct intel_pxp *pxp, struct drm_file *drmfile,
		struct prelim_drm_i915_pxp_tee_io_message_params *params)
{
	struct drm_i915_private *i915;
	void *msg_in = NULL;
	void *msg_out = NULL;
	int ret = 0;
	i915 = pxp->fe.i915;


	if (!params->msg_in || !params->msg_out ||
			!ioctl_buffer_size_valid(params->msg_out_buf_size) ||
			!ioctl_buffer_size_valid(params->msg_in_size))
		return -EINVAL;

	msg_in = kzalloc(params->msg_in_size, GFP_KERNEL);
	if (!msg_in)
		return -ENOMEM;

	msg_out = kzalloc(params->msg_out_buf_size, GFP_KERNEL);
	if (!msg_out) {
		ret = -ENOMEM;
		goto end;
	}

	if (copy_from_user(msg_in, u64_to_user_ptr(params->msg_in), params->msg_in_size)) {
		drm_dbg(&i915->drm, "Failed to copy_from_user for TEE message\n");
		ret = -EFAULT;
		goto end;
	}

	ret = intel_pxp_fe_io_message(pxp,
			msg_in, params->msg_in_size,
			msg_out, params->msg_out_buf_size,
			&params->msg_out_ret_size);

	if (ret) {
		drm_dbg(&i915->drm, "Failed to send/receive user TEE message\n");
		goto end;
	}

	if (copy_to_user(u64_to_user_ptr(params->msg_out), msg_out, params->msg_out_ret_size)) {
		drm_dbg(&i915->drm, "Failed copy_to_user for TEE message\n");
		ret = -EFAULT;
		goto end;
	}

end:
	kfree(msg_in);
	kfree(msg_out);
	return ret;
}

static int pxp_fe_send_tee_msg(struct intel_pxp *pxp,
		struct prelim_drm_i915_pxp_ops *pxp_ops,
		struct drm_file *drmfile)
{
	struct drm_i915_private *i915;
	struct prelim_drm_i915_pxp_tee_io_message_params params;
	struct prelim_drm_i915_pxp_tee_io_message_params __user *uparams =
		u64_to_user_ptr(pxp_ops->params);
	int ret = 0;
	i915 = pxp->fe.i915;

	if (copy_from_user(&params, uparams, sizeof(params)) != 0)
		return -EFAULT;

	ret = intel_pxp_fe_ioctl_io_message(pxp, drmfile, &params);
	if (ret >= 0) {
		pxp_ops->status = ret;

		if (copy_to_user(uparams, &params, sizeof(params)))
			ret = -EFAULT;
		else
			ret = 0;
	} else {
		drm_dbg(&i915->drm, "Failed to send user TEE IO message\n");
	}

	return ret;
}

static int pxp_fe_query_tag(struct intel_pxp *pxp, struct prelim_drm_i915_pxp_ops *pxp_ops)
{
	struct prelim_drm_i915_pxp_query_tag params;
	struct prelim_drm_i915_pxp_query_tag __user *uparams =
		u64_to_user_ptr(pxp_ops->params);
	int ret = 0;

	if (copy_from_user(&params, uparams, sizeof(params)) != 0)
		return -EFAULT;

	ret = intel_pxp_fe_sm_ioctl_query_pxp_tag(pxp, &params.session_is_alive,
			&params.pxp_tag);
	if (ret >= 0) {
		pxp_ops->status = ret;

		if (copy_to_user(uparams, &params, sizeof(params)))
			ret = -EFAULT;
		else
			ret = 0;
	}

	return ret;
}

	static int
pxp_fe_process_host_session_handle_request(struct intel_pxp *pxp,
		struct prelim_drm_i915_pxp_ops *pxp_ops,
		struct drm_file *drmfile)
{
	struct prelim_drm_i915_pxp_host_session_handle_request params;
	struct prelim_drm_i915_pxp_host_session_handle_request __user *uparams =
		u64_to_user_ptr(pxp_ops->params);
	int ret = 0;

	if (copy_from_user(&params, uparams, sizeof(params)) != 0)
		return -EFAULT;

	if (params.request_type != PRELIM_DRM_I915_PXP_GET_HOST_SESSION_HANDLE) {
		ret = PRELIM_DRM_I915_PXP_OP_STATUS_ERROR_INVALID;
		goto error_out;
	}

	intel_pxp_fe_gsccs_get_client_host_session_handle(pxp, drmfile, params.request_type,
			&params.host_session_handle);

	if (!params.host_session_handle) {
		ret = PRELIM_DRM_I915_PXP_OP_STATUS_ERROR_UNKNOWN;
		DRM_WARN("PXP FE: Host Session Handle allocated 0x0\n");
	}

error_out:
	if (ret >= 0) {
		pxp_ops->status = ret;

		if (copy_to_user(uparams, &params, sizeof(params)))
			ret = -EFAULT;
		else
			ret = 0;
	}

	return ret;
}

int i915_pxp_fe_ops_ioctl(struct drm_device *dev, void *data, struct drm_file *drmfile)
{
	int ret = 0;
	struct prelim_drm_i915_pxp_ops *pxp_ops = data;
	struct drm_i915_private *i915 = to_i915(dev);
	struct intel_pxp *pxp = i915->pxp;
	intel_wakeref_t wakeref;

	if (!intel_pxp_is_enabled(pxp))
		return -ENODEV;

	wakeref = intel_runtime_pm_get_if_in_use(&i915->runtime_pm);
	if (!wakeref) {
		drm_dbg(&i915->drm, "PXP FE: pxp ioctl blocked due to state in suspend\n");
		pxp_ops->status = PRELIM_DRM_I915_PXP_OP_STATUS_SESSION_NOT_AVAILABLE;
		return 0;
	}

	if (!intel_pxp_is_active(pxp)) {
		ret = intel_pxp_start(pxp);
		if (ret)
			goto out_pm;
	}

	mutex_lock(&pxp->fe.session_mutex);

	switch (pxp_ops->action) {
		case PRELIM_DRM_I915_PXP_ACTION_SET_SESSION_STATUS:
			ret = pxp_fe_set_session_status(pxp, pxp_ops, drmfile);
			break;
		case PRELIM_DRM_I915_PXP_ACTION_TEE_IO_MESSAGE:
			ret = pxp_fe_send_tee_msg(pxp, pxp_ops, drmfile);
			break;
		case PRELIM_DRM_I915_PXP_ACTION_QUERY_PXP_TAG:
			ret = pxp_fe_query_tag(pxp, pxp_ops);
			break;
		case PRELIM_DRM_I915_PXP_ACTION_HOST_SESSION_HANDLE_REQ:
			ret = pxp_fe_process_host_session_handle_request(pxp, pxp_ops, drmfile);
			break;
		default:
			ret = -EINVAL;
			break;
	}

	mutex_unlock(&pxp->fe.session_mutex);
out_pm:
	intel_runtime_pm_put(&i915->runtime_pm, wakeref);

	return ret;
}

void intel_pxp_fe_close(struct intel_pxp *pxp, struct drm_file *drmfile)
{
	int index = 0;
	if (!intel_pxp_fe_is_enabled(pxp) || !drmfile)
		return;

	mutex_lock(&pxp->fe.session_mutex);
	for (index = 0; index < INTEL_PXP_MAX_HWDRM_SESSIONS; index++) {
		if (pxp->fe.hwdrm_sessions[index].index >= 0 && (pxp->fe.hwdrm_sessions[index].drmfile == drmfile)) {
			printk("%s, PXP FE: session terminate:%d\n", __FUNCTION__, index);
			intel_pxp_fe_sm_ioctl_terminate_session(pxp, pxp->fe.hwdrm_sessions[index].drmfile, index);
		}
	}
	mutex_unlock(&pxp->fe.session_mutex);
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

