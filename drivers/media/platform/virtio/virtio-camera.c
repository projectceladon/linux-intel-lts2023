// SPDX-License-Identifier: GPL-2.0-or-later
 /*
  * Driver for VirtIO camera device.
  *
  * Copyright © 2022 Collabora, Ltd.
  */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_camera.h>
#include <linux/virtio_types.h>
#include <linux/virtio_ids.h>
#include <media/videobuf2-dma-sg.h>

#include <media/media-device.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>

#include <asm/msr.h>

#define VQ_NAME_LEN	24
/**
 * struct virtio_camera_ctrl_req - The internal data for one virtio-camera request and response
 * @ctrl: The request info, filled in frontend
 * @resp: The response info, filled by backend
 * @completion: the "completion" signal
 * @vb: The specific buffer related to this request
 */
struct virtio_camera_ctrl_req {
	struct virtio_camera_op_ctrl_req ctrl;
	struct virtio_camera_op_ctrl_req resp;
	struct completion completion;
	struct vb2_buffer *vb;
};

/* Per-virtqueue state */
struct virtio_camera_vq {
	struct virtqueue *vq;
	char name[VQ_NAME_LEN];
};

/**
 * struct virtio_camera_video - All internal data for one instance of video node
 * @vdev: video device node structure
 * @video_lock: ioctl serialization mutex
 * @vb_queue: vb2 video capture queue
 * @sequence: frame sequence counter
 * @format: current v4l2 format
 * @ctr_vqx: ctrl virtqueue
 */
struct virtio_camera_video {
	struct video_device vdev;
	struct mutex video_lock;
	struct vb2_queue vb_queue;
	unsigned int sequence;
	struct v4l2_format format;
	struct virtio_camera_vq *ctr_vqx;
	unsigned int idx;
};

/**
 * struct virtio_camera_buffer - the driver-specific buffer structure;
 *        driver uses this custom buffer structure type. The first field of the
 *        driver-specific buffer structure must be the subsystem-specific
 *        struct (vb2_v4l2_buffer in the case of V4L2).
 * @vb: vb2_v4l2 buffer
 * @uuid: ID info for this buffer
 */
struct virtio_camera_buffer {
	struct vb2_v4l2_buffer vb;
	u8 uuid[16];
};

/**
 * struct virtual_camera - All internal data for one instance of virtual camera
 * @vnode: video nodes
 * @nr_videos: number of videos;  one virtual camera may contain multiple video streams
 * @v4l2_lock: ioctl serialization mutex
 * @v4l2_dev: top-level v4l2 device struct
 * @mdev: top-level media device struct
 */
struct virtual_camera {
	struct virtio_camera_video *vnodes;
	int nr_videos;
	struct mutex v4l2_lock;
	struct v4l2_device v4l2_dev;
	struct media_device mdev;
};

/**
 * struct virtio_camera - All internal data for one instance of virtio camera
 * @config: virtio camera configuration structure
 * @vqs: used virtqueues
 * @nvqs: number of virtqueues
 * @virtual_cameras: virtual cameras; one virtio_camera may contain multiple virtual cameras
 */
struct virtio_camera {
	struct virtio_camera_config config;
	struct virtio_camera_vq *vqs;
	unsigned int nvqs;
	struct virtual_camera *virtual_cameras;
};

static inline struct virtio_camera_buffer *
vb_to_vcam_buf(struct vb2_buffer *vb)
{
	struct vb2_v4l2_buffer *vbuf = to_vb2_v4l2_buffer(vb);

	return container_of(vbuf, struct virtio_camera_buffer, vb);
}

static struct virtio_camera_ctrl_req *
virtio_camera_create_req(unsigned int cmd)
{
	struct virtio_camera_ctrl_req *vcam_req;

	vcam_req = kmalloc(sizeof(*vcam_req), GFP_KERNEL);
	if (unlikely(vcam_req == NULL)) {
		pr_err("virtio_camera: could not allocate integrity buffer\n");
		return NULL;
	}

	vcam_req->ctrl.header.cmd = cmd;
	vcam_req->vb = NULL;
	init_completion(&vcam_req->completion);

	return vcam_req;
}

static void virtio_camera_control_ack(struct virtqueue *vq)
{
	struct virtio_camera_ctrl_req *req;
	struct vb2_v4l2_buffer *vbuf;
	unsigned int len;

	while ((req = virtqueue_get_buf(vq, &len))) {
		complete(&req->completion);

		if (req->vb) {
			vbuf = to_vb2_v4l2_buffer(req->vb);
			vbuf->sequence = req->resp.u.buffer.sequence;
			vbuf->vb2_buf.timestamp = req->resp.u.buffer.timestamp;
			vb2_buffer_done(req->vb, VB2_BUF_STATE_DONE);
			pr_debug("virtio-camera: mark the buffer done. UUID is %d, ptr is %pK\n",
			req->resp.u.buffer.uuid[0] + req->resp.u.buffer.uuid[1], req->vb);

			kfree(req);
		}
	}
}

static int vcam_vq_request(struct virtio_camera_video *vnode,
			   struct virtio_camera_ctrl_req *req,
			   struct virtio_camera_mem_entry *ents,
			   unsigned int num_ents,
			   bool async)
{
	struct scatterlist vreq[3], *sgs[3];
	unsigned int num_sgs = 0;
	int ret;

	memset(&req->resp, 0, sizeof(req->resp));

	sg_init_one(&vreq[0], &req->ctrl, sizeof(req->ctrl));
	sgs[num_sgs++] = &vreq[0];

	if (ents) {
		sg_init_one(&vreq[1], ents, sizeof(*ents) * num_ents);
		sgs[num_sgs++] = &vreq[1];
	}
	sg_init_one(&vreq[2], &req->resp, sizeof(req->resp));
	sgs[num_sgs++] = &vreq[2];

	ret = virtqueue_add_sgs(vnode->ctr_vqx->vq, sgs, num_sgs - 1, 1, req, GFP_KERNEL);
	if (ret)
		return ret;

	virtqueue_kick(vnode->ctr_vqx->vq);

	if (async)
		return 0;

	wait_for_completion(&req->completion);

	memset(&req->ctrl, 0, sizeof(req->ctrl));

	switch (req->resp.header.cmd) {
	case VIRTIO_CAMERA_CMD_RESP_OK_NODATA:
		ret = 0;
		break;

	case VIRTIO_CAMERA_CMD_RESP_ERR_BUSY:
		ret = -EBUSY;
		break;

	case VIRTIO_CAMERA_CMD_RESP_ERR_OUT_OF_MEMORY:
		ret = -ENOMEM;
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int vcam_v4l2_fh_open(struct file *filp)
{
	struct virtio_camera_video *vnode;
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vnode = video_drvdata(filp);

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_FILE_OPEN);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err) {
		pr_err("virtio-camera: file handler open failed because of err response.\n");
		goto err_free;
	}

	err = v4l2_fh_open(filp);

err_free:
	kfree(vcam_req);
	return err;
}

int vcam_v4l2_fh_release(struct file *filp)
{
	struct virtio_camera_video *vnode;
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	err = vb2_fop_release(filp);
	if (err)
		goto err;

	vnode = video_drvdata(filp);
	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_FILE_CLOSE);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		pr_err("virtio-camera: file handler release failed because of err response.\n");

	kfree(vcam_req);
err:
	return err;
}
static const struct v4l2_file_operations vcam_v4l2_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = video_ioctl2,
	.open = vcam_v4l2_fh_open,
	.release = vcam_v4l2_fh_release,
	.poll = vb2_fop_poll,
	.mmap = vb2_fop_mmap,
	.read = vb2_fop_read,
};

static int vcam_querycap(struct file *file, void *priv,
			 struct v4l2_capability *cap)
{
	struct virtio_camera_video *vnode = video_drvdata(file);

	strscpy(cap->bus_info, "platform:camera", sizeof(cap->bus_info));
	strscpy(cap->driver, "virtio-camera", sizeof(cap->driver));
	snprintf(cap->card, sizeof(cap->card), "virtio-camera%u", vnode->idx);
	return 0;
}

static int vcam_enum_fmt(struct file *file, void *fh, struct v4l2_fmtdesc *f)
{
	struct virtio_camera_video *vnode = video_drvdata(file);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_ENUM_FORMAT);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	vcam_req->ctrl.header.index = f->index;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		goto err_free;

	f->pixelformat = vcam_req->resp.u.format.pixelformat;

err_free:
	kfree(vcam_req);
	return err;
}

static int vcam_enum_framesizes(struct file *file, void *fh,
				struct v4l2_frmsizeenum *fsize)
{
	struct virtio_camera_video *vnode = video_drvdata(file);
	struct virtio_camera_format_size *sz;
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_ENUM_SIZE);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	vcam_req->ctrl.header.index = fsize->index;
	vcam_req->ctrl.u.format.pixelformat = fsize->pixel_format;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		goto  err_free;

	sz = &vcam_req->resp.u.format.size;
	/* For simplify, now only support the DISCRETE format. */
	if (true) {
		fsize->discrete.width = sz->width;
		fsize->discrete.height = sz->height;
		fsize->type = V4L2_FRMSIZE_TYPE_DISCRETE;
	} else {
		fsize->stepwise.min_width = sz->min_width;
		fsize->stepwise.max_width = sz->max_width;
		fsize->stepwise.min_height = sz->min_height;
		fsize->stepwise.max_height = sz->max_height;
		fsize->stepwise.step_width = sz->step_width;
		fsize->stepwise.step_height = sz->max_height;

		if (sz->step_width == 1 && sz->step_height == 1)
			fsize->type = V4L2_FRMSIZE_TYPE_CONTINUOUS;
		else
			fsize->type = V4L2_FRMSIZE_TYPE_STEPWISE;
	}
	pr_debug("%s: fmt width is %d, height is %d\n", __func__, sz->width, sz->height);

err_free:
	kfree(vcam_req);
	return err;
}

static int vcam_enum_frameintervals(struct file *file, void *fh,
				 struct v4l2_frmivalenum *fintv)
{
	struct virtio_camera_video *vnode = video_drvdata(file);
	struct virtio_camera_format_size *sz;
	struct virtio_camera_ctrl_req *vcam_req;
	int err = 0;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_ENUM_INTV);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	vcam_req->ctrl.header.index = fintv->index;
	vcam_req->ctrl.u.format.pixelformat = fintv->pixel_format;
	vcam_req->ctrl.u.format.size.height = fintv->height;
	vcam_req->ctrl.u.format.size.width = fintv->width;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	sz = &vcam_req->resp.u.format.size;
	if (err)
		goto err_free;

	fintv->type = V4L2_FRMIVAL_TYPE_DISCRETE;
	fintv->discrete.denominator = sz->fps;
	fintv->discrete.numerator = 1;
	pr_debug("%s: idx is %d, denominator is %d, numerator is %d\n", __func__,
		fintv->index, fintv->discrete.denominator, fintv->discrete.numerator);

err_free:
	kfree(vcam_req);
	return err;
}

static int vcam_g_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct virtio_camera_video *vnode = video_drvdata(file);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_GET_FORMAT);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		goto err_free;

	f->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	f->fmt.pix.flags = 0;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.width = vcam_req->resp.u.format.size.width;
	f->fmt.pix.height = vcam_req->resp.u.format.size.height;
	f->fmt.pix.pixelformat = vcam_req->resp.u.format.pixelformat;
	f->fmt.pix.bytesperline = vcam_req->resp.u.format.size.stride;
	f->fmt.pix.sizeimage = vcam_req->resp.u.format.size.sizeimage;

	/* TODO */
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	vnode->format = *f;

err_free:
	kfree(vcam_req);
	return err;
}

static int vcam_s_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct virtio_camera_video *vnode = video_drvdata(file);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	if (f->type != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_SET_FORMAT);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	vcam_req->ctrl.u.format.size.width = f->fmt.pix.width;
	vcam_req->ctrl.u.format.size.height = f->fmt.pix.height;
	vcam_req->ctrl.u.format.size.stride = f->fmt.pix.bytesperline;
	vcam_req->ctrl.u.format.pixelformat = f->fmt.pix.pixelformat;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		goto err_free;

	f->fmt.pix.flags = 0;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.width = vcam_req->resp.u.format.size.width;
	f->fmt.pix.height = vcam_req->resp.u.format.size.height;
	f->fmt.pix.pixelformat = vcam_req->resp.u.format.pixelformat;
	f->fmt.pix.bytesperline = vcam_req->resp.u.format.size.stride;
	f->fmt.pix.sizeimage = vcam_req->resp.u.format.size.sizeimage;

	/* TODO */
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	vnode->format = *f;

err_free:
	kfree(vcam_req);
	return err;
}

static int vcam_try_fmt(struct file *file, void *fh, struct v4l2_format *f)
{
	struct virtio_camera_video *vnode = video_drvdata(file);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_TRY_FORMAT);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	vcam_req->ctrl.u.format.size.width = f->fmt.pix.width;
	vcam_req->ctrl.u.format.size.height = f->fmt.pix.height;
	vcam_req->ctrl.u.format.size.stride = f->fmt.pix.bytesperline;
	vcam_req->ctrl.u.format.pixelformat = f->fmt.pix.pixelformat;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		goto err_free;

	f->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;

	f->fmt.pix.flags = 0;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.width = vcam_req->resp.u.format.size.width;
	f->fmt.pix.height = vcam_req->resp.u.format.size.height;
	f->fmt.pix.pixelformat = vcam_req->resp.u.format.pixelformat;
	f->fmt.pix.bytesperline = vcam_req->resp.u.format.size.stride;
	f->fmt.pix.sizeimage = vcam_req->resp.u.format.size.sizeimage;

	/* TODO */
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

err_free:
	kfree(vcam_req);
	return err;
}

static int vcam_enum_input(struct file *filp, void *p,
				struct v4l2_input *input)
{
	if (input->index > 0)
		return -EINVAL;

	strscpy(input->name, "virtio-camera0", sizeof(input->name));
	input->type = V4L2_INPUT_TYPE_CAMERA;
	input->std = V4L2_STD_UNKNOWN;
	input->status = 0;

	return 0;
}

static int vcam_g_input(struct file *filp, void *p, unsigned int *i)
{
	*i = 0;

	return 0;
}

static int vcam_s_input(struct file *filp, void *p, unsigned int i)
{
	if (i)
		return -EINVAL;

	return 0;
}

static const struct v4l2_ioctl_ops vcam_ioctl_ops = {
	.vidioc_querycap = vcam_querycap,
	.vidioc_enum_fmt_vid_cap = vcam_enum_fmt,
	/* Frame size and interval */
	.vidioc_enum_frameintervals = vcam_enum_frameintervals,
	.vidioc_enum_framesizes = vcam_enum_framesizes,
	.vidioc_g_fmt_vid_cap = vcam_g_fmt,
	.vidioc_s_fmt_vid_cap = vcam_s_fmt,
	.vidioc_try_fmt_vid_cap = vcam_try_fmt,
	.vidioc_reqbufs = vb2_ioctl_reqbufs,
	.vidioc_querybuf = vb2_ioctl_querybuf,
	.vidioc_qbuf = vb2_ioctl_qbuf,
	.vidioc_expbuf = vb2_ioctl_expbuf,
	.vidioc_dqbuf = vb2_ioctl_dqbuf,
	.vidioc_create_bufs = vb2_ioctl_create_bufs,
	.vidioc_prepare_buf = vb2_ioctl_prepare_buf,
	.vidioc_streamon = vb2_ioctl_streamon,
	.vidioc_streamoff = vb2_ioctl_streamoff,
	.vidioc_enum_input = vcam_enum_input,
	.vidioc_g_input = vcam_g_input,
	.vidioc_s_input = vcam_s_input,
};

static int
vcam_queue_setup(struct vb2_queue *vq,
		 unsigned int *nbuffers, unsigned int *num_planes,
		 unsigned int sizes[], struct device *alloc_devs[])

{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(vq);
	unsigned int size = vnode->format.fmt.pix.sizeimage;
	int ret;

	if (vq->num_buffers + *nbuffers < 2)
		*nbuffers = 2 - vq->num_buffers;

	if (*num_planes) {
		ret = sizes[0] < size ? -EINVAL : 0;
		return ret;
	}

	*num_planes = 1;
	sizes[0] = size;

	return 0;
}

static int vcam_buf_init(struct vb2_buffer *vb)
{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_camera_buffer *vbuf = vb_to_vcam_buf(vb);
	struct virtio_camera_mem_entry *ents;
	struct virtio_camera_ctrl_req *vcam_req;
	struct scatterlist *sg;
	struct sg_table *sgt;
	unsigned int i;
	int err;

	/* TODO */
	if (WARN_ON(vb->num_planes != 1))
		return -EINVAL;

	sgt = vb2_dma_sg_plane_desc(vb, 0);
	ents = kmalloc_array(sgt->nents, sizeof(*ents), GFP_KERNEL);
	if (!ents)
		return -ENOMEM;

	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		ents[i].addr = cpu_to_le64(sg_phys(sg));
		ents[i].length = cpu_to_le32(sg->length);
	}

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_CREATE_BUFFER);
	if (unlikely(vcam_req == NULL)) {
		pr_err("%s: Fail to init the virtio-camera request buffer\n", __func__);
		err = -ENOMEM;
		goto err_free;
	}

	vcam_req->ctrl.u.buffer.num_entries = sgt->nents;

	err = vcam_vq_request(vnode, vcam_req, ents, sgt->nents, false);
	if (err)
		goto err_free;

	memcpy(vbuf->uuid, vcam_req->resp.u.buffer.uuid, sizeof(vbuf->uuid));

	vcam_req->vb = vb;

err_free:
	kfree(ents);
	kfree(vcam_req);
	return err;
}

static void vcam_buf_cleanup(struct vb2_buffer *vb)
{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_camera_buffer *vbuf = vb_to_vcam_buf(vb);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_DESTROY_BUFFER);
	if (unlikely(vcam_req == NULL)) {
		pr_err("%s: Failed to clean vcam buffer\n", __func__);
		return;
	}

	memcpy(vcam_req->ctrl.u.buffer.uuid, vbuf->uuid, sizeof(vbuf->uuid));
	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err) {
	     pr_err("%s: Failed to deinit virtio-camera buffers, buffers may still be retained by backend\n",
		     __func__);
	}
	kfree(vcam_req);
}

static int vcam_buf_prepare(struct vb2_buffer *vb)
{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(vb->vb2_queue);

	vb2_set_plane_payload(vb, 0, vnode->format.fmt.pix.sizeimage);

	return 0;
}

static void vcam_buf_queue(struct vb2_buffer *vb)
{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(vb->vb2_queue);
	struct virtio_camera_buffer *vbuf = vb_to_vcam_buf(vb);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_ENQUEUE_BUFFER);
	if (unlikely(vcam_req == NULL)) {
		pr_err("%s: Failed to queue a vcam buffer\n", __func__);
		return;
	}

	memcpy(vcam_req->ctrl.u.buffer.uuid, vbuf->uuid, sizeof(vbuf->uuid));
	vcam_req->vb = vb;
	err = vcam_vq_request(vnode, vcam_req, NULL, 0, true);
	if (err) {
		vb2_buffer_done(vb, VB2_BUF_STATE_ERROR);
		goto err_free;
	}

	pr_debug("virtio-camera: qbuf, video idx is %d. UUID is %d, ptr is %pK\n",
	vnode->idx, vcam_req->resp.u.buffer.uuid[0] + vcam_req->resp.u.buffer.uuid[1],
	 vcam_req->vb);
	return;

err_free:
	kfree(vcam_req);
}

static int vcam_start_streaming(struct vb2_queue *q, unsigned int count)
{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(q);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vnode->sequence = 0;
	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_STREAM_ON);
	if (unlikely(vcam_req == NULL))
		return -ENOMEM;

	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		pr_err("%s: Failed to start streaming, err response\n", __func__);

	kfree(vcam_req);
	return err;
}

static void vcam_stop_streaming(struct vb2_queue *q)
{
	struct virtio_camera_video *vnode = vb2_get_drv_priv(q);
	struct virtio_camera_ctrl_req *vcam_req;
	int err;

	vcam_req = virtio_camera_create_req(VIRTIO_CAMERA_CMD_STREAM_OFF);
	if (unlikely(vcam_req == NULL)) {
		pr_err("%s: Failed to stop streaming\n", __func__);
		return;
	}

	/*TODO, mark all vcam buffers invalid when err occur*/
	err = vcam_vq_request(vnode, vcam_req, NULL, 0, false);
	if (err)
		pr_err("%s: Failed to stop streaming, err response\n", __func__);

	vb2_wait_for_all_buffers(q);
	kfree(vcam_req);
}

static const struct vb2_ops vcam_vb2_ops = {
	.queue_setup = vcam_queue_setup,
	.wait_prepare = vb2_ops_wait_prepare,
	.wait_finish = vb2_ops_wait_finish,
	.buf_init = vcam_buf_init,
	.buf_queue = vcam_buf_queue,
	.buf_cleanup = vcam_buf_cleanup,
	.buf_prepare = vcam_buf_prepare,
	.start_streaming = vcam_start_streaming,
	.stop_streaming = vcam_stop_streaming,
};

static void delete_vqs(void *data)
{
	struct virtio_device *vdev = data;

	vdev->config->del_vqs(vdev);
}

/* Initialize virtqueues */
static int virtio_camera_setup_vqs(struct virtio_device *vdev,
				struct virtio_camera *vcam)
{
	struct virtqueue **vqs;
	vq_callback_t **callbacks;
	const char **names;
	unsigned int i, nvqs = 0;
	int ret = 0;

	if (vcam->config.num_virtual_cameras == 0)
		return -EINVAL;

	for (i = 0; i < vcam->config.num_virtual_cameras; i++)
		nvqs +=  vcam->config.nr_per_virtual_camera[i];

	vcam->vqs = devm_kzalloc(&vdev->dev,
			    nvqs * sizeof(struct virtio_camera_vq),
			    GFP_KERNEL);
	if (!vcam->vqs) {
		pr_err("%s: virtio_camera failed alloc mem.\n", __func__);
		return -ENOMEM;
	}

	vcam->nvqs = nvqs;

	vqs = kmalloc_array(vcam->nvqs, sizeof(vqs[0]), GFP_KERNEL);
	callbacks = kmalloc_array(vcam->nvqs, sizeof(callbacks[0]),
					GFP_KERNEL);
	names = kmalloc_array(vcam->nvqs, sizeof(names[0]), GFP_KERNEL);
	if (!vqs || !callbacks || !names) {
		pr_err("%s: virtio_camera failed alloc mem.\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	/* Initialize the requests virtqueues */
	for (i = 0; i < vcam->nvqs; i++) {
		snprintf(vcam->vqs[i].name, VQ_NAME_LEN, "control.%u", i);
		callbacks[i] = virtio_camera_control_ack;
		names[i] = vcam->vqs[i].name;
	}

	ret = virtio_find_vqs(vdev, vcam->nvqs, vqs, callbacks, names, NULL);
	if (ret < 0) {
		pr_err("%s: virtio_camera failed find vqs.\n", __func__);
		goto out;
	}

	for (i = 0; i < vcam->nvqs; i++) {
		vcam->vqs[i].vq = vqs[i];
		pr_debug("%s: setup vq %d, address is%pK\n", __func__, i, vqs[i]);
	}

out:
	kfree(names);
	kfree(callbacks);
	kfree(vqs);
	if (ret)
		kfree(vcam->vqs);
	return ret;
}

static int virtio_camera_unregister_devs(struct virtio_camera *vcam,
	int virt_cameras_idx, int vnodes_idx)
{
	struct virtual_camera *virt_camera;
	unsigned int i, j;

	if (virt_cameras_idx >= vcam->config.num_virtual_cameras)
		return -EINVAL;

	if (vnodes_idx >= vcam->virtual_cameras[virt_cameras_idx].nr_videos)
		return -EINVAL;

	for (i = 0; i < virt_cameras_idx; i++) {
		virt_camera = &vcam->virtual_cameras[i];
		for (j = 0; j < virt_camera->nr_videos; j++)
			video_unregister_device(&virt_camera->vnodes[j].vdev);
		v4l2_device_unregister(&virt_camera->v4l2_dev);
	}

	virt_camera = &vcam->virtual_cameras[virt_cameras_idx];
	for (j = 0; j <= vnodes_idx; j++)
		video_unregister_device(&virt_camera->vnodes[j].vdev);
	v4l2_device_unregister(&vcam->virtual_cameras[i].v4l2_dev);

	return 0;
}

static int virtio_camera_setup_vnode(struct virtio_device *vdev,
				struct virtio_camera *vcam)
{
	struct virtual_camera *virt_camera;
	struct virtio_camera_video *vnode;
	unsigned int i, j, vq_idx = 0;
	int err;

	vcam->virtual_cameras = devm_kzalloc(&vdev->dev,
				vcam->config.num_virtual_cameras * sizeof(*virt_camera),
				GFP_KERNEL);
	if (!vcam->virtual_cameras)
		return -ENOMEM;

	for (i = 0; i < vcam->config.num_virtual_cameras; i++) {
		virt_camera = &vcam->virtual_cameras[i];
		virt_camera->vnodes = devm_kzalloc(&vdev->dev,
					vcam->config.nr_per_virtual_camera[i] * sizeof(*vnode),
					GFP_KERNEL);
		if (!virt_camera->vnodes)
			return -ENOMEM;

		virt_camera->nr_videos = vcam->config.nr_per_virtual_camera[i];
		mutex_init(&virt_camera->v4l2_lock);
		media_device_init(&virt_camera->mdev);

		err = v4l2_device_register(&vdev->dev, &virt_camera->v4l2_dev);
		if (err) {
			if (i > 0)
				virtio_camera_unregister_devs(vcam, i-1, virt_camera->nr_videos-1);
			return dev_err_probe(&vdev->dev, err, "failed to register v4l2 device\n");
		}

		for (j = 0; j < vcam->config.nr_per_virtual_camera[i]; j++) {
			vnode = &vcam->virtual_cameras[i].vnodes[0];
			video_set_drvdata(&vnode->vdev, vnode);
			mutex_init(&vnode->video_lock);
			vnode->vdev.queue = &vnode->vb_queue;
			vnode->vdev.lock = &vnode->video_lock,
			vnode->vdev.fops = &vcam_v4l2_fops,
			vnode->vdev.vfl_dir = VFL_DIR_RX,
			vnode->vdev.release = video_device_release_empty,
			vnode->vdev.v4l2_dev = &vcam->virtual_cameras[i].v4l2_dev;
			vnode->vdev.ioctl_ops = &vcam_ioctl_ops,
			vnode->vdev.device_caps = V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_STREAMING;

			vnode->vb_queue.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
			vnode->vb_queue.buf_struct_size = sizeof(struct virtio_camera_buffer);
			vnode->vb_queue.timestamp_flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC;
			vnode->vb_queue.io_modes = VB2_MMAP | VB2_DMABUF;
			vnode->vb_queue.mem_ops = &vb2_dma_sg_memops;
			vnode->vb_queue.lock = &vnode->video_lock;
			vnode->vb_queue.min_buffers_needed = 1;
			vnode->vb_queue.gfp_flags = GFP_DMA32;
			vnode->vb_queue.ops = &vcam_vb2_ops;
			vnode->vb_queue.dev = vdev->dev.parent;
			vnode->vb_queue.drv_priv = vnode;

			vnode->idx = i;
			err = vb2_queue_init(&vnode->vb_queue);
			if (err) {
				virtio_camera_unregister_devs(vcam, i, j-1);
				return dev_err_probe(&vdev->dev, err, "failed to init vb2 queue");
			}

			vnode->ctr_vqx = &vcam->vqs[vq_idx++];

			err = video_register_device(&vnode->vdev, VFL_TYPE_VIDEO, -1);

			if (err) {
				virtio_camera_unregister_devs(vcam, i, j-1);
				return dev_err_probe(&vdev->dev, err, "failed to register video");
			}
		}
	}

	pr_info("%s: success register video devices\n", __func__);
	return 0;
}

static int virtio_camera_probe(struct virtio_device *vdev)
{
	struct virtio_camera *vcam;
	int err, i;

	vcam = devm_kzalloc(&vdev->dev, sizeof(*vcam), GFP_KERNEL);
	if (!vcam)
		return -ENOMEM;

	vdev->priv = vcam;

	virtio_cread_bytes(vdev, 0, &vcam->config, sizeof(vcam->config));

	if (vcam->config.num_virtual_cameras > ARRAY_SIZE(vcam->config.nr_per_virtual_camera)) {
		pr_err("%s: nr cameras too large %d", __func__, vcam->config.num_virtual_cameras);
		return -EINVAL;
	}

	for (i = 0; i < vcam->config.num_virtual_cameras; i++)
		vcam->config.nr_per_virtual_camera[i] = 1;

	err = virtio_camera_setup_vqs(vdev, vcam);
	if (err)
		goto out;

	err = virtio_camera_setup_vnode(vdev, vcam);
	if (err)
		goto out_vqs;

	err = devm_add_action_or_reset(&vdev->dev, delete_vqs, vdev);
	if (err)
		goto out_vqs;

	return 0;

out_vqs:
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

out:
	pr_err("Failed to probe virtio-camera device\n");
	vdev->priv = NULL;
	return err;
}

static void virtio_camera_remove(struct virtio_device *vdev)
{
	struct virtio_camera *vcam = vdev->priv;
	int i, j;

	for (i = 0; i < vcam->config.num_virtual_cameras; i++) {
		for (j = 0; j < vcam->config.nr_per_virtual_camera[i]; j++)
			video_unregister_device(&vcam->virtual_cameras[i].vnodes[j].vdev);

		v4l2_device_unregister(&vcam->virtual_cameras[i].v4l2_dev);
	}

	virtio_break_device(vdev);
	vdev->config->reset(vdev);
}

static const unsigned int features[] = {
	/* none */
};

static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_CAMERA, VIRTIO_DEV_ANY_ID },
	{},
};
MODULE_DEVICE_TABLE(virtio, id_table);

static struct virtio_driver virtio_camera_driver = {
	.feature_table_size = ARRAY_SIZE(features),
	.feature_table = features,
	.probe = virtio_camera_probe,
	.remove = virtio_camera_remove,
	.driver.name = "virtio-camera",
	.id_table = id_table,
};
module_virtio_driver(virtio_camera_driver);

MODULE_AUTHOR("Dmitry Osipenko <dmitry.osipenko@collabora.com>");
MODULE_AUTHOR("Zhangwei6 <wei6.zhang@intel.com>");
MODULE_DESCRIPTION("virtio camera device driver");
MODULE_LICENSE("GPL");
