// SPDX-License-Identifier: (MIT OR GPL-2.0)

/*
 * Copyright © 2021 2025 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Dongwon Kim <dongwon.kim@intel.com>
 *    Mateusz Polrola <mateusz.polrola@gmail.com>
 *    Vivek Kasireddy <vivek.kasireddy@intel.com>
 *    Xue Bosheng <bosheng.xue@intel.com>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/dma-buf.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_vdmabuf.h>

MODULE_IMPORT_NS(DMA_BUF);

struct virtio_vdmabuf_config {
	uint64_t vmid;
} __attribute__((packed));

#define VIRTIO_VDMABUF_MAX_ID INT_MAX
#define REFS_PER_PAGE (PAGE_SIZE / sizeof(long))
#define NEW_BUF_ID_GEN(vmid, cnt) \
	(((vmid & 0xFFFFFFFF) << 32) | ((cnt) & 0xFFFFFFFF))

/* one global drv object */
static struct virtio_vdmabuf_info *drv_info;

struct virtio_vdmabuf {
	/* virtio device structure */
	struct virtio_device *vdev;

	/* virtual queue array */
	struct virtqueue *vqs[VDMABUF_VQ_MAX];

	/* ID of guest OS */
	u64 vmid;

	/* spin lock that needs to be acquired before accessing
	 * virtual queue
	 */
	spinlock_t vq_lock;
	struct mutex recv_lock;
	struct mutex send_lock;

	spinlock_t msg_lock;
	struct list_head msg_list;

	/* workqueue */
	struct workqueue_struct *wq;
	struct work_struct recv_work;
	struct work_struct send_work;

	struct virtio_shm_region host_visible_region;
	uint64_t bar_addr;
};

struct virtio_vdmabuf_be {
	struct virtio_vdmabuf *vdmabuf;
	struct list_head list;
	struct virtio_vdmabuf_event_queue *evq;
	struct kref ref;
	int role;
};

static inline bool vhost_client_add(struct virtio_vdmabuf_be *new)
{
	unsigned long flags;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_add_tail(&new->list, &drv_info->head_client_list);
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
	return 0;
}

static inline int vhost_client_delete(struct virtio_vdmabuf_be *be)
{
	struct virtio_vdmabuf_be *iter, *temp;
	unsigned long flags;
	int ret = false;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_for_each_entry_safe(iter, temp, &drv_info->head_client_list, list)
		if (iter == be) {
			list_del(&iter->list);
			ret = true;
			break;
		}
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
	return ret;
}

static inline struct virtio_vdmabuf_be *vhost_client_found_consumer(void)
{
       unsigned long flags;
       struct virtio_vdmabuf_be *found = NULL;
       bool hit = false;
       spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
       list_for_each_entry(found, &drv_info->head_client_list, list)
	if ((found->role & VDMABUF_CONSUMER)) {
			if (kref_get_unless_zero(&found->ref)) {
				hit = true;
				break;
			}
		}
       spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
       if (hit)
		return found;
	else
		return NULL;
}

static void client_free(struct kref *kref)
{
	struct virtio_vdmabuf_be *client;
	struct virtio_vdmabuf_event *e, *et;
	client = container_of(kref, typeof(*client), ref);
	list_for_each_entry_safe(e, et, &client->evq->e_list, link) {
		list_del(&e->link);
		if (e->e_data.data)
			kfree(e->e_data.data);
		kfree(e);
		client->evq->pending--;
	}

	if (client->evq)
		kfree(client->evq);
	kfree(client);
}

static void get_client(struct virtio_vdmabuf_be *client)
{
	if (client) {
		kref_get(&client->ref);
	}
}
static void put_client(struct virtio_vdmabuf_be *client)
{
	if (client) {
		kref_put(&client->ref, client_free);
	}
}

static virtio_vdmabuf_buf_id_t get_buf_id(struct virtio_vdmabuf *vdmabuf)
{
	virtio_vdmabuf_buf_id_t buf_id = { 0, { 0, 0 } };
	static int count = 0;

	count = count < VIRTIO_VDMABUF_MAX_ID ? count + 1 : 0;
	buf_id.id = NEW_BUF_ID_GEN(vdmabuf->vmid, count);

	/* random data embedded in the id for security */
	get_random_bytes(&buf_id.rng_key[0], 8);

	return buf_id;
}

/* stop sharing pages */
static void
virtio_vdmabuf_free_buf(struct virtio_vdmabuf_shared_pages *pages_info)
{
	if (!pages_info)
		return;
	int n_l2refs = (pages_info->nents / REFS_PER_PAGE +
			((pages_info->nents % REFS_PER_PAGE) ? 1 : 0));

	if (pages_info->l2refs)
		free_pages((u64)pages_info->l2refs,
			   get_order(n_l2refs * PAGE_SIZE));
	if (pages_info->l3refs)
		free_page((u64)pages_info->l3refs);
}

static int send_msg_to_host(enum virtio_vdmabuf_cmd cmd, int *op)
{
	struct virtio_vdmabuf *vdmabuf = drv_info->priv;
	struct virtio_vdmabuf_msg *msg;
	unsigned long flags;

	switch (cmd) {
	case VIRTIO_VDMABUF_CMD_EXPORT:
		msg = kvcalloc(1, sizeof(struct virtio_vdmabuf_msg),
			       GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		memcpy(&msg->op[0], &op[0], 10 * sizeof(int) + op[9]);
		break;
	case VIRTIO_VDMABUF_CMD_DMABUF_REL:
		msg = kvcalloc(1, sizeof(struct virtio_vdmabuf_msg),
			       GFP_KERNEL);
		if (!msg)
			return -ENOMEM;
		memcpy(&msg->op[0], &op[0], 8 * sizeof(int));
		break;
	case VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT:
		msg = kvcalloc(1, sizeof(struct virtio_vdmabuf_msg),
			       GFP_KERNEL);
		if (!msg)
			return -ENOMEM;
		memcpy(&msg->op[0], &op[0], 8 * sizeof(int));
		break;
	default:
		/* no command found */
		return -EINVAL;
	}

	msg->cmd = cmd;
	spin_lock_irqsave(&vdmabuf->msg_lock, flags);
	list_add_tail(&msg->list, &vdmabuf->msg_list);
	spin_unlock_irqrestore(&vdmabuf->msg_lock, flags);
	queue_work(vdmabuf->wq, &vdmabuf->send_work);

	return 0;
}

static void vbuf_free(struct kref *kref)
{
	struct virtio_vdmabuf_buf *vbuf;
	vbuf = container_of(kref, typeof(*vbuf), ref);
	vbuf->valid = false;
	dev_dbg(drv_info->dev, "vdmabuf: free vbuf:%p, is_export:%d\n", vbuf, vbuf->is_export);
	virtio_vdmabuf_del_buf(drv_info, &vbuf->buf_id);
	virtio_vdmabuf_free_buf(vbuf->pages_info);

	if (vbuf->attach)
		dma_buf_unmap_attachment(vbuf->attach, vbuf->sgt,
					 DMA_BIDIRECTIONAL);

	if (vbuf->dma_buf && vbuf->attach) {
		dma_buf_detach(vbuf->dma_buf, vbuf->attach);
		dma_buf_put(vbuf->dma_buf);
		vbuf->dma_buf = NULL;
		vbuf->attach = NULL;
	}
	if (vbuf->pages_info)
		kvfree(vbuf->pages_info);
	if (vbuf->priv)
		kvfree(vbuf->priv);
	kvfree(vbuf);
}

__attribute__((unused))
static void get_vbuf(struct virtio_vdmabuf_buf *vbuf)
{
	if (vbuf) {
		kref_get(&vbuf->ref);
	}
}
static void put_vbuf(struct virtio_vdmabuf_buf *vbuf)
{
	if (vbuf) {
		kref_put(&vbuf->ref, vbuf_free);
	}
}

/* sharing pages for original DMABUF with Host */
static struct virtio_vdmabuf_shared_pages *
virtio_vdmabuf_share_buf(struct page **pages, int nents, int first_ofst,
			 int last_len)
{
	struct virtio_vdmabuf_shared_pages *pages_info;
	int i;
	int n_l2refs =
		nents / REFS_PER_PAGE + ((nents % REFS_PER_PAGE) ? 1 : 0);

	pages_info = kvcalloc(1, sizeof(*pages_info), GFP_KERNEL);
	if (!pages_info)
		return NULL;

	pages_info->pages = pages;
	pages_info->nents = nents;
	pages_info->first_ofst = first_ofst;
	pages_info->last_len = last_len;
	pages_info->l3refs = (u64 *)__get_free_page(GFP_KERNEL);

	if (!pages_info->l3refs) {
		kvfree(pages_info);
		return NULL;
	}

	pages_info->l2refs = (u64 **)__get_free_pages(
		GFP_KERNEL, get_order(n_l2refs * PAGE_SIZE));

	if (!pages_info->l2refs) {
		free_page((u64)pages_info->l3refs);
		kvfree(pages_info);
		return NULL;
	}

	/* Share physical address of pages */
	for (i = 0; i < nents; i++)
		pages_info->l2refs[i] = (u64 *)page_to_phys(pages[i]);

	for (i = 0; i < n_l2refs; i++)
		pages_info->l3refs[i] = virt_to_phys(
			(void *)pages_info->l2refs + i * PAGE_SIZE);

	pages_info->ref = (u64)virt_to_phys(pages_info->l3refs);

	return pages_info;
}

static void virtio_vdmabuf_clear_buf(struct virtio_vdmabuf_buf *exp)
{
	/* Start cleanup of buffer in reverse order to exporting */
	virtio_vdmabuf_free_buf(exp->pages_info);

	if (exp->attach)
		dma_buf_unmap_attachment(exp->attach, exp->sgt, DMA_BIDIRECTIONAL);

	if (exp->dma_buf && exp->attach) {
		dma_buf_detach(exp->dma_buf, exp->attach);
		/* close connection to dma-buf completely */
		dma_buf_put(exp->dma_buf);
		exp->dma_buf = NULL;
	}
}

static int remove_buf(struct virtio_vdmabuf_buf *exp)
{
	int ret;

	virtio_vdmabuf_clear_buf(exp);

	ret = virtio_vdmabuf_del_buf(drv_info, &exp->buf_id);
	if (ret)
		return ret;

	if (exp->sz_priv > 0 && !exp->priv)
		kvfree(exp->priv);
	if (exp->pages_info)
		kvfree(exp->pages_info);
	kvfree(exp);
	return 0;
}

static void virtio_vdmabuf_fill_recv_msg(struct virtio_vdmabuf *vdmabuf)
{
	struct virtqueue *vq = vdmabuf->vqs[VDMABUF_VQ_RECV];
	struct scatterlist sg;
	struct virtio_vdmabuf_msg *msg;
	int ret;

	msg = kvzalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return;

	sg_init_one(&sg, msg, sizeof(struct virtio_vdmabuf_msg));
	ret = virtqueue_add_inbuf(vq, &sg, 1, msg, GFP_KERNEL);
	if (ret)
		return;

	virtqueue_kick(vq);
}

static int parse_msg_from_host(struct virtio_vdmabuf *vdmabuf,
			       struct virtio_vdmabuf_msg *msg)
{
	struct virtio_vdmabuf_buf *exp;
	virtio_vdmabuf_buf_id_t buf_id;
	dev_dbg(drv_info->dev, "vdmabuf: parse msg cmd:%d\n", msg->cmd);
	switch (msg->cmd) {
	case VIRTIO_VDMABUF_CMD_DMABUF_REL:
		memcpy(&buf_id, msg->op, sizeof(buf_id));

		exp = virtio_vdmabuf_find_buf(drv_info, &buf_id);
		if (!exp) {
			dev_dbg(drv_info->dev, "vdmabuf rel: can't find buffer\n");
		} else {
			put_vbuf(exp);
		}

		break;
	default:
		dev_err(drv_info->dev, "empty cmd\n");
		return -EINVAL;
	}

	return 0;
}

static void virtio_vdmabuf_recv_work(struct work_struct *work)
{
	struct virtio_vdmabuf *vdmabuf =
		container_of(work, struct virtio_vdmabuf, recv_work);
	struct virtqueue *vq = vdmabuf->vqs[VDMABUF_VQ_RECV];
	struct virtio_vdmabuf_msg *msg;
	int sz;

	mutex_lock(&vdmabuf->recv_lock);

	do {
		virtqueue_disable_cb(vq);
		for (;;) {
			msg = virtqueue_get_buf(vq, &sz);
			if (!msg)
				break;

			/* valid size */
			if (sz == sizeof(struct virtio_vdmabuf_msg)) {
				if (parse_msg_from_host(vdmabuf, msg))
					dev_err(drv_info->dev,
						"msg parse error\n");

				kvfree(msg);
			} else {
				dev_err(drv_info->dev,
					"received malformed message\n");
			}
		}
	} while (!virtqueue_enable_cb(vq));

	mutex_unlock(&vdmabuf->recv_lock);
}

static void virtio_vdmabuf_send_msg_work(struct work_struct *work)
{
	struct virtio_vdmabuf *vdmabuf =
		container_of(work, struct virtio_vdmabuf, send_work);
	struct virtqueue *vq = vdmabuf->vqs[VDMABUF_VQ_SEND];
	struct scatterlist sg;
	struct virtio_vdmabuf_msg *msg;
	bool added = false;
	unsigned long flags;
	int ret;
	int sz;
 
 	mutex_lock(&vdmabuf->send_lock);
	do {
		virtqueue_disable_cb(vq);
		for (;;) {
			msg = virtqueue_get_buf(vq, &sz);
			if (!msg)
				break;

			kvfree(msg);
		}
	} while (!virtqueue_enable_cb(vq));
	mutex_unlock(&vdmabuf->send_lock);

	for (;;) {
		spin_lock_irqsave(&vdmabuf->msg_lock, flags);
		if (list_empty(&vdmabuf->msg_list)) {
			spin_unlock_irqrestore(&vdmabuf->msg_lock, flags);
			break;
		}

		msg = list_first_entry(&vdmabuf->msg_list,
				       struct virtio_vdmabuf_msg, list);
		list_del_init(&msg->list);
		spin_unlock_irqrestore(&vdmabuf->msg_lock, flags);

		if (msg->cmd == VIRTIO_VDMABUF_CMD_EXPORT) {
			mutex_lock(&vdmabuf->recv_lock);
			virtio_vdmabuf_fill_recv_msg(
				vdmabuf); // for sos to gos rel buf event
			mutex_unlock(&vdmabuf->recv_lock);
		}

		sg_init_one(&sg, msg, sizeof(struct virtio_vdmabuf_msg));
		mutex_lock(&vdmabuf->send_lock);
		ret = virtqueue_add_outbuf(vq, &sg, 1, msg, GFP_KERNEL);
		if (ret < 0) {
			mutex_unlock(&vdmabuf->send_lock);
			dev_err(drv_info->dev, "failed to add msg to vq, ret:%d\n", ret);
			break;
		}
		mutex_unlock(&vdmabuf->send_lock);

		added = true;
	}

	if (added) {
		mutex_lock(&vdmabuf->send_lock);
		virtqueue_kick(vq);
		mutex_unlock(&vdmabuf->send_lock);
	}
}

static void virtio_vdmabuf_recv_cb(struct virtqueue *vq)
{
	struct virtio_vdmabuf *vdmabuf = vq->vdev->priv;

	if (!vdmabuf)
		return;

	queue_work(vdmabuf->wq, &vdmabuf->recv_work);
}

static void virtio_vdmabuf_send_cb(struct virtqueue *vq)
{
	struct virtio_vdmabuf *vdmabuf = vq->vdev->priv;

	if (!vdmabuf)
		return;

	queue_work(vdmabuf->wq, &vdmabuf->send_work);
}

static int remove_all_bufs(struct virtio_vdmabuf *vdmabuf)
{
	struct virtio_vdmabuf_buf *found;
	struct hlist_node *tmp;
	int bkt;
	int ret;

	hash_for_each_safe(drv_info->buf_list, bkt, tmp, found, node) {
		ret = remove_buf(found);
		if (ret)
			return ret;
	}

	return 0;
}

static struct sg_table *
virtio_vdmabuf_map_dmabuf(struct dma_buf_attachment *attachment,
			  enum dma_data_direction dir)
{
	struct virtio_vdmabuf_buf *exp_buf;
	struct sg_table *sgt;
	struct scatterlist *sgl;
	int i, ret;

	if (!attachment->dmabuf || !attachment->dmabuf->priv)
		return ERR_PTR(-EINVAL);

	exp_buf = attachment->dmabuf->priv;

	sgt = kvzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(sgt, exp_buf->pages_info->nents, GFP_KERNEL);
	if (ret) {
		kvfree(sgt);
		return ERR_PTR(ret);
	}

	sgl = sgt->sgl;
	for (i = 0; i < exp_buf->pages_info->nents; i++) {
		sg_set_page(sgl, exp_buf->pages_info->pages[i], PAGE_SIZE, 0);
		sgl = sg_next(sgl);
	}

	if (!dma_map_sg(attachment->dev, sgt->sgl, sgt->nents, dir)) {
		sg_free_table(sgt);
		kvfree(sgt);
		return ERR_PTR(-EINVAL);
	}

	return sgt;
}

static int virtio_vdmabuf_mmap_dmabuf(struct dma_buf *dmabuf,
				      struct vm_area_struct *vma)
{
	struct virtio_vdmabuf_buf *exp_buf;
	u64 uaddr;
	int i, ret = 0;

	if (!dmabuf->priv)
		return -EINVAL;

	exp_buf = dmabuf->priv;

	if (!exp_buf->pages_info)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	uaddr = vma->vm_start;
	for (i = 0; i < exp_buf->pages_info->nents; i++) {
		ret = vm_insert_page(vma, uaddr, exp_buf->pages_info->pages[i]);
		if (ret)
			return ret;

		uaddr += PAGE_SIZE;
	}

	return 0;
}

static void virtio_vdmabuf_unmap_dmabuf(struct dma_buf_attachment *attachment,
					struct sg_table *sgt,
					enum dma_data_direction dir)
{
	dma_unmap_sg(attachment->dev, sgt->sgl, sgt->nents, dir);

	sg_free_table(sgt);
	kvfree(sgt);
}

static void virtio_vdmabuf_release_dmabuf(struct dma_buf *dmabuf)
{
	struct virtio_vdmabuf_buf *exp_buf = dmabuf->priv;
	int i;

	for (i = 0; i < exp_buf->pages_info->nents; i++)
		put_page(exp_buf->pages_info->pages[i]);

	virtio_vdmabuf_del_buf(drv_info, &exp_buf->buf_id);
	put_vbuf(exp_buf);
}

static const struct dma_buf_ops virtio_vdmabuf_dmabuf_ops = {
	.map_dma_buf = virtio_vdmabuf_map_dmabuf,
	.unmap_dma_buf = virtio_vdmabuf_unmap_dmabuf,
	.release = virtio_vdmabuf_release_dmabuf,
	.mmap = virtio_vdmabuf_mmap_dmabuf,
};

static int virtio_vdmabuf_create_dmabuf(struct virtio_vdmabuf *vdmabuf,
					uint64_t bo_size)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct virtio_vdmabuf_buf *exp_buf;
	struct dma_buf *dmabuf;
	uint32_t num_pages = DIV_ROUND_UP(bo_size, PAGE_SIZE);
	int i, j, ret;

	exp_buf = kvzalloc(sizeof(*exp_buf), GFP_KERNEL);
	if (!exp_buf)
		goto err_exp;
	kref_init(&exp_buf->ref);
	exp_buf->pages_info =
		kvzalloc(sizeof(*(exp_buf->pages_info)), GFP_KERNEL);
	if (!exp_buf->pages_info)
		goto err_pages_info;

	exp_buf->pages_info->pages =
		kvzalloc(num_pages * sizeof(struct page *), GFP_KERNEL);
	if (!exp_buf->pages_info->pages)
		goto err_pages;

	exp_info.ops = &virtio_vdmabuf_dmabuf_ops;
	exp_info.size = num_pages * PAGE_SIZE;
	exp_info.flags = O_CLOEXEC | O_RDWR;
	exp_info.priv = exp_buf;

	for (i = 0; i < num_pages; i++) {
		exp_buf->pages_info->pages[i] =
			alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!exp_buf->pages_info->pages[i])
			goto err_alloc;
	}

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR_OR_NULL(dmabuf))
		goto err_alloc;

	ret = dma_buf_fd(dmabuf, 0);
	if (ret < 0)
		goto err_alloc;

	exp_buf->fd = ret;
	//	exp_buf->buf_id = get_buf_id(vdmabuf);
	exp_buf->pages_info->nents = num_pages;
	exp_buf->is_export = true;

	//	virtio_vdmabuf_add_buf(drv_info, exp_buf);

	return ret;

err_alloc:
	for (j = 0; j < i; j++)
		put_page(exp_buf->pages_info->pages[i]);
err_pages:
	kvfree(exp_buf->pages_info->pages);
err_pages_info:
	kvfree(exp_buf->pages_info);
err_exp:
	kvfree(exp_buf);

	return -ENOMEM;
}

static int virtio_vdmabuf_open(struct inode *inode, struct file *filp)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = NULL;
	if (!drv_info || !filp->private_data) {
		pr_err("virtio vdmabuf driver is not ready\n");
		return -EINVAL;
	}

	virtio_dmabuf = kzalloc(sizeof(*virtio_dmabuf), GFP_KERNEL);
	if (!virtio_dmabuf)
		return -ENOMEM;

	virtio_dmabuf->vdmabuf = drv_info->priv;
	filp->private_data = virtio_dmabuf;
	virtio_dmabuf->evq = kzalloc(sizeof(*(virtio_dmabuf->evq)), GFP_KERNEL);
	if (!virtio_dmabuf->evq) {
		kfree(virtio_dmabuf);
		return -ENOMEM;
	}
	mutex_init(&virtio_dmabuf->evq->e_readlock);
	spin_lock_init(&virtio_dmabuf->evq->e_lock);
	/* Initialize event queue */
	INIT_LIST_HEAD(&virtio_dmabuf->evq->e_list);
	init_waitqueue_head(&virtio_dmabuf->evq->e_wait);
	/* resetting number of pending events */
	virtio_dmabuf->evq->pending = 0;

	kref_init(&virtio_dmabuf->ref);
	vhost_client_add(virtio_dmabuf);

	return 0;
}

static void virtio_vdmabuf_unexport_exported_buf(struct virtio_vdmabuf_info *info,
					 struct file *filp)
{
	struct virtio_vdmabuf_buf *found = NULL;
	unsigned long flags;
	int i = 0;
	int op[65] = {0};
	int ret = 0;
	if (!info)
		return;
	spin_lock_irqsave(&info->buf_list_lock, flags);

	hash_for_each(info->buf_list, i, found, node) {
		if (found->filp == filp && !found->unexport && found->is_export) {
			found->unexport = true;
			memcpy(op, &found->buf_id, sizeof(found->buf_id));
			spin_unlock_irqrestore(&info->buf_list_lock, flags);
			ret = send_msg_to_host(VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT, op);
			if (ret < 0) {
				dev_err(drv_info->dev, "fail to send unexport cmd\n");
			}
			spin_lock_irqsave(&info->buf_list_lock, flags);
		}
	}
	spin_unlock_irqrestore(&info->buf_list_lock, flags);
}

static int virtio_vdmabuf_release(struct inode *inode, struct file *filp)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = NULL;
	virtio_dmabuf = filp->private_data;
	if (!virtio_dmabuf)
		return -1;
	dev_dbg(drv_info->dev, "release vhost client\n");
	virtio_vdmabuf_unexport_exported_buf(drv_info, filp);
	vhost_client_delete(virtio_dmabuf);
	put_client(virtio_dmabuf);
	return 0;
}

/* Notify Host about the new vdmabuf */
static int export_notify(struct virtio_vdmabuf_buf *exp)
{
	struct virtio_vdmabuf_shared_pages *pages_info = exp->pages_info;
	int *op;
	int ret;

	op = kvcalloc(1, sizeof(int) * 65, GFP_KERNEL);
	if (!op)
		return -ENOMEM;

	memcpy(op, &exp->buf_id, sizeof(exp->buf_id));

	op[4] = pages_info->nents;
	op[5] = pages_info->first_ofst;
	op[6] = pages_info->last_len;

	memcpy(&op[7], &pages_info->ref, sizeof(u64));
	op[9] = exp->sz_priv;

	/* driver/application specific private info */
	memcpy(&op[10], exp->priv, op[9]);

	ret = send_msg_to_host(VIRTIO_VDMABUF_CMD_EXPORT, op);

	kvfree(op);
	return ret;
}

static int num_pgs(struct sg_table *sgt)
{
	struct scatterlist *sgl;
	int len, i;
	/* at least one page */
	int n_pgs = 1;

	sgl = sgt->sgl;

	len = sgl->length - PAGE_SIZE + sgl->offset;

	/* round-up */
	n_pgs += ((len + PAGE_SIZE - 1) / PAGE_SIZE);

	for (i = 1; i < sgt->nents; i++) {
		sgl = sg_next(sgl);

		/* round-up */
		n_pgs += ((sgl->length + PAGE_SIZE - 1) /
			  PAGE_SIZE); /* round-up */
	}

	return n_pgs;
}

static struct page **extr_pgs(struct sg_table *sgt, int *nents, int *last_len)
{
	struct scatterlist *sgl;
	struct page **pages;
	struct page **temp_pgs;
	int i, j;
	int len;

	*nents = num_pgs(sgt);
	pages = kvmalloc_array(*nents, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return NULL;

	sgl = sgt->sgl;

	temp_pgs = pages;
	*temp_pgs++ = sg_page(sgl);
	len = sgl->length - PAGE_SIZE + sgl->offset;

	i = 1;
	while (len > 0) {
		*temp_pgs++ = nth_page(sg_page(sgl), i++);
		len -= PAGE_SIZE;
	}

	for (i = 1; i < sgt->nents; i++) {
		sgl = sg_next(sgl);
		*temp_pgs++ = sg_page(sgl);
		len = sgl->length - PAGE_SIZE;
		j = 1;

		while (len > 0) {
			*temp_pgs++ = nth_page(sg_page(sgl), j++);
			len -= PAGE_SIZE;
		}
	}

	*last_len = len + PAGE_SIZE;

	return pages;
}
static int unexport_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_unexport *attr = data;
	struct virtio_vdmabuf_buf *exp;
	int op[65] = {0};
	int ret = 0;

	if (vdmabuf->vmid <= 0)
		return -EINVAL;

	exp = virtio_vdmabuf_find_and_get_buf(drv_info, &attr->buf_id);
	if (!exp || !exp->valid) {
		dev_dbg(drv_info->dev, "unexport:no valid buf found with id = %llu\n",
			attr->buf_id.id);
		return -ENOENT;
	}

	exp->unexport = true;

	memcpy(op, &exp->buf_id, sizeof(exp->buf_id));

	ret = send_msg_to_host(VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT, op);
	if (ret < 0) {
		dev_err(drv_info->dev, "fail to send unexport cmd\n");
	}

	put_vbuf(exp);
	return ret;
}

static int export_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_export *attr = data;
	struct virtio_vdmabuf_buf *exp;
	struct dma_buf *dmabuf;
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct page **pages;
	int nents, last_len;
	int ret = 0;
	virtio_vdmabuf_buf_id_t buf_id;

	if (vdmabuf->vmid <= 0)
		return -EINVAL;

	dmabuf = dma_buf_get(attr->fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	buf_id = get_buf_id(vdmabuf);
	attach = dma_buf_attach(dmabuf, drv_info->dev);
	if (IS_ERR(attach)) {
		ret = PTR_ERR(attach);
		goto fail_attach;
	}

	sgt = dma_buf_map_attachment(attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(sgt)) {
		ret = PTR_ERR(sgt);
		goto fail_map_attachment;
	}

	exp = kvcalloc(1, sizeof(*exp), GFP_KERNEL);
	if (!exp) {
		ret = -ENOMEM;
		goto fail_sgt_info_creation;
	}
	kref_init(&exp->ref);
	/* possible truncation */
	if (attr->sz_priv > MAX_SIZE_PRIV_DATA)
		exp->sz_priv = MAX_SIZE_PRIV_DATA;
	else
		exp->sz_priv = attr->sz_priv;

	/* creating buffer for private data */
	if (exp->sz_priv != 0) {
		exp->priv = kvcalloc(1, exp->sz_priv, GFP_KERNEL);
		if (!exp->priv) {
			ret = -ENOMEM;
			goto fail_priv_creation;
		}
	}
	exp->buf_id = buf_id;
	exp->attach = attach;
	exp->sgt = sgt;
	exp->dma_buf = dmabuf;
	exp->size = dmabuf->size;
	exp->valid = true;

	if (exp->sz_priv) {
		/* copy private data to sgt_info */
		ret = copy_from_user(exp->priv, attr->priv, exp->sz_priv);
		if (ret) {
			ret = -EINVAL;
			goto fail_exp;
		}
	}
	pages = extr_pgs(sgt, &nents, &last_len);
	if (pages == NULL) {
		ret = -ENOMEM;
		goto fail_exp;
	}
	exp->pages_info = virtio_vdmabuf_share_buf(pages, nents,
						   sgt->sgl->offset, last_len);

	if (!exp->pages_info) {
		ret = -ENOMEM;
		goto fail_create_pages_info;
	}

	exp->data_priv = vdmabuf;
	ret = export_notify(exp);
	if (ret < 0)
		goto fail_send_request;

	exp->is_export = true;
	memcpy(&attr->buf_id, &exp->buf_id, sizeof(virtio_vdmabuf_buf_id_t));
	virtio_vdmabuf_add_buf(drv_info, exp);
	exp->filp = filp;

	return ret;

fail_send_request:
	virtio_vdmabuf_free_buf(exp->pages_info);
	kvfree(exp->pages_info);

fail_create_pages_info:
	kvfree(pages);

fail_exp:
	kvfree(exp->priv);

fail_priv_creation:
	kvfree(exp);

fail_sgt_info_creation:
	dma_buf_unmap_attachment(attach, sgt, DMA_BIDIRECTIONAL);

fail_map_attachment:
	dma_buf_detach(dmabuf, attach);

fail_attach:
	dma_buf_put(dmabuf);

	return ret;
}

static int alloc_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_alloc *attr = data;
	int ret;

	ret = virtio_vdmabuf_create_dmabuf(vdmabuf, attr->size);
	if (ret < 0)
		return ret;

	attr->fd = ret;

	return ret;
}

static int query_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_query_bufinfo *attr = data;
	struct virtio_vdmabuf_buf *exp;
	int ret = 0;
	if (vdmabuf->vmid <= 0)
		return -EINVAL;

	exp = virtio_vdmabuf_find_and_get_buf(drv_info, &attr->buf_id);
	if (!exp || !exp->valid) {
		dev_dbg(drv_info->dev, "query:no valid buf found with id = %llu\n",
			attr->buf_id.id);
		return -ENOENT;
	}
	if (attr->subcmd == VIRTIO_VDMABUF_QUERY_SIZE) {
		attr->info = exp->size;
	} else if (attr->subcmd == VIRTIO_VDMABUF_QUERY_PRIV_INFO_SIZE) {
		attr->info = exp->sz_priv;
	} else if (attr->subcmd == VIRTIO_VDMABUF_QUERY_PRIV_INFO) {
		if (exp->sz_priv) {
			if (!access_ok((void __user *)attr->info, exp->sz_priv)) {
				dev_err(drv_info->dev, "query ioctl, addr is not usable\n");
				ret = -EINVAL;
			}
			if (!ret) {
				if (copy_to_user((void __user *)attr->info,
							exp->priv, exp->sz_priv)) {
					dev_err(drv_info->dev, "query, copy failure\n");
					ret = -EFAULT;
				}
			}
		}
	}
	put_vbuf(exp);
	return ret;
}


static int role_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf_role *role =
		(struct virtio_vdmabuf_role *)data;

	if (role->role & VDMABUF_CONSUMER) {
		struct virtio_vdmabuf_be *client = NULL;
		client = vhost_client_found_consumer();
		if (client) {
			put_client(client);
			dev_dbg(drv_info->dev, "vdmabuf: duplicate consumer role\n");
			return -EINVAL;
		}
	}

	virtio_dmabuf->role = role->role;
	return 0;
}

static const struct virtio_vdmabuf_ioctl_desc virtio_vdmabuf_ioctls[] = {
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_ROLE, role_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_ALLOC_FD, alloc_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_EXPORT, export_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_UNEXPORT, unexport_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_QUERY_BUFINFO, query_ioctl, 0),
};

static long virtio_vdmabuf_ioctl(struct file *filp, unsigned int cmd,
				 unsigned long param)
{
	const struct virtio_vdmabuf_ioctl_desc *ioctl = NULL;
	int ret;
	virtio_vdmabuf_ioctl_t func = NULL;
	char *kdata;

	for (int i = 0; i < ARRAY_SIZE(virtio_vdmabuf_ioctls); i++) {
		ioctl = &virtio_vdmabuf_ioctls[i];
		if (ioctl->cmd == cmd) {
			func = ioctl->func;
			break;
		}
	}

	if ((!func)) {
		dev_err(drv_info->dev, "invalid ioctl, cmd:%d\n", cmd);
		return -EINVAL;
	}

	kdata = kvmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!kdata)
		return -ENOMEM;

	if (copy_from_user(kdata, (void __user *)param, _IOC_SIZE(cmd)) != 0) {
		dev_err(drv_info->dev, "failed to copy from user arguments\n");
		ret = -EFAULT;
		goto ioctl_error;
	}

	ret = func(filp, kdata);

	if (copy_to_user((void __user *)param, kdata, _IOC_SIZE(cmd)) != 0) {
		dev_err(drv_info->dev, "failed to copy to user arguments\n");
		ret = -EFAULT;
		goto ioctl_error;
	}

ioctl_error:
	kvfree(kdata);
	return ret;
}

static __poll_t virtio_vdmabuf_event_poll(struct file *filp,
					      struct poll_table_struct *wait)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;

	poll_wait(filp, &virtio_dmabuf->evq->e_wait, wait);
	if (!list_empty(&virtio_dmabuf->evq->e_list))
		return POLLIN | POLLRDNORM;

	return 0;
}

static ssize_t virtio_vdmabuf_event_read(struct file *filp, char __user *buf,
					 size_t cnt, loff_t *ofst)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	int ret;

	/* make sure user buffer can be written */
	if (!access_ok(buf, sizeof(*buf))) {
		dev_err(drv_info->dev, "user buffer can't be written.\n");
		return -EINVAL;
	}

	ret = mutex_lock_interruptible(&virtio_dmabuf->evq->e_readlock);
	if (ret)
		return ret;

	for (;;) {
		struct virtio_vdmabuf_event *e = NULL;

		spin_lock_irq(&virtio_dmabuf->evq->e_lock);
		if (!list_empty(&virtio_dmabuf->evq->e_list)) {
			e = list_first_entry(&virtio_dmabuf->evq->e_list,
					     struct virtio_vdmabuf_event, link);
			list_del(&e->link);
		}
		spin_unlock_irq(&virtio_dmabuf->evq->e_lock);

		if (!e) {
			if (ret)
				break;

			if (filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			mutex_unlock(&virtio_dmabuf->evq->e_readlock);
			ret = wait_event_interruptible(
				virtio_dmabuf->evq->e_wait,
				!list_empty(&virtio_dmabuf->evq->e_list));

			if (ret == 0)
				ret = mutex_lock_interruptible(
					&virtio_dmabuf->evq->e_readlock);

			if (ret)
				return ret;
		} else {
			unsigned int len =
				(sizeof(e->e_data.hdr) + e->e_data.hdr.size);

			if (len > cnt - ret) {
put_back_event:
				spin_lock_irq(&virtio_dmabuf->evq->e_lock);
				list_add(&e->link, &virtio_dmabuf->evq->e_list);
				spin_unlock_irq(&virtio_dmabuf->evq->e_lock);
				break;
			}

			if (copy_to_user(buf + ret, &e->e_data.hdr,
					 sizeof(e->e_data.hdr))) {
				if (ret == 0)
					ret = -EFAULT;

				goto put_back_event;
			}

			ret += sizeof(e->e_data.hdr);

			if (copy_to_user(buf + ret, e->e_data.data,
					 e->e_data.hdr.size)) {
				/* error while copying void *data */

				struct virtio_vdmabuf_e_hdr dummy_hdr = { 0 };

				ret -= sizeof(e->e_data.hdr);

				/* nullifying hdr of the event in user buffer */
				if (copy_to_user(buf + ret, &dummy_hdr,
						 sizeof(dummy_hdr)))
					dev_err(drv_info->dev,
						"fail to nullify invalid hdr\n");

				ret = -EFAULT;

				goto put_back_event;
			}

			ret += e->e_data.hdr.size;
			virtio_dmabuf->evq->pending--;
			if (e->e_data.data)
				kfree(e->e_data.data);
			kvfree(e);
		}
	}

	mutex_unlock(&virtio_dmabuf->evq->e_readlock);

	return ret;
}

static const struct file_operations virtio_vdmabuf_fops = {
	.owner = THIS_MODULE,
	.open = virtio_vdmabuf_open,
	.release = virtio_vdmabuf_release,
	.read = virtio_vdmabuf_event_read,
	.poll = virtio_vdmabuf_event_poll,
	.unlocked_ioctl = virtio_vdmabuf_ioctl,
};

static struct miscdevice virtio_vdmabuf_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "virtio-vdmabuf",
	.fops = &virtio_vdmabuf_fops,
};

static int virtio_vdmabuf_probe(struct virtio_device *vdev)
{
	uint64_t vmid = 0;
	char *addr;
	vq_callback_t *cbs[] = {
		virtio_vdmabuf_recv_cb,
		virtio_vdmabuf_send_cb,
	};
	static const char *const names[] = {
		"recv",
		"send",
	};
	struct virtio_vdmabuf *vdmabuf;
	int ret = 0;

	if (!drv_info)
		return -EINVAL;

	vdmabuf = drv_info->priv;

	if (!vdmabuf)
		return -EINVAL;

	vdmabuf->vdev = vdev;
	vdev->priv = vdmabuf;

	/* initialize spinlock for synchronizing virtqueue accesses */
	spin_lock_init(&vdmabuf->vq_lock);

	spin_lock_init(&vdmabuf->msg_lock);

	ret = virtio_find_vqs(vdmabuf->vdev, VDMABUF_VQ_MAX, vdmabuf->vqs, cbs,
			      names, NULL);
	if (ret) {
		dev_err(drv_info->dev, "Cannot find any vqs\n");
		return ret;
	}
	virtio_cread_le(vdev, struct virtio_vdmabuf_config, vmid, &vmid);
	vdmabuf->vmid = vmid;
	INIT_LIST_HEAD(&vdmabuf->msg_list);
	INIT_WORK(&vdmabuf->recv_work, virtio_vdmabuf_recv_work);
	INIT_WORK(&vdmabuf->send_work, virtio_vdmabuf_send_msg_work);

	virtio_vdmabuf_fill_recv_msg(vdmabuf);
	if (virtio_get_shm_region(vdev, &vdmabuf->host_visible_region, 1)) {
		if (!devm_request_mem_region(&vdev->dev,
					     vdmabuf->host_visible_region.addr,
					     vdmabuf->host_visible_region.len,
					     dev_name(&vdev->dev))) {
			dev_err(drv_info->dev, "vdmabuf: Could not reserve host visible region\n");
			ret = -EBUSY;
		}
		addr = devm_ioremap(&vdev->dev,
				    vdmabuf->host_visible_region.addr,
				    vdmabuf->host_visible_region.len);
		if (addr) {
			vdmabuf->bar_addr = (uint64_t)addr;
			dev_dbg(drv_info->dev, "vdmabuf: host addr:%llx remap addr:%p + %lld\n",
					vdmabuf->host_visible_region.addr, addr,
					vdmabuf->host_visible_region.len);
		}
	} else {
		dev_info(drv_info->dev, "vdmabuf: backend to frontend is not supported\n");
	}
	dev_info(drv_info->dev, "vdmabuf: probe device:%lld\n", vdmabuf->vmid);

	return ret;
}

static void virtio_vdmabuf_remove(struct virtio_device *vdev)
{
	struct virtio_vdmabuf *vdmabuf;

	if (!drv_info)
		return;
	dev_dbg(drv_info->dev, "vdmabuf: remove vdmabuf:%lld\n", vdmabuf->vmid);
	vdmabuf = drv_info->priv;
	flush_work(&vdmabuf->recv_work);
	flush_work(&vdmabuf->send_work);

	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);
}

static ssize_t vdmabuf_buf_info_show(struct device *dev,
					struct device_attribute *attr, char *buf)
{
	unsigned long flags;
	struct virtio_vdmabuf_buf *found = NULL;
	int written = 0;
	int i = 0;
	if (!drv_info)
		return 0;

	spin_lock_irqsave(&drv_info->buf_list_lock, flags);
	hash_for_each(drv_info->buf_list, i, found, node) {
		written += snprintf(buf + written, PAGE_SIZE - written,
			"bufid:%lld vmid:%d, size:%lld, priv_size:%ld, is_export:%d\n",
			found->buf_id.id, found->vmid, found->size, found->sz_priv,
			found->is_export);
	}
	spin_unlock_irqrestore(&drv_info->buf_list_lock, flags);

	return written;
}

static DEVICE_ATTR(buf_info, 0444, vdmabuf_buf_info_show, NULL);

static struct attribute *sysfs_attrs[] = {
	&dev_attr_buf_info.attr,
	NULL
};

static const struct attribute_group vdmabuf_attribute_group[] = {
	{.attrs = sysfs_attrs},
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_VDMABUF, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_vdmabuf_vdev_drv = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtio_vdmabuf_probe,
	.remove = virtio_vdmabuf_remove,
};

static int __init virtio_vdmabuf_init(void)
{
	struct virtio_vdmabuf *vdmabuf;
	int ret = 0;

	drv_info = NULL;

	ret = misc_register(&virtio_vdmabuf_miscdev);
	if (ret) {
		pr_err("virtio-vdmabuf misc driver can't be registered\n");
		return ret;
	}

	dma_coerce_mask_and_coherent(virtio_vdmabuf_miscdev.this_device,
				     DMA_BIT_MASK(64));

	drv_info = kvcalloc(1, sizeof(*drv_info), GFP_KERNEL);
	if (!drv_info) {
		misc_deregister(&virtio_vdmabuf_miscdev);
		return -ENOMEM;
	}

	vdmabuf = kvcalloc(1, sizeof(*vdmabuf), GFP_KERNEL);
	if (!vdmabuf) {
		kvfree(drv_info);
		misc_deregister(&virtio_vdmabuf_miscdev);
		return -ENOMEM;
	}

	drv_info->priv = (void *)vdmabuf;
	drv_info->dev = virtio_vdmabuf_miscdev.this_device;
	spin_lock_init(&drv_info->buf_list_lock);
	spin_lock_init(&drv_info->vdmabuf_instances_lock);
	INIT_LIST_HEAD(&drv_info->head_client_list);
	mutex_init(&vdmabuf->recv_lock);
	mutex_init(&vdmabuf->send_lock);

	// mutex_init(&drv_info->g_mutex);
	hash_init(drv_info->buf_list);

	vdmabuf->wq = create_workqueue("virtio_vdmabuf_wq");
	if (!vdmabuf->wq) {
		dev_err(drv_info->dev, "vdmabuf workqueue can't be registered\n");
		ret = -EFAULT;
		goto err_create_wq;
	}
	ret = register_virtio_driver(&virtio_vdmabuf_vdev_drv);
	if (ret) {
		dev_err(drv_info->dev, "vdmabuf driver can't be registered\n");
		goto err_register_virtio_driver;
	}
	ret = sysfs_create_group(&virtio_vdmabuf_miscdev.this_device->kobj,
					vdmabuf_attribute_group);
	if (ret < 0) {
		dev_err(drv_info->dev, "vdmabuf sysfs can't be registered\n");
		goto err_sysfs;
	}

	return 0;
err_sysfs:
	unregister_virtio_driver(&virtio_vdmabuf_vdev_drv);
err_register_virtio_driver:
	if (vdmabuf->wq)
		destroy_workqueue(vdmabuf->wq);
err_create_wq:
	misc_deregister(&virtio_vdmabuf_miscdev);
	kvfree(vdmabuf);
	kvfree(drv_info);
	return ret;
}

static void __exit virtio_vdmabuf_deinit(void)
{
	struct virtio_vdmabuf *vdmabuf = drv_info->priv;
	sysfs_remove_group(&virtio_vdmabuf_miscdev.this_device->kobj,
				vdmabuf_attribute_group);
	misc_deregister(&virtio_vdmabuf_miscdev);
	unregister_virtio_driver(&virtio_vdmabuf_vdev_drv);

	if (vdmabuf->wq)
		destroy_workqueue(vdmabuf->wq);

	/* freeing all exported buffers */
	remove_all_bufs(vdmabuf);

	kvfree(vdmabuf);
	kvfree(drv_info);
}

module_init(virtio_vdmabuf_init);
module_exit(virtio_vdmabuf_deinit);

MODULE_DEVICE_TABLE(virtio, virtio_vdmabuf_id_table);
MODULE_DESCRIPTION("Virtio Vdmabuf frontend driver");
MODULE_LICENSE("GPL and additional rights");
