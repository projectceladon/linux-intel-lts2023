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

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/miscdevice.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/hashtable.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/dma-buf.h>
#include <linux/vhost.h>
#include <linux/vfio.h>
#include <linux/highmem.h>
#include <linux/virtio_vdmabuf.h>

#include "vhost.h"

MODULE_IMPORT_NS(DMA_BUF);

#define REFS_PER_PAGE (PAGE_SIZE / sizeof(long))

enum {
	VHOST_VDMABUF_FEATURES = VHOST_FEATURES,
};

static struct virtio_vdmabuf_info *drv_info;

struct vhost_vdmabuf {
	struct vhost_dev dev;
	struct vhost_virtqueue vqs[VDMABUF_VQ_MAX];
	struct vhost_work send_work;
	u64 vmid;
	char name[MAX_VM_NAME_LEN];
	struct list_head msg_list;
	struct list_head list;
	struct list_head link;
	struct virtio_vdmabuf_be *virtio_dmabuf;
	struct kref ref;
	uint32_t size;
	uint64_t bar_gpa;
	uint64_t bar_hva;
	spinlock_t alloc_lock;
	unsigned long *alloc_bitmap;
	// unsigned int alloc_shift;
	struct page **pages;
	uint32_t num_pages;
	bool active;
	struct mm_struct *mm;
};

struct virtio_vdmabuf_be {
	struct vhost_vdmabuf *vdmabuf;
	struct list_head list;
	struct virtio_vdmabuf_event_queue *evq;
	char name[MAX_VM_NAME_LEN];
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

static inline struct virtio_vdmabuf_be *vhost_client_found_consumer(char *name)
{
       unsigned long flags;
       struct virtio_vdmabuf_be *found = NULL;
       bool hit = false;
       spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
       list_for_each_entry(found, &drv_info->head_client_list, list)
		if ((found->role & VDMABUF_MASTER_CONSUMER) &&
			strncmp(found->name, name, MAX_VM_NAME_LEN) == 0) {
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

static inline void vhost_vdmabuf_add(struct vhost_vdmabuf *new)
{
	unsigned long flags;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_add_tail(&new->list, &drv_info->head_vdmabuf_list);
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
}

static inline struct vhost_vdmabuf *vhost_vdmabuf_find(u64 vmid)
{
	struct vhost_vdmabuf *found = NULL;
	bool hit = false;
	unsigned long flags;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_for_each_entry(found, &drv_info->head_vdmabuf_list, list)
		if (found->vmid == vmid) {
			hit = true;
			break;
		}
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
	if (hit)
		return found;
	else
		return NULL;
}

static inline struct vhost_vdmabuf *
vhost_vdmabuf_bind(struct virtio_vdmabuf_be *virtio_dmabuf)
{
	struct vhost_vdmabuf *found = NULL;
	bool hit = false;
	unsigned long flags;
	if (!virtio_dmabuf)
		return found;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_for_each_entry(found, &drv_info->head_vdmabuf_list, list)
		if (strncmp(found->name, virtio_dmabuf->name,
			    MAX_VM_NAME_LEN) == 0 &&
		    found->active) {
			if (kref_get_unless_zero(&found->ref)) {
				found->virtio_dmabuf = virtio_dmabuf;
				hit = true;
			}
			break;
		}
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
	if (hit) {
		return found;
	}
	return NULL;
}

static inline bool vhost_vdmabuf_del(struct vhost_vdmabuf *vdmabuf)
{
	struct vhost_vdmabuf *iter, *temp;
	unsigned long flags;
	int ret = false;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_for_each_entry_safe(iter, temp, &drv_info->head_vdmabuf_list, list)
		if (iter == vdmabuf) {
			if (vdmabuf->virtio_dmabuf)
				vdmabuf->virtio_dmabuf->vdmabuf = NULL;
			list_del(&iter->list);
			ret = true;
			break;
		}
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
	return ret;
}

static inline void vhost_vdmabuf_del_all(void)
{
	struct vhost_vdmabuf *iter, *temp;
	unsigned long flags;
	spin_lock_irqsave(&drv_info->vdmabuf_instances_lock, flags);
	list_for_each_entry_safe(iter, temp, &drv_info->head_vdmabuf_list,
				 list) {
		list_del(&iter->list);
		kfree(iter);
	}
	spin_unlock_irqrestore(&drv_info->vdmabuf_instances_lock, flags);
}

static void *map_gpa(struct vhost_vdmabuf *vdmabuf, u64 gpa)
{
	struct mm_struct *mm = vdmabuf->mm;
	struct vhost_iotlb *umem = vdmabuf->dev.umem;
	struct vhost_iotlb_map *map;
	unsigned long vaddr;
	struct page *page;
	int ret;
	void *hva;
	if (!mm || !umem)
		return NULL;
	map = vhost_iotlb_itree_first(umem, gpa, gpa + PAGE_SIZE - 1);
	if (map == NULL || map->start > gpa) {
		return NULL;
	}
	vaddr = map->addr + gpa - map->start;
	ret = get_user_pages_remote(mm, vaddr, 1, 0, &page, NULL);
	if (ret < 0)
		return NULL;
	hva = kmap_local_page(page);
	return hva;
}

static void unmap_hva(struct vhost_vdmabuf *vdmabuf, u64 hva)
{
	if (hva)
		kunmap_local((void *)hva);
}

static int get_page_from_gpa(struct vhost_vdmabuf *vdmabuf, u64 gpa, struct page **page)
{
	struct mm_struct *mm = vdmabuf->mm;
	struct vhost_iotlb *umem = vdmabuf->dev.umem;
	struct vhost_iotlb_map *map;
	unsigned long vaddr;
	int ret;
	if (!mm || !umem || !page)
		return -1;
	map = vhost_iotlb_itree_first(umem, gpa, gpa + PAGE_SIZE - 1);
	if (map == NULL || map->start > gpa) {
		return -1;
	}
	vaddr = map->addr + gpa - map->start;
	ret = get_user_pages_remote(mm, vaddr, 1, 0, page, NULL);
	if (ret < 0)
		return -1;
	return 0;
}

static int send_msg_to_guest(u64 vmid, enum virtio_vdmabuf_cmd cmd, int *op)
{
	struct virtio_vdmabuf_msg *msg;
	struct vhost_vdmabuf *vdmabuf;
	struct vhost_virtqueue *vq = NULL;

	vdmabuf = vhost_vdmabuf_find(vmid);
	if (!vdmabuf) {
		dev_err(drv_info->dev, "can't find vdmabuf for : vmid = %llu\n",
			vmid);
		return -EINVAL;
	}
	vq = &vdmabuf->vqs[VDMABUF_VQ_SEND];

	msg = kvcalloc(1, sizeof(struct virtio_vdmabuf_msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	memcpy(&msg->op[0], &op[0], 10 * sizeof(int) + op[9]);
	msg->cmd = cmd;

	list_add_tail(&msg->list, &vdmabuf->msg_list);
	vhost_vq_work_queue(vq, &vdmabuf->send_work);

	return 0;
}

static int send_release_msg(struct virtio_vdmabuf_buf *vbuf)
{
	struct vhost_vdmabuf *vdmabuf = vbuf->data_priv;
	int ret = 0;
	int op[65] = { 0 };
	if (!vdmabuf)
		return -ENODEV;

	memcpy(op, &vbuf->buf_id, sizeof(vbuf->buf_id));
	ret = send_msg_to_guest(vdmabuf->vmid, VIRTIO_VDMABUF_CMD_DMABUF_REL,
				op);
	if (ret < 0) {
		dev_err(drv_info->dev, "fail to send release cmd\n");
		return ret;
	}
	return ret;
}

/* unmapping mapped pages */
static int
vhost_vdmabuf_unmap_pages(u64 vmid,
			  struct virtio_vdmabuf_shared_pages *pages_info)
{
	struct vhost_vdmabuf *vdmabuf = vhost_vdmabuf_find(vmid);

	if (!vdmabuf || !pages_info || pages_info->pages)
		return -EINVAL;

	kfree(pages_info->l2refs);
	kfree(pages_info->pages);
	pages_info->pages = NULL;

	return 0;
}

static void vbuf_free(struct kref *kref)
{
	struct virtio_vdmabuf_buf *vbuf;
	struct vhost_vdmabuf *vdmabuf;
	unsigned long flags;
	vbuf = container_of(kref, typeof(*vbuf), ref);
	vbuf->valid = false;
	vdmabuf = vbuf->data_priv;
	dev_dbg(drv_info->dev, "vdmabuf: free vbuf:%p, is_export:%d\n", vbuf, vbuf->is_export);
	virtio_vdmabuf_del_buf(drv_info, &vbuf->buf_id);
	if (vbuf->is_export) {
		spin_lock_irqsave(&vdmabuf->alloc_lock, flags);
		bitmap_clear(vdmabuf->alloc_bitmap,
				vbuf->pages_info->ref,
				vbuf->pages_info->nents);
		spin_unlock_irqrestore(&vdmabuf->alloc_lock, flags);
	} else {
		send_release_msg(vbuf);
		vhost_vdmabuf_unmap_pages(vbuf->vmid, vbuf->pages_info);
	}
	if (vbuf->pages_info)
		kvfree(vbuf->pages_info);
	if (vbuf->priv)
		kvfree(vbuf->priv);
	kvfree(vbuf);
}

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

/* mapping guest's pages for the vdmabuf */
static int
vhost_vdmabuf_map_pages(u64 vmid,
		struct virtio_vdmabuf_shared_pages *pages_info)
{
	struct vhost_vdmabuf *vdmabuf = vhost_vdmabuf_find(vmid);
	int npgs = REFS_PER_PAGE;
	int last_nents, n_l2refs;
	struct page *page = NULL;
	int i, j = 0, k = 0;
	int ret = 0;

	if (!vdmabuf || !pages_info || pages_info->pages)
		return -EINVAL;

	last_nents = (pages_info->nents - 1) % npgs + 1;
	n_l2refs = (pages_info->nents / npgs) + ((last_nents > 0) ? 1 : 0) -
		   (last_nents == npgs);

	pages_info->pages =
		kcalloc(pages_info->nents, sizeof(struct page *), GFP_KERNEL);
	if (!pages_info->pages)
		goto fail_page_alloc;

	pages_info->l2refs = kcalloc(n_l2refs, sizeof(u64 *), GFP_KERNEL);
	if (!pages_info->l2refs)
		goto fail_l2refs;

	pages_info->l3refs = (u64 *)map_gpa(vdmabuf, pages_info->ref);
	if (!pages_info->l3refs)
		goto fail_l3refs;

	for (i = 0; i < n_l2refs; i++) {
		pages_info->l2refs[i] =
			(u64 *)map_gpa(vdmabuf, pages_info->l3refs[i]);

		if (!(pages_info->l2refs[i]))
			goto fail_mapping_l2;

		/* last level-2 ref */
		if (i == n_l2refs - 1)
			npgs = last_nents;

		for (j = 0; j < npgs; j++) {
			ret = get_page_from_gpa(vdmabuf, pages_info->l2refs[i][j], &page);
			if (ret < 0)
				goto fail_mapping_l2;

			pages_info->pages[k] = page;
			k++;
		}
		unmap_hva(vdmabuf, pages_info->l3refs[i]);
	}

	unmap_hva(vdmabuf, pages_info->ref);

	return 0;

fail_mapping_l2:
	for (j = 0; j < i; j++) {
		unmap_hva(vdmabuf, pages_info->l3refs[i]);
	}

	unmap_hva(vdmabuf, pages_info->l3refs[i]);
	unmap_hva(vdmabuf, pages_info->ref);

fail_l3refs:
	kfree(pages_info->l2refs);

fail_l2refs:
	kfree(pages_info->pages);

fail_page_alloc:
	return -ENOMEM;
}

/* create sg_table with given pages and other parameters */
static struct sg_table *new_sgt(struct page **pgs, int first_ofst, int last_len,
				int nents)
{
	struct sg_table *sgt;
	struct scatterlist *sgl;
	int i, ret;

	sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!sgt)
		return NULL;

	ret = sg_alloc_table(sgt, nents, GFP_KERNEL);
	if (ret) {
		kfree(sgt);
		return NULL;
	}

	sgl = sgt->sgl;
	sg_set_page(sgl, pgs[0], PAGE_SIZE - first_ofst, first_ofst);

	for (i = 1; i < nents - 1; i++) {
		sgl = sg_next(sgl);
		sg_set_page(sgl, pgs[i], PAGE_SIZE, 0);
	}

	/* more than 1 page */
	if (nents > 1) {
		sgl = sg_next(sgl);
		sg_set_page(sgl, pgs[i], last_len, 0);
	}

	return sgt;
}

static struct sg_table *
vhost_vdmabuf_dmabuf_map(struct dma_buf_attachment *attachment,
			 enum dma_data_direction dir)
{
	struct virtio_vdmabuf_buf *imp;

	if (!attachment->dmabuf || !attachment->dmabuf->priv)
		return NULL;

	imp = (struct virtio_vdmabuf_buf *)attachment->dmabuf->priv;

	/* if buffer has never been mapped */
	if (!imp->sgt) {
		imp->sgt = new_sgt(imp->pages_info->pages,
				   imp->pages_info->first_ofst,
				   imp->pages_info->last_len,
				   imp->pages_info->nents);

		if (!imp->sgt)
			return NULL;
	}

	if (!dma_map_sg(attachment->dev, imp->sgt->sgl, imp->sgt->nents, dir)) {
		sg_free_table(imp->sgt);
		kfree(imp->sgt);
		return NULL;
	}

	return imp->sgt;
}

static void vhost_vdmabuf_dmabuf_unmap(struct dma_buf_attachment *attachment,
				       struct sg_table *sg,
				       enum dma_data_direction dir)
{
	dma_unmap_sg(attachment->dev, sg->sgl, sg->nents, dir);

	sg_free_table(sg);
	kfree(sg);
}

static int vhost_vdmabuf_dmabuf_mmap(struct dma_buf *dmabuf,
				     struct vm_area_struct *vma)
{
	struct virtio_vdmabuf_buf *imp;
	u64 uaddr;
	int i, err;
	unsigned long pfn;

	if (!dmabuf->priv)
		return -EINVAL;

	imp = (struct virtio_vdmabuf_buf *)dmabuf->priv;

	if (!imp->pages_info)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_page_prot = pgprot_writecombine(vm_get_page_prot(vma->vm_flags));

	uaddr = vma->vm_start;
	for (i = 0; i < imp->pages_info->nents; i++) {
		pfn = page_to_pfn(imp->pages_info->pages[i]);
		err = remap_pfn_range(vma, vma->vm_start + PAGE_SIZE * i, pfn, PAGE_SIZE,
					vma->vm_page_prot);
		if (err)
			return err;

		uaddr += PAGE_SIZE;
	}

	return 0;
}

static int vhost_vdmabuf_dmabuf_vmap(struct dma_buf *dmabuf,
				     struct iosys_map *map)
{
	struct virtio_vdmabuf_buf *imp;
	void *addr;

	if (!dmabuf->priv)
		return -EINVAL;

	imp = (struct virtio_vdmabuf_buf *)dmabuf->priv;

	if (!imp->pages_info)
		return -EINVAL;

	addr = vmap(imp->pages_info->pages, imp->pages_info->nents, 0,
		    PAGE_KERNEL);
	if (IS_ERR(addr))
		return PTR_ERR(addr);
	iosys_map_set_vaddr(map, addr);

	return 0;
}

static void vhost_vdmabuf_dmabuf_release(struct dma_buf *dma_buf)
{
	struct virtio_vdmabuf_buf *imp;

	if (!dma_buf->priv)
		return;

	imp = (struct virtio_vdmabuf_buf *)dma_buf->priv;
	imp->dma_buf = NULL;

	imp->imported = false;

	put_vbuf(imp);
}

static const struct dma_buf_ops vhost_vdmabuf_dmabuf_ops = {
	.map_dma_buf = vhost_vdmabuf_dmabuf_map,
	.unmap_dma_buf = vhost_vdmabuf_dmabuf_unmap,
	.release = vhost_vdmabuf_dmabuf_release,
	.mmap = vhost_vdmabuf_dmabuf_mmap,
	.vmap = vhost_vdmabuf_dmabuf_vmap,
};

/* exporting dmabuf as fd */
static int vhost_vdmabuf_exp_fd(struct virtio_vdmabuf_buf *imp, int flags)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

	exp_info.ops = &vhost_vdmabuf_dmabuf_ops;

	/* multiple of PAGE_SIZE, not considering offset */
	exp_info.size = imp->size;
	exp_info.flags = O_CLOEXEC | O_RDWR;
	exp_info.priv = imp;

	if (!imp->dma_buf) {
		imp->dma_buf = dma_buf_export(&exp_info);
		if (IS_ERR_OR_NULL(imp->dma_buf)) {
			imp->dma_buf = NULL;
			return -EINVAL;
		}
	}

	return dma_buf_fd(imp->dma_buf, flags);
}

static int vhost_vdmabuf_add_event(struct vhost_vdmabuf *vdmabuf,
				   struct virtio_vdmabuf_buf *buf_info)
{
	struct virtio_vdmabuf_event *e_oldest, *e_new;
	struct virtio_vdmabuf_be *client = NULL;
	struct virtio_vdmabuf_event_queue *evq = NULL;
	unsigned long irqflags;

	client = vhost_client_found_consumer(vdmabuf->name);
	if (!client) {
		return 0;
	}
	evq = client->evq;

	e_new = kzalloc(sizeof(*e_new), GFP_KERNEL);
	if (!e_new) {
		put_client(client);
		return -ENOMEM;
	}
	if (buf_info->sz_priv) {
		e_new->e_data.data = kzalloc(buf_info->sz_priv, GFP_KERNEL);
		if (!e_new->e_data.data) {
			put_client(client);
			kfree(e_new);
			return -ENOMEM;
		}
		memcpy(e_new->e_data.data, buf_info->priv, buf_info->sz_priv);
	}
	e_new->e_data.hdr.buf_id = buf_info->buf_id;
	e_new->e_data.hdr.size = buf_info->sz_priv;

	evq = client->evq;
	spin_lock_irqsave(&evq->e_lock, irqflags);

	/* check current number of event then if it hits the max num (32)
	 * then remove the oldest event in the list
	 */
	if (evq->pending > 31) {
		e_oldest = list_first_entry(&evq->e_list,
					    struct virtio_vdmabuf_event, link);
		list_del(&e_oldest->link);
		evq->pending--;
		if (e_oldest->e_data.data)
			kfree(e_oldest->e_data.data);
		kfree(e_oldest);
	}

	list_add_tail(&e_new->link, &evq->e_list);

	evq->pending++;

	wake_up_interruptible(&evq->e_wait);
	spin_unlock_irqrestore(&evq->e_lock, irqflags);
	put_client(client);

	return 0;
}

static int register_exported(struct vhost_vdmabuf *vdmabuf,
			     virtio_vdmabuf_buf_id_t *buf_id, int *ops)
{
	struct virtio_vdmabuf_buf *imp;
	int ret;

	imp = kvzalloc(sizeof(*imp), GFP_KERNEL);
	if (!imp)
		return -ENOMEM;
	kref_init(&imp->ref);
	imp->pages_info = kvzalloc(sizeof(struct virtio_vdmabuf_shared_pages),
				   GFP_KERNEL);
	if (!imp->pages_info) {
		kvfree(imp);
		return -ENOMEM;
	}

	imp->sz_priv = ops[VIRTIO_VDMABUF_PRIVATE_DATA_SIZE];
	if (imp->sz_priv) {
		imp->priv = kvzalloc(ops[VIRTIO_VDMABUF_PRIVATE_DATA_SIZE],
				     GFP_KERNEL);
		if (!imp->priv) {
			kvfree(imp->pages_info);
			kvfree(imp);
			return -ENOMEM;
		}
	}

	memcpy(&imp->buf_id, buf_id, sizeof(*buf_id));

	imp->pages_info->nents = ops[VIRTIO_VDMABUF_NUM_PAGES_SHARED];
	imp->pages_info->first_ofst =
		ops[VIRTIO_VDMABUF_FIRST_PAGE_DATA_OFFSET];
	imp->pages_info->last_len = ops[VIRTIO_VDMABUF_LAST_PAGE_DATA_LENGTH];
	imp->pages_info->ref =
		*(u64 *)&ops[VIRTIO_VDMABUF_REF_ADDR_UPPER_32BIT];
	imp->vmid = vdmabuf->vmid;
	imp->size = imp->pages_info->last_len + PAGE_SIZE - imp->pages_info->first_ofst +
						(imp->pages_info->nents - 2) * PAGE_SIZE;
	imp->valid = true;
	imp->is_export = false;
	imp->data_priv = vdmabuf;
	get_vbuf(imp);
	virtio_vdmabuf_add_buf(drv_info, imp);

	/* transferring private data */
	memcpy(imp->priv, &ops[VIRTIO_VDMABUF_PRIVATE_DATA_START],
	       imp->sz_priv);

	/* generate import event */
	ret = vhost_vdmabuf_add_event(vdmabuf, imp);
	put_vbuf(imp);
	if (ret)
		return ret;

	return 0;
}

static void send_to_recvq(struct vhost_vdmabuf *vdmabuf,
			  struct vhost_virtqueue *vq)
{
	struct virtio_vdmabuf_msg *msg;
	int head, in, out, in_size;
	bool added = false;
	int ret;

	mutex_lock(&vq->mutex);

	if (!vhost_vq_get_backend(vq))
		goto out;

	vhost_disable_notify(&vdmabuf->dev, vq);

	for (;;) {
		if (list_empty(&vdmabuf->msg_list))
			break;

		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out,
					 &in, NULL, NULL);

		if (head < 0 || head == vq->num)
			break;

		in_size = iov_length(&vq->iov[out], in);
		if (in_size != sizeof(struct virtio_vdmabuf_msg)) {
			dev_err(drv_info->dev, "rx msg with wrong size\n");
			break;
		}

		msg = list_first_entry(&vdmabuf->msg_list,
				       struct virtio_vdmabuf_msg, list);
		list_del_init(&msg->list);

		ret = __copy_to_user(vq->iov[out].iov_base, msg,
				     sizeof(struct virtio_vdmabuf_msg));
		if (ret) {
			dev_err(drv_info->dev, "fail to copy tx msg\n");
			break;
		}

		vhost_add_used(vq, head, in_size);
		added = true;

		//kfree(msg);
	}

	vhost_enable_notify(&vdmabuf->dev, vq);
	if (added)
		vhost_signal(&vdmabuf->dev, vq);
out:
	mutex_unlock(&vq->mutex);
}

static void vhost_send_msg_work(struct vhost_work *work)
{
	struct vhost_vdmabuf *vdmabuf =
		container_of(work, struct vhost_vdmabuf, send_work);
	struct vhost_virtqueue *vq = &vdmabuf->vqs[VDMABUF_VQ_RECV];

	send_to_recvq(vdmabuf, vq);
}

/* parse incoming message from a guest */
static int parse_msg(struct vhost_vdmabuf *vdmabuf,
		     struct virtio_vdmabuf_msg *msg)
{
	virtio_vdmabuf_buf_id_t *buf_id;
	struct virtio_vdmabuf_buf *imp;
	int ret = 0;
	dev_dbg(drv_info->dev, "vdmabuf: parse msg cmd:%d\n", msg->cmd);
	switch (msg->cmd) {
	case VIRTIO_VDMABUF_CMD_EXPORT:
		buf_id = (virtio_vdmabuf_buf_id_t *)msg->op;
		ret = register_exported(vdmabuf, buf_id, msg->op);

		break;
	case VIRTIO_VDMABUF_CMD_DMABUF_REL:
		buf_id = (virtio_vdmabuf_buf_id_t *)msg->op;
		imp = virtio_vdmabuf_find_buf(drv_info, buf_id);
		if (!imp) {
			dev_err(drv_info->dev, "vdmabuf rel: can't find buffer\n");
			//ret = -EINVAL;
		} else {
			put_vbuf(imp);
		}
		break;
	case VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT:
		buf_id = (virtio_vdmabuf_buf_id_t *)msg->op;
		imp = virtio_vdmabuf_find_buf(drv_info, buf_id);
		if (imp) {
			imp->unexport = true;
			put_vbuf(imp);
		} else {
			dev_dbg(drv_info->dev, "vdmabuf unexport: can't find buffer\n");
		}
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void vhost_vdmabuf_handle_send_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq =
		container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_vdmabuf *vdmabuf =
		container_of(vq->dev, struct vhost_vdmabuf, dev);
	struct virtio_vdmabuf_msg msg;
	int head, in, out, in_size;
	bool added = false;
	int ret;

	mutex_lock(&vq->mutex);

	if (!vhost_vq_get_backend(vq))
		goto out;

	vhost_disable_notify(&vdmabuf->dev, vq);

	/* Make sure we will process all pending requests */
	for (;;) {
		head = vhost_get_vq_desc(vq, vq->iov, ARRAY_SIZE(vq->iov), &out,
					 &in, NULL, NULL);

		if (head < 0 || head == vq->num)
			break;

		in_size = iov_length(&vq->iov[in], out);
		if (in_size != sizeof(struct virtio_vdmabuf_msg)) {
			dev_err(drv_info->dev, "rx msg with wrong size\n");
			break;
		}

		if (__copy_from_user(&msg, vq->iov[in].iov_base, in_size)) {
			dev_err(drv_info->dev,
				"err: can't get the msg from vq\n");
			break;
		}

		ret = parse_msg(vdmabuf, &msg);
		if (ret) {
			dev_err(drv_info->dev, "msg parse error: %d", ret);
			dev_err(drv_info->dev, " cmd: %d\n", msg.cmd);

			break;
		}

		vhost_add_used(vq, head, in_size);
		added = true;
	}

	vhost_enable_notify(&vdmabuf->dev, vq);
	if (added)
		vhost_signal(&vdmabuf->dev, vq);
out:
	mutex_unlock(&vq->mutex);
}

static void vhost_vdmabuf_handle_recv_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq =
		container_of(work, struct vhost_virtqueue, poll.work);
	struct vhost_vdmabuf *vdmabuf =
		container_of(vq->dev, struct vhost_vdmabuf, dev);

	send_to_recvq(vdmabuf, vq);
}

static int vhost_vdmabuf_open(struct inode *inode, struct file *filp)
{
	struct vhost_vdmabuf *vdmabuf;
	struct vhost_virtqueue **vqs;
	int ret = 0;

	if (!drv_info) {
		pr_err("vhost-vdmabuf: can't open misc device\n");
		return -EINVAL;
	}

	vdmabuf = kzalloc(sizeof(*vdmabuf), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!vdmabuf)
		return -ENOMEM;

	vqs = kmalloc_array(ARRAY_SIZE(vdmabuf->vqs), sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		kfree(vdmabuf);
		return -ENOMEM;
	}

	vqs[VDMABUF_VQ_SEND] = &vdmabuf->vqs[VDMABUF_VQ_SEND];
	vqs[VDMABUF_VQ_RECV] = &vdmabuf->vqs[VDMABUF_VQ_RECV];
	vdmabuf->vqs[VDMABUF_VQ_SEND].handle_kick =
		vhost_vdmabuf_handle_send_kick;
	vdmabuf->vqs[VDMABUF_VQ_RECV].handle_kick =
		vhost_vdmabuf_handle_recv_kick;

	vhost_dev_init(&vdmabuf->dev, vqs, ARRAY_SIZE(vdmabuf->vqs), UIO_MAXIOV,
		       0, 0, true, NULL);

	INIT_LIST_HEAD(&vdmabuf->msg_list);
	kref_init(&vdmabuf->ref);
	vhost_work_init(&vdmabuf->send_work, vhost_send_msg_work);
	vdmabuf->vmid = 0;
	spin_lock_init(&vdmabuf->alloc_lock);
	vdmabuf->alloc_bitmap = NULL;

	vdmabuf->active = true;
	vhost_vdmabuf_add(vdmabuf);
	dev_dbg(drv_info->dev, "add vhost vdmabuf device\n");

	filp->private_data = vdmabuf;

	return ret;
}

static void vhost_vdmabuf_flush(struct vhost_vdmabuf *vdmabuf)
{
	vhost_dev_flush(&vdmabuf->dev);
}

static void vdmabuf_free(struct kref *kref)
{
	struct vhost_vdmabuf *vdmabuf;
	vdmabuf = container_of(kref, typeof(*vdmabuf), ref);
	if (!vdmabuf)
		return;
	if (vdmabuf->pages && vdmabuf->num_pages) {
		for (int j = 0; j < vdmabuf->num_pages; j++)
			unpin_user_page(vdmabuf->pages[j]);
		kfree(vdmabuf->pages);
	}
	if (vdmabuf->alloc_bitmap && vdmabuf->num_pages)
		kfree(vdmabuf->alloc_bitmap);

	vdmabuf->num_pages = 0;
	kfree(vdmabuf->dev.vqs);
	kfree(vdmabuf);
	vdmabuf = NULL;
}

void put_vhost_vdmabuf(struct vhost_vdmabuf *vdmabuf)
{
	if (vdmabuf) {
		kref_put(&vdmabuf->ref, vdmabuf_free);
	}
}

static int vhost_vdmabuf_release(struct inode *inode, struct file *filp)
{
	struct vhost_vdmabuf *vdmabuf = filp->private_data;

	dev_dbg(drv_info->dev, "vhost vdmabuf release\n");
	vdmabuf->active = false;
	if (!vhost_vdmabuf_del(vdmabuf))
		return -EINVAL;

	vhost_vdmabuf_flush(vdmabuf);

	vhost_dev_cleanup(&vdmabuf->dev);

	put_vhost_vdmabuf(vdmabuf);

	filp->private_data = NULL;

	return 0;
}

static __poll_t virtio_vdmabuf_be_event_poll(struct file *filp,
					     struct poll_table_struct *wait)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;

	poll_wait(filp, &virtio_dmabuf->evq->e_wait, wait);

	if (!list_empty(&virtio_dmabuf->evq->e_list)) {
		return POLLIN | POLLRDNORM;
	}
	return 0;
}

static ssize_t virtio_vdmabuf_be_event_read(struct file *filp, char __user *buf,
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
	if (ret) {
		return ret;
	}

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

			if (ret) {
				return ret;
			}
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

			spin_lock_irq(&virtio_dmabuf->evq->e_lock);
			virtio_dmabuf->evq->pending--;
			spin_unlock_irq(&virtio_dmabuf->evq->e_lock);
			if (e->e_data.data)
				kfree(e->e_data.data);
			kfree(e);
		}
	}

	mutex_unlock(&virtio_dmabuf->evq->e_readlock);
	return ret;
}

static int vhost_vdmabuf_start(struct vhost_vdmabuf *vdmabuf)
{
	struct vhost_virtqueue *vq;
	int i, ret;

	mutex_lock(&vdmabuf->dev.mutex);

	ret = vhost_dev_check_owner(&vdmabuf->dev);
	if (ret)
		goto err;

	for (i = 0; i < ARRAY_SIZE(vdmabuf->vqs); i++) {
		vq = &vdmabuf->vqs[i];

		mutex_lock(&vq->mutex);

		if (!vhost_vq_access_ok(vq)) {
			ret = -EFAULT;
			goto err_vq;
		}

		if (!vhost_vq_get_backend(vq)) {
			vhost_vq_set_backend(vq, vdmabuf);
			ret = vhost_vq_init_access(vq);
			if (ret)
				goto err_vq;
		}

		mutex_unlock(&vq->mutex);
	}

	mutex_unlock(&vdmabuf->dev.mutex);
	return 0;

err_vq:
	vhost_vq_set_backend(vq, NULL);
	mutex_unlock(&vq->mutex);

	for (i = 0; i < ARRAY_SIZE(vdmabuf->vqs); i++) {
		vq = &vdmabuf->vqs[i];

		mutex_lock(&vq->mutex);
		vhost_vq_set_backend(vq, NULL);
		mutex_unlock(&vq->mutex);
	}

err:
	mutex_unlock(&vdmabuf->dev.mutex);
	return ret;
}

static int vhost_vdmabuf_stop(struct vhost_vdmabuf *vdmabuf)
{
	struct vhost_virtqueue *vq;
	int i, ret;

	mutex_lock(&vdmabuf->dev.mutex);

	ret = vhost_dev_check_owner(&vdmabuf->dev);
	if (ret)
		goto err;

	for (i = 0; i < ARRAY_SIZE(vdmabuf->vqs); i++) {
		vq = &vdmabuf->vqs[i];

		mutex_lock(&vq->mutex);
		vhost_vq_set_backend(vq, NULL);
		mutex_unlock(&vq->mutex);
	}

err:
	mutex_unlock(&vdmabuf->dev.mutex);
	return ret;
}

static int vhost_vdmabuf_set_features(struct vhost_vdmabuf *vdmabuf,
				      u64 features)
{
	struct vhost_virtqueue *vq;
	int i;

	if (features & ~VHOST_VDMABUF_FEATURES)
		return -EOPNOTSUPP;

	mutex_lock(&vdmabuf->dev.mutex);
	if ((features & (1 << VHOST_F_LOG_ALL)) &&
	    !vhost_log_access_ok(&vdmabuf->dev)) {
		mutex_unlock(&vdmabuf->dev.mutex);
		return -EFAULT;
	}

	for (i = 0; i < ARRAY_SIZE(vdmabuf->vqs); i++) {
		vq = &vdmabuf->vqs[i];
		mutex_lock(&vq->mutex);
		vq->acked_features = features;
		mutex_unlock(&vq->mutex);
	}

	mutex_unlock(&vdmabuf->dev.mutex);
	return 0;
}

/* wrapper ioctl for vhost interface control */
static int vhost_core_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long param)
{
	struct vhost_vdmabuf *vdmabuf = filp->private_data;
	void __user *argp = (void __user *)param;
	u64 features;
	int ret, start;

	switch (cmd) {
	case VHOST_GET_FEATURES:
		features = VHOST_VDMABUF_FEATURES;
		if (copy_to_user(argp, &features, sizeof(features)))
			return -EFAULT;
		return 0;
	case VHOST_SET_FEATURES:
		if (copy_from_user(&features, argp, sizeof(features)))
			return -EFAULT;
		return vhost_vdmabuf_set_features(vdmabuf, features);
	case VHOST_VDMABUF_SET_RUNNING:
		if (copy_from_user(&start, argp, sizeof(start)))
			return -EFAULT;

		if (start)
			return vhost_vdmabuf_start(vdmabuf);
		else
			return vhost_vdmabuf_stop(vdmabuf);
	default:
		mutex_lock(&vdmabuf->dev.mutex);
		ret = vhost_dev_ioctl(&vdmabuf->dev, cmd, argp);
		if (ret == -ENOIOCTLCMD) {
			ret = vhost_vring_ioctl(&vdmabuf->dev, cmd, argp);
		} else {
			vhost_vdmabuf_flush(vdmabuf);
		}
		mutex_unlock(&vdmabuf->dev.mutex);
	}

	return ret;
}

/*
 * ioctl - importing vdmabuf from guest OS
 *
 * user parameters:
 *
 *	virtio_vdmabuf_buf_id_t buf_id - vdmabuf ID of imported buffer
 *	int flags - flags
 *	int fd - file handle of	the imported buffer
 *
 */
static int import_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct vhost_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_import *attr = data;
	struct virtio_vdmabuf_buf *imp;
	int ret = 0;

	if (!vdmabuf || !vdmabuf->active)
		return -1;
	mutex_lock(&vdmabuf->dev.mutex);

	/* look for dmabuf for the id */
	imp = virtio_vdmabuf_find_and_get_buf(drv_info, &attr->buf_id);
	if (!imp || !imp->valid) {
		mutex_unlock(&vdmabuf->dev.mutex);
		dev_dbg(drv_info->dev, "import:no valid buf found with id = %llu\n",
			attr->buf_id.id);
		return -ENOENT;
	}

	/* only if mapped pages are not present */
	if (!imp->pages_info->pages) {
		ret = vhost_vdmabuf_map_pages(vdmabuf->vmid, imp->pages_info);
		if (ret < 0) {
			dev_err(drv_info->dev, "failed to map guest pages\n");
			goto fail_map;
		}
	}

	attr->fd = vhost_vdmabuf_exp_fd(imp, attr->flags);
	if (attr->fd < 0) {
		dev_err(drv_info->dev, "failed to get file descriptor\n");
		ret = attr->fd;
		goto fail_import;
	}

	imp->imported = true;

	mutex_unlock(&vdmabuf->dev.mutex);
	goto success;

fail_import:
	/* not imported yet? */
	if (!imp->imported) {
		vhost_vdmabuf_unmap_pages(vdmabuf->vmid, imp->pages_info);
		if (imp->dma_buf) {
			kfree(imp->dma_buf);
			imp->dma_buf = NULL;
		}

		if (imp->sgt) {
			sg_free_table(imp->sgt);
			kfree(imp->sgt);
			imp->sgt = NULL;
		}
	}

fail_map:
	put_vbuf(imp);
	mutex_unlock(&vdmabuf->dev.mutex);
success:
	return ret;
}

static int vm_set_ioctl(struct file *filp, void *data)
{
	struct vhost_vdmabuf *vdmabuf = filp->private_data;
	struct vhost_vdmabuf_set *set = data;
	if (!set || !vdmabuf)
		return -1;

	vdmabuf->vmid = set->vmid;
	memcpy(vdmabuf->name, set->name, MAX_VM_NAME_LEN);
	vdmabuf->mm = current->mm;
	return 0;
}

static int smem_ioctl(struct file *filp, void *data)
{
	struct vhost_vdmabuf *vdmabuf = filp->private_data;
	struct virtio_vdmabuf_smem *smem = data;
	int chunks, bitmap_size;
	int pinned;

	if (!smem || !vdmabuf)
		return -1;
	vdmabuf->size = smem->size;
	if (smem->size == 0) {
		dev_info(drv_info->dev, "smem size is zero, be to fe sharing is not supported\n");
		return 0;
	}
	vdmabuf->bar_gpa = smem->gpa;
	vdmabuf->bar_hva = smem->hva;
	vdmabuf->num_pages = DIV_ROUND_UP(vdmabuf->size, PAGE_SIZE);

	chunks = vdmabuf->num_pages;
	bitmap_size = BITS_TO_LONGS(chunks) * sizeof(long);
	vdmabuf->alloc_bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!vdmabuf->alloc_bitmap)
		return -ENOMEM;

	vdmabuf->pages = kvzalloc(vdmabuf->num_pages * sizeof(struct page *),
				  GFP_KERNEL);
	if (!vdmabuf->pages) {
		kfree(vdmabuf->alloc_bitmap);
		return -ENOMEM;
	}

	pinned = pin_user_pages_fast(vdmabuf->bar_hva, vdmabuf->num_pages,
				     FOLL_WRITE | FOLL_LONGTERM,
				     vdmabuf->pages);
	if (pinned < 0) {
		kfree(vdmabuf->alloc_bitmap);
		kfree(vdmabuf->pages);
		vdmabuf->num_pages = 0;
		return -ENOMEM;
	} else if (pinned != vdmabuf->num_pages) {
		for (int j = 0; j < pinned; j++)
			unpin_user_page(vdmabuf->pages[j]);
		kfree(vdmabuf->alloc_bitmap);
		kfree(vdmabuf->pages);
		vdmabuf->num_pages = 0;
		return -ENOMEM;
	}
	return 0;
}

static const struct virtio_vdmabuf_ioctl_desc vhost_vdmabuf_ioctls[] = {
	VIRTIO_VDMABUF_IOCTL_DEF(VHOST_VDMABUF_SET_ID, vm_set_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_SHARED_MEM, smem_ioctl, 0),
};

static long vhost_vdmabuf_ioctl(struct file *filp, unsigned int cmd,
				unsigned long param)
{
	const struct virtio_vdmabuf_ioctl_desc *ioctl = NULL;
	virtio_vdmabuf_ioctl_t func = NULL;
	int ret;
	char *kdata;

	/* check if cmd is vhost's */
	if (_IOC_TYPE(cmd) == VHOST_VIRTIO) {
		ret = vhost_core_ioctl(filp, cmd, param);
		return ret;
	}

	for (int i = 0; i < ARRAY_SIZE(vhost_vdmabuf_ioctls); i++) {
		ioctl = &vhost_vdmabuf_ioctls[i];
		if (ioctl->cmd == cmd) {
			func = ioctl->func;
			break;
		}
	}

	if ((!func)) {
		dev_err(drv_info->dev, "invalid ioctl, cmd:%d\n", cmd);
		return -EINVAL;
	}

	kdata = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!kdata)
		return -ENOMEM;

	if (copy_from_user(kdata, (void __user *)param, _IOC_SIZE(cmd)) != 0) {
		dev_err(drv_info->dev, "failed to copy args from userspace\n");
		ret = -EFAULT;
		goto ioctl_error;
	}

	ret = func(filp, kdata);

	if (copy_to_user((void __user *)param, kdata, _IOC_SIZE(cmd)) != 0) {
		dev_err(drv_info->dev,
			"failed to copy args back to userspace\n");
		ret = -EFAULT;
		goto ioctl_error;
	}

ioctl_error:
	kfree(kdata);
	return ret;
}

static const struct file_operations vhost_vdmabuf_fops = {
	.owner = THIS_MODULE,
	.open = vhost_vdmabuf_open,
	.release = vhost_vdmabuf_release,
	.unlocked_ioctl = vhost_vdmabuf_ioctl,
};

static struct miscdevice vhost_vdmabuf_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "vhost-vdmabuf",
	.fops = &vhost_vdmabuf_fops,
};

static int virtio_vdmabuf_be_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct virtio_vdmabuf_be *virtio_dmabuf = NULL;
	filp->private_data = NULL;
	virtio_dmabuf = kzalloc(sizeof(*virtio_dmabuf), GFP_KERNEL);
	if (!virtio_dmabuf)
		return -ENOMEM;
	virtio_dmabuf->vdmabuf = NULL;
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
	dev_dbg(drv_info->dev, "add vhost client\n");

	return ret;
}

static void
virtio_vdmabuf_unexport_exported_buf(struct virtio_vdmabuf_info *info,
				     struct file *filp)
{
	struct virtio_vdmabuf_buf *found = NULL;
	unsigned long flags;
	struct vhost_vdmabuf *vdmabuf;
	int i = 0;
	int ret = 0;
	int op[65] = { 0 };
	if (!info)
		return;
	spin_lock_irqsave(&info->buf_list_lock, flags);

	hash_for_each(info->buf_list, i, found, node) {
		if (found->filp == filp && !found->unexport && found->is_export &&
		    found->data_priv) {
			found->unexport = true;
			memcpy(op, &found->buf_id, sizeof(found->buf_id));
			vdmabuf = found->data_priv;
			spin_unlock_irqrestore(&info->buf_list_lock, flags);
			ret = send_msg_to_guest(
				vdmabuf->vmid,
				VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT, op);
			if (ret < 0) {
				dev_err(drv_info->dev,
					"fail to send unexport cmd\n");
			}
			spin_lock_irqsave(&info->buf_list_lock, flags);
		}
	}
	spin_unlock_irqrestore(&info->buf_list_lock, flags);
}

static int virtio_vdmabuf_be_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct virtio_vdmabuf_be *virtio_dmabuf = NULL;
	virtio_dmabuf = filp->private_data;
	if (!virtio_dmabuf)
		return ret;
	dev_dbg(drv_info->dev, "release vhost client\n");
	virtio_vdmabuf_unexport_exported_buf(drv_info, filp);
	vhost_client_delete(virtio_dmabuf);
	put_client(virtio_dmabuf);
	return ret;
}

static int attach_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf_attach *attach =
		(struct virtio_vdmabuf_attach *)data;
	if (!attach)
		return -1;

	memcpy(virtio_dmabuf->name, attach->name, MAX_VM_NAME_LEN);
	return 0;
}

static int role_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct virtio_vdmabuf_role *role =
		(struct virtio_vdmabuf_role *)data;

	if (strlen(virtio_dmabuf->name) == 0) {
		dev_err(drv_info->dev, "vdmabuf: set role should behind attach\n");
		return -EINVAL;
	}

	if (role->role & VDMABUF_MASTER_CONSUMER) {
		struct virtio_vdmabuf_be *client = NULL;
		client = vhost_client_found_consumer(virtio_dmabuf->name);
		if (client) {
			put_client(client);
			dev_dbg(drv_info->dev, "vdmabuf: duplicate consumer role\n");
			return -EINVAL;
		}
	}

	virtio_dmabuf->role = role->role;
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
	int i, ret;

	if (!dmabuf->priv)
		return -EINVAL;

	exp_buf = dmabuf->priv;

	if (!exp_buf->pages_info)
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_page_prot = pgprot_writecombine(vm_get_page_prot(vma->vm_flags));

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

	put_vbuf(exp_buf);
}

static const struct dma_buf_ops virtio_vdmabuf_dmabuf_ops = {
	.map_dma_buf = virtio_vdmabuf_map_dmabuf,
	.unmap_dma_buf = virtio_vdmabuf_unmap_dmabuf,
	.release = virtio_vdmabuf_release_dmabuf,
	.mmap = virtio_vdmabuf_mmap_dmabuf,
};

int find_avail_unused_bar_address(struct vhost_vdmabuf *vdmabuf, int num_pages)
{
	unsigned long flags;
	int chunk = -ENOMEM;
	int ret = -ENOMEM;

	if (!vdmabuf || !vdmabuf->alloc_bitmap || vdmabuf->num_pages == 0)
		return -1;
	spin_lock_irqsave(&vdmabuf->alloc_lock, flags);
	chunk = bitmap_find_next_zero_area(vdmabuf->alloc_bitmap,
					   vdmabuf->num_pages, 0, num_pages, 0);
	if (chunk < vdmabuf->num_pages) {
		ret = chunk;
		bitmap_set(vdmabuf->alloc_bitmap, chunk, num_pages);
	}
	spin_unlock_irqrestore(&vdmabuf->alloc_lock, flags);
	return ret;
}

#define VIRTIO_VDMABUF_MAX_ID INT_MAX
#define NEW_BUF_ID_GEN(vmid, cnt) \
	(((vmid & 0xFFFFFFFF) << 32) | ((cnt) & 0xFFFFFFFF))
static virtio_vdmabuf_buf_id_t vhost_get_buf_id(struct vhost_vdmabuf *vdmabuf)
{
	virtio_vdmabuf_buf_id_t buf_id = { 0, { 0, 0 } };
	static int count = 0;

	count = count < VIRTIO_VDMABUF_MAX_ID ? count + 1 : 0;
	buf_id.id = NEW_BUF_ID_GEN(0UL, count);

	/* random data embedded in the id for security */
	get_random_bytes(&buf_id.rng_key[0], 8);

	return buf_id;
}

static int virtio_vdmabuf_create_dmabuf(struct vhost_vdmabuf *vdmabuf, struct file *filp,
					uint64_t bo_size)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct virtio_vdmabuf_buf *exp_buf;
	struct dma_buf *dmabuf;
	uint32_t num_pages = DIV_ROUND_UP(bo_size, PAGE_SIZE);
	int i, ret;
	int chunk;
	virtio_vdmabuf_buf_id_t buf_id;

	chunk = find_avail_unused_bar_address(vdmabuf, num_pages);
	if (chunk < 0) {
		dev_err(drv_info->dev, "vdmabuf: no availabe space\n");
		return -ENOMEM;
	}

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

	exp_buf->pages_info->first_ofst = 0;
	exp_buf->pages_info->last_len = PAGE_SIZE;
	exp_buf->pages_info->offset = chunk;
	exp_buf->pages_info->ref = exp_buf->pages_info->offset;
	exp_buf->pages_info->nents = num_pages;
	exp_buf->data_priv = vdmabuf;

	for (i = 0; i < num_pages; i++) {
		exp_buf->pages_info->pages[i] = vdmabuf->pages[chunk + i];
	}

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR_OR_NULL(dmabuf))
		goto err_pages;

	ret = dma_buf_fd(dmabuf, 0);
	if (ret < 0)
		goto err_pages;
	exp_buf->valid = true;
	exp_buf->fd = ret;
	exp_buf->is_export = true;
	buf_id = vhost_get_buf_id(vdmabuf);
	exp_buf->buf_id = buf_id;
	exp_buf->filp = filp;
	virtio_vdmabuf_add_buf(drv_info, exp_buf);

	return ret;

err_pages:
	kvfree(exp_buf->pages_info->pages);
err_pages_info:
	kvfree(exp_buf->pages_info);
err_exp:
	kvfree(exp_buf);

	return -ENOMEM;
}

static int alloc_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct vhost_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_alloc *attr = data;
	int ret;

	if (!vdmabuf || !vdmabuf->active)
		return -1;
	ret = virtio_vdmabuf_create_dmabuf(vdmabuf, filp, attr->size);
	if (ret < 0)
		return ret;

	attr->fd = ret;

	return ret;
}

static int export_notify(struct virtio_vdmabuf_buf *exp)
{
	struct virtio_vdmabuf_shared_pages *pages_info = exp->pages_info;
	struct vhost_vdmabuf *vdmabuf = exp->data_priv;
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

	ret = send_msg_to_guest(vdmabuf->vmid, VIRTIO_VDMABUF_CMD_EXPORT, op);

	kvfree(op);
	return ret;
}

static int export_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct vhost_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_export *attr = data;
	struct virtio_vdmabuf_buf *exp;
	int ret = 0;

	if (!vdmabuf || !vdmabuf->active)
		return -EINVAL;

	exp = virtio_vdmabuf_find_fd_and_get_buf(drv_info, filp, attr->fd);
	if (!exp) {
		dev_err(drv_info->dev, "vdmabuf: export invalid fd parameter\n");
		return -EINVAL;
	}

	if (attr->sz_priv > MAX_SIZE_PRIV_DATA)
		exp->sz_priv = MAX_SIZE_PRIV_DATA;
	else
		exp->sz_priv = attr->sz_priv;

	/* creating buffer for private data */
	if (exp->sz_priv != 0) {
		exp->priv = kvcalloc(1, exp->sz_priv, GFP_KERNEL);
		if (!exp->priv) {
			ret = -ENOMEM;
			goto fail_priv;
		}

		ret = copy_from_user(exp->priv, attr->priv, exp->sz_priv);
		if (ret) {
			ret = -EINVAL;
			goto fail_priv;
		}
	}

	ret = export_notify(exp);
	if (ret < 0)
		goto fail_priv;

	exp->bar_mapped = true;
	memcpy(&attr->buf_id, &exp->buf_id, sizeof(virtio_vdmabuf_buf_id_t));

	return ret;

fail_priv:
	if (exp->priv)
		kvfree(exp->priv);
	put_vbuf(exp);

	return ret;
}

static int unexport_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;
	struct vhost_vdmabuf *vdmabuf = virtio_dmabuf->vdmabuf;
	struct virtio_vdmabuf_unexport *attr = data;
	struct virtio_vdmabuf_buf *exp;
	int op[65] = {0};
	int ret = 0;

	if (!vdmabuf || !vdmabuf->active)
		return -EINVAL;

	exp = virtio_vdmabuf_find_and_get_buf(drv_info, &attr->buf_id);
	if (!exp || !exp->valid) {
		dev_err(drv_info->dev, "no valid buf found with id = %llu\n",
			attr->buf_id.id);
		return -ENOENT;
	}

	if (!exp->is_export) {
		dev_dbg(drv_info->dev, "unexport: buf is not exported id = %llu\n",
			attr->buf_id.id);
		put_vbuf(exp);
		return -ENOENT;
	}

	memcpy(op, &exp->buf_id, sizeof(exp->buf_id));

	ret = send_msg_to_guest(vdmabuf->vmid,
				VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT, op);
	if (ret < 0) {
		dev_err(drv_info->dev, "fail to send unexport cmd\n");
	} else {
		exp->unexport = true;
	}

	put_vbuf(exp);

	return ret;
}

static int query_ioctl(struct file *filp, void *data)
{
	struct virtio_vdmabuf_query_bufinfo *attr = data;
	struct virtio_vdmabuf_buf *exp;
	int ret = 0;

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
			if (!access_ok((void __user *)attr->info,
				       exp->sz_priv)) {
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

static const struct virtio_vdmabuf_ioctl_desc virtio_vdmabuf_be_ioctls[] = {
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_ATTACH, attach_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_ROLE, role_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_IMPORT, import_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_ALLOC_FD, alloc_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_EXPORT, export_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_UNEXPORT, unexport_ioctl, 0),
	VIRTIO_VDMABUF_IOCTL_DEF(VIRTIO_VDMABUF_IOCTL_QUERY_BUFINFO, query_ioctl, 0),
};

static long virtio_vdmabuf_be_ioctl(struct file *filp, unsigned int cmd,
				    unsigned long param)
{
	const struct virtio_vdmabuf_ioctl_desc *ioctl = NULL;
	virtio_vdmabuf_ioctl_t func = NULL;
	int ret;
	char *kdata;
	struct vhost_vdmabuf *vdmabuf;
	struct virtio_vdmabuf_be *virtio_dmabuf = filp->private_data;

	for (int i = 0; i < ARRAY_SIZE(virtio_vdmabuf_be_ioctls); i++) {
		ioctl = &virtio_vdmabuf_be_ioctls[i];
		if (ioctl->cmd == cmd) {
			func = ioctl->func;
			break;
		}
	}

	if ((!func)) {
		dev_err(drv_info->dev, "invalid ioctl, cmd:%d\n", cmd);
		return -EINVAL;
	}

	kdata = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL);
	if (!kdata)
		return -ENOMEM;

	if (copy_from_user(kdata, (void __user *)param, _IOC_SIZE(cmd)) != 0) {
		dev_err(drv_info->dev, "failed to copy args from userspace\n");
		ret = -EFAULT;
		goto ioctl_error;
	}

	vdmabuf = vhost_vdmabuf_bind(virtio_dmabuf);
	virtio_dmabuf->vdmabuf = vdmabuf;
	ret = func(filp, kdata);
	put_vhost_vdmabuf(vdmabuf);

	if (copy_to_user((void __user *)param, kdata, _IOC_SIZE(cmd)) != 0) {
		dev_err(drv_info->dev,
			"failed to copy args back to userspace\n");
		ret = -EFAULT;
		goto ioctl_error;
	}

ioctl_error:
	kfree(kdata);
	return ret;
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
				"bufid:%lld vmid:%d, size:%lld, priv_size:%ld, is_export:%d\n", found->buf_id.id, found->vmid,
				found->size, found->sz_priv, found->is_export);
	}
	spin_unlock_irqrestore(&drv_info->buf_list_lock, flags);

	return written;
}

static DEVICE_ATTR(buf_info, S_IRUGO, vdmabuf_buf_info_show, NULL);

static struct attribute *sysfs_attrs[] = {
	&dev_attr_buf_info.attr,
	NULL
};

static const struct attribute_group vdmabuf_attribute_group[] = {
	{.attrs = sysfs_attrs},
};

static const struct file_operations virtio_vdmabuf_be_fops = {
	.owner = THIS_MODULE,
	.open = virtio_vdmabuf_be_open,
	.release = virtio_vdmabuf_be_release,
	.read = virtio_vdmabuf_be_event_read,
	.poll = virtio_vdmabuf_be_event_poll,
	.unlocked_ioctl = virtio_vdmabuf_be_ioctl,
};

static struct miscdevice virtio_vdmabuf_be_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "virtio-vdmabuf-be",
	.fops = &virtio_vdmabuf_be_fops,
};

static int __init vhost_vdmabuf_init(void)
{
	int ret = 0;

	ret = misc_register(&vhost_vdmabuf_miscdev);
	if (ret) {
		pr_err("vhost-vdmabuf: driver can't be registered, ret:%d\n",
		       ret);
		return ret;
	}

	dma_coerce_mask_and_coherent(vhost_vdmabuf_miscdev.this_device,
				     DMA_BIT_MASK(64));

	drv_info = kcalloc(1, sizeof(*drv_info), GFP_KERNEL);
	if (!drv_info) {
		ret = -ENOMEM;
		goto err_drv_info_alloc;
	}

	drv_info->dev = vhost_vdmabuf_miscdev.this_device;

	hash_init(drv_info->buf_list);
	// mutex_init(&drv_info->g_mutex);
	spin_lock_init(&drv_info->vdmabuf_instances_lock);
	INIT_LIST_HEAD(&drv_info->head_vdmabuf_list);
	INIT_LIST_HEAD(&drv_info->head_client_list);
	spin_lock_init(&drv_info->buf_list_lock);

	ret = misc_register(&virtio_vdmabuf_be_miscdev);
	if (ret) {
		pr_err("virtio-vdmabuf: driver can't be registered, ret:%d\n", ret);
		goto err_vm_register;
	}
	ret = sysfs_create_group(&virtio_vdmabuf_be_miscdev.this_device->kobj,
			vdmabuf_attribute_group);
	if (ret < 0) {
		dev_err(drv_info->dev, "vdmabuf sysfs can't be registered\n");
		goto err_sysfs;
	}
	return 0;

err_sysfs:
	misc_deregister(&virtio_vdmabuf_be_miscdev);
err_vm_register:
	kfree(drv_info);
err_drv_info_alloc:
	misc_deregister(&vhost_vdmabuf_miscdev);

	return ret;
}

static void __exit vhost_vdmabuf_deinit(void)
{
	sysfs_remove_group(&virtio_vdmabuf_be_miscdev.this_device->kobj,
				vdmabuf_attribute_group);
	misc_deregister(&virtio_vdmabuf_be_miscdev);
	misc_deregister(&vhost_vdmabuf_miscdev);
	vhost_vdmabuf_del_all();

	kfree(drv_info);
	drv_info = NULL;
}

module_init(vhost_vdmabuf_init);
module_exit(vhost_vdmabuf_deinit);

MODULE_DESCRIPTION("Vhost Vdmabuf Driver");
MODULE_LICENSE("GPL and additional rights");
