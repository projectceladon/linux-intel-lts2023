/* SPDX-License-Identifier: (MIT OR GPL-2.0) */

/*
 * Copyright © 2021 Intel Corporation
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
 */

#ifndef _LINUX_VIRTIO_VDMABUF_H
#define _LINUX_VIRTIO_VDMABUF_H

#include <uapi/linux/virtio_vdmabuf.h>
#include <linux/hashtable.h>

struct virtio_vdmabuf_shared_pages {
	/* cross-VM ref addr for the buffer */
	u64 ref;

	/* page array */
	struct page **pages;
	u64 **l2refs;
	u64 *l3refs;

	/* data offset in the first page
	 * and data length in the last page
	 */
	int first_ofst;
	int last_len;

	/* number of shared pages */
	int nents;

	u64 offset;
};

struct virtio_vdmabuf_buf {
	virtio_vdmabuf_buf_id_t buf_id;
	struct kref ref;

	struct dma_buf_attachment *attach;
	struct dma_buf *dma_buf;
	struct sg_table *sgt;
	struct virtio_vdmabuf_shared_pages *pages_info;
	int vmid;
	int fd;
	uint64_t size;

	bool unexport;
	/* validity of the buffer */
	bool valid;

	bool is_export;
	bool bar_mapped;
	/* set if the buffer is imported via import_ioctl */
	bool imported;

	/* size of private */
	size_t sz_priv;
	/* private data associated with the exported buffer */
	void *priv;

	struct file *filp;
	struct hlist_node node;
	void *data_priv;
};

struct virtio_vdmabuf_event {
	struct virtio_vdmabuf_e_data e_data;
	struct list_head link;
};

struct virtio_vdmabuf_event_queue {
	wait_queue_head_t e_wait;
	struct list_head e_list;

	spinlock_t e_lock;
	struct mutex e_readlock;

	/* # of pending events */
	int pending;
};

/* driver information */
struct virtio_vdmabuf_info {
	struct device *dev;

	struct list_head head_vdmabuf_list;
	struct list_head head_client_list;
	spinlock_t vdmabuf_instances_lock;

	spinlock_t buf_list_lock;
	DECLARE_HASHTABLE(buf_list, 7);

	void *priv;
	struct mutex g_mutex;
};

/* IOCTL definitions
 */
typedef int (*virtio_vdmabuf_ioctl_t)(struct file *filp, void *data);

struct virtio_vdmabuf_ioctl_desc {
	unsigned int cmd;
	int flags;
	virtio_vdmabuf_ioctl_t func;
	const char *name;
};

#define VIRTIO_VDMABUF_IOCTL_DEF(ioctl, _func, _flags)                       \
	[_IOC_NR(ioctl)] = {                                                 \
		.cmd = ioctl, .func = _func, .flags = _flags, .name = #ioctl \
	}

#define VIRTIO_VDMABUF_VMID(buf_id) ((((buf_id).id) >> 32) & 0xFFFFFFFF)

/* Messages between Host and Guest */

/* List of commands from Guest to Host:
 *
 * ------------------------------------------------------------------
 * A. NEED_VMID
 *
 *  guest asks the host to provide its vmid
 *
 * req:
 *
 * cmd: VIRTIO_VDMABUF_NEED_VMID
 *
 * ack:
 *
 * cmd: same as req
 * op[0] : vmid of guest
 *
 * ------------------------------------------------------------------
 * B. EXPORT
 *
 *  export dmabuf to host
 *
 * req:
 *
 * cmd: VIRTIO_VDMABUF_CMD_EXPORT
 * op0~op3 : HDMABUF ID
 * op4 : number of pages to be shared
 * op5 : offset of data in the first page
 * op6 : length of data in the last page
 * op7 : upper 32 bit of top-level ref of shared buf
 * op8 : lower 32 bit of top-level ref of shared buf
 * op9 : size of private data
 * op10 ~ op64: User private date associated with the buffer
 *	        (e.g. graphic buffer's meta info)
 *
 * ------------------------------------------------------------------
 *
 * List of commands from Host to Guest
 *
 * ------------------------------------------------------------------
 * A. RELEASE
 *
 *  notifying guest that the shared buffer is released by an importer
 *
 * req:
 *
 * cmd: VIRTIO_VDMABUF_CMD_DMABUF_REL
 * op0~op3 : VDMABUF ID
 *
 * ------------------------------------------------------------------
 */

/* msg structures */
struct virtio_vdmabuf_msg {
	struct list_head list;
	unsigned int cmd;
	unsigned int op[64];
};

enum {
	VDMABUF_VQ_RECV = 0,
	VDMABUF_VQ_SEND = 1,
	VDMABUF_VQ_MAX = 2,
};

enum virtio_vdmabuf_cmd {
	VIRTIO_VDMABUF_CMD_EXPORT = 0x10,
	VIRTIO_VDMABUF_CMD_DMABUF_REL,
	VIRTIO_VDMABUF_CMD_DMABUF_UNEXPORT,
};

enum virtio_vdmabuf_ops {
	VIRTIO_VDMABUF_HDMABUF_ID_ID = 0,
	VIRTIO_VDMABUF_HDMABUF_ID_RNG_KEY0,
	VIRTIO_VDMABUF_HDMABUF_ID_RNG_KEY1,
	VIRTIO_VDMABUF_NUM_PAGES_SHARED = 4,
	VIRTIO_VDMABUF_FIRST_PAGE_DATA_OFFSET,
	VIRTIO_VDMABUF_LAST_PAGE_DATA_LENGTH,
	VIRTIO_VDMABUF_REF_ADDR_UPPER_32BIT,
	VIRTIO_VDMABUF_REF_ADDR_LOWER_32BIT,
	VIRTIO_VDMABUF_PRIVATE_DATA_SIZE,
	VIRTIO_VDMABUF_PRIVATE_DATA_START
};

/* adding exported/imported vdmabuf info to hash */
static inline int virtio_vdmabuf_add_buf(struct virtio_vdmabuf_info *info,
					 struct virtio_vdmabuf_buf *new)
{
	unsigned long flags;
	spin_lock_irqsave(&info->buf_list_lock, flags);
	hash_add(info->buf_list, &new->node, new->buf_id.id);
	spin_unlock_irqrestore(&info->buf_list_lock, flags);
	return 0;
}

/* comparing two vdmabuf IDs */
static inline bool is_same_buf(virtio_vdmabuf_buf_id_t a,
			       virtio_vdmabuf_buf_id_t b)
{
	int i;

	if (a.id != b.id)
		return false;

	/* compare keys */
	for (i = 0; i < 2; i++) {
		if (a.rng_key[i] != b.rng_key[i])
			return false;
	}

	return true;
}

/* find buf for given vdmabuf ID */
static inline struct virtio_vdmabuf_buf *
virtio_vdmabuf_find_buf(struct virtio_vdmabuf_info *info,
			virtio_vdmabuf_buf_id_t *buf_id)
{
	struct virtio_vdmabuf_buf *found = NULL;
	unsigned long flags;
	spin_lock_irqsave(&info->buf_list_lock, flags);

	hash_for_each_possible(info->buf_list, found, node, buf_id->id)
		if (is_same_buf(found->buf_id, *buf_id) && found->valid)
			break;
	spin_unlock_irqrestore(&info->buf_list_lock, flags);

	return found;
}

/* find buf for given vdmabuf ID */
static inline struct virtio_vdmabuf_buf *
virtio_vdmabuf_find_and_get_buf(struct virtio_vdmabuf_info *info,
			virtio_vdmabuf_buf_id_t *buf_id)
{
	struct virtio_vdmabuf_buf *found = NULL;
	bool hit = false;
	unsigned long flags;
	spin_lock_irqsave(&info->buf_list_lock, flags);

	hash_for_each_possible(info->buf_list, found, node, buf_id->id)
		if (is_same_buf(found->buf_id, *buf_id) && found->valid) {
			if (kref_get_unless_zero(&found->ref)) {
				hit = true;
				break;
			}
		}
	spin_unlock_irqrestore(&info->buf_list_lock, flags);
	if (hit)
		return found;
	else
		return NULL;
}

/* find buf for given fd */
static inline struct virtio_vdmabuf_buf *
virtio_vdmabuf_find_buf_fd(struct virtio_vdmabuf_info *info, int fd)
{
	struct virtio_vdmabuf_buf *found = NULL;
	int i;
	unsigned long flags;
	spin_lock_irqsave(&info->buf_list_lock, flags);
	hash_for_each(info->buf_list, i, found, node)
		if (found->fd == fd)
			break;
	spin_unlock_irqrestore(&info->buf_list_lock, flags);

	return found;
}

/* delete buf from hash */
static inline int virtio_vdmabuf_del_buf(struct virtio_vdmabuf_info *info,
					 virtio_vdmabuf_buf_id_t *buf_id)
{
	struct virtio_vdmabuf_buf *found = NULL;
	unsigned long flags;
	int ret = -1;
	spin_lock_irqsave(&info->buf_list_lock, flags);

	hash_for_each_possible(info->buf_list, found, node, buf_id->id)
		if (is_same_buf(found->buf_id, *buf_id))
			break;
	if (found) {
		hash_del(&found->node);
		ret = 0;
	}
	spin_unlock_irqrestore(&info->buf_list_lock, flags);
	return ret;
}

#endif
