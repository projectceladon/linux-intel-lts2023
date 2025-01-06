/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR MIT) */

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

#ifndef _UAPI_LINUX_VIRTIO_VDMABUF_H
#define _UAPI_LINUX_VIRTIO_VDMABUF_H

#define MAX_SIZE_PRIV_DATA 192
#define MAX_VM_NAME_LEN 16

typedef struct {
	__u64 id;
	/* 8B long Random number */
	int rng_key[2];
} virtio_vdmabuf_buf_id_t;

struct virtio_vdmabuf_e_hdr {
	/* buf_id of new buf */
	virtio_vdmabuf_buf_id_t buf_id;
	/* size of private data */
	int size;
};

struct virtio_vdmabuf_e_data {
	struct virtio_vdmabuf_e_hdr hdr;
	/* ptr to private data */
	void __user *data;
};

#define VIRTIO_VDMABUF_IOCTL_IMPORT \
_IOC(_IOC_NONE, 'G', 2, sizeof(struct virtio_vdmabuf_import))

struct virtio_vdmabuf_import {
	/* IN parameters */
	/* vdmabuf id to be imported */
	virtio_vdmabuf_buf_id_t buf_id;
	/* flags */
	int flags;
	/* OUT parameters */
	/* exported dma buf fd */
	int fd;
};

#define VIRTIO_VDMABUF_IOCTL_EXPORT \
_IOC(_IOC_NONE, 'G', 4, sizeof(struct virtio_vdmabuf_export))
struct virtio_vdmabuf_export {
	/* IN parameters */
	/* DMA buf fd to be exported */
	int fd;
	/* exported dma buf id */
	virtio_vdmabuf_buf_id_t buf_id;
	int sz_priv;
	char *priv;
};

#define VIRTIO_VDMABUF_IOCTL_ALLOC_FD \
_IOC(_IOC_NONE, 'G', 5, sizeof(struct virtio_vdmabuf_alloc))
struct virtio_vdmabuf_alloc {
	/* IN parameters */
	uint32_t size;
	/* OUT parameters */
	int fd;
};

#define VHOST_VDMABUF_SET_ID \
_IOC(_IOC_NONE, 'G', 6, sizeof(struct vhost_vdmabuf_set))
struct vhost_vdmabuf_set {
	/* IN parameters */
	uint64_t vmid;
	/* IN parameters */
	char name[MAX_VM_NAME_LEN];
};

#define VIRTIO_VDMABUF_IOCTL_ATTACH \
_IOC(_IOC_NONE, 'G', 7, sizeof(struct virtio_vdmabuf_attach))
struct virtio_vdmabuf_attach {
	/* IN parameters */
	char name[MAX_VM_NAME_LEN];
};

#define VDMABUF_PRODUCER 0x1
#define VDMABUF_CONSUMER 0x2

#define VIRTIO_VDMABUF_IOCTL_ROLE \
_IOC(_IOC_NONE, 'G', 3, sizeof(struct virtio_vdmabuf_role))
struct virtio_vdmabuf_role {
	/* IN parameters */
	int role;
};

#define VIRTIO_VDMABUF_IOCTL_SHARED_MEM \
_IOC(_IOC_NONE, 'G', 8, sizeof(struct virtio_vdmabuf_smem))
struct virtio_vdmabuf_smem {
	/* IN parameters */
	uint64_t hva;
	uint64_t gpa;
	uint64_t size;
};

#define VIRTIO_VDMABUF_IOCTL_UNEXPORT \
_IOC(_IOC_NONE, 'G', 9, sizeof(struct virtio_vdmabuf_unexport))
struct virtio_vdmabuf_unexport {
	/* IN parameters */
	virtio_vdmabuf_buf_id_t buf_id;
};

#define VIRTIO_VDMABUF_IOCTL_QUERY_BUFINFO \
_IOC(_IOC_NONE, 'G', 10, sizeof(struct virtio_vdmabuf_query_bufinfo))
struct virtio_vdmabuf_query_bufinfo {
	/* IN parameters */
	virtio_vdmabuf_buf_id_t buf_id;
	int subcmd;
	/* OUT parameters */
	unsigned long info;
};

/* DMABUF query */
enum virtio_vdmabuf_query_cmd {
	VIRTIO_VDMABUF_QUERY_SIZE = 0x10,
	VIRTIO_VDMABUF_QUERY_PRIV_INFO_SIZE,
	VIRTIO_VDMABUF_QUERY_PRIV_INFO,
};
#endif
