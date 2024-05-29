/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/*
 * Virtio Camera Device
 *
 * Copyright © 2022 Collabora, Ltd.
 */

#ifndef _LINUX_VIRTIO_CAMERA_H
#define _LINUX_VIRTIO_CAMERA_H

#include <linux/types.h>

enum virtio_camera_ctrl_type {
	VIRTIO_CAMERA_CMD_GET_FORMAT = 0x1,
	VIRTIO_CAMERA_CMD_SET_FORMAT,
	VIRTIO_CAMERA_CMD_TRY_FORMAT,
	VIRTIO_CAMERA_CMD_ENUM_FORMAT,
	VIRTIO_CAMERA_CMD_ENUM_SIZE,
	VIRTIO_CAMERA_CMD_CREATE_BUFFER,
	VIRTIO_CAMERA_CMD_DESTROY_BUFFER,
	VIRTIO_CAMERA_CMD_ENQUEUE_BUFFER,
	VIRTIO_CAMERA_CMD_STREAM_ON,
	VIRTIO_CAMERA_CMD_STREAM_OFF,
	VIRTIO_CAMERA_CMD_FILE_OPEN,
	VIRTIO_CAMERA_CMD_FILE_CLOSE,
	VIRTIO_CAMERA_CMD_ENUM_INTV,

	VIRTIO_CAMERA_CMD_RESP_OK_NODATA = 0x100,

	VIRTIO_CAMERA_CMD_RESP_ERR_UNSPEC = 0x200,
	VIRTIO_CAMERA_CMD_RESP_ERR_BUSY = 0x201,
	VIRTIO_CAMERA_CMD_RESP_ERR_OUT_OF_MEMORY = 0x202,
};

struct virtio_camera_config {
	__u8 name[256];
	__le32 num_virtual_cameras;
	__le32 nr_per_virtual_camera[16];
};

struct virtio_camera_mem_entry {
	__le64 addr;
	__le32 length;
};

struct virtio_camera_ctrl_hdr {
	__le32 cmd;
	__le32 index;
};

struct virtio_camera_format_size {
	union {
		__le32 min_width;
		__le32 width;
	};
	__le32 max_width;
	__le32 step_width;

	union {
		__le32 min_height;
		__le32 height;
	};
	__le32 max_height;
	__le32 step_height;
	__le32 stride;
	__le32 sizeimage;
	__le32 fps;
};

struct virtio_camera_req_format {
	__le32 pixelformat;
	struct virtio_camera_format_size size;
};

struct virtio_camera_req_buffer {
	__le32 num_entries;
	__u8 uuid[16];
	__le32 sequence;
	__le64 timestamp;
};

struct virtio_camera_op_ctrl_req {
	struct virtio_camera_ctrl_hdr header;

	union {
		struct virtio_camera_req_format format;
		struct virtio_camera_req_buffer buffer;
		__le64 padding[3];
	} u;
};

#endif
