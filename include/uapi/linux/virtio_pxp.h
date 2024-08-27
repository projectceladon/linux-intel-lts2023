/* SPDX-License-Identifier: MIT */
/*
 * Copyright(c) 2024, Intel Corporation. All rights reserved.
 */
#ifndef _LINUX_VIRTIO_PXP_H
#define _LINUX_VIRTIO_PXP_H

#include <linux/types.h>
#define MAX_RINGS 64

struct virtio_pxp_config {
	uint32_t device_idx;
	uint32_t device_vfid;
	uint32_t sessions;
};

struct virtio_pxp_set_session_req {
	__le32 action;
	__le32 pxp_tag;
	__le32 session_type;
	__le32 session_mode;
	__le32 req_session_state;
};
struct virtio_pxp_set_session_resp {
	__le32 status;
	__le32 pxp_tag;
};

struct virtio_pxp_io_message_req {
	__le32 action;
	__le32 msg_in_size;
	__le32 msg_out_buf_size;
};

struct virtio_pxp_io_message_resp {
	__le32 status;
	__le32 msg_out_ret_size;
};

struct virtio_pxp_query_tag_req {
	__le32 action;
	__le32 session_is_alive;
	__le32 pxp_tag;
};

struct virtio_pxp_query_tag_resp {
	__le32 status;
	__le32 session_is_alive;
	__le32 pxp_tag;
};

struct virtio_pxp_host_session_handle_req {
	__le32 action;
	__le32 request_type;
	__le64 host_session_handle;
};
struct virtio_pxp_host_session_handle_resp {
	__le32 status;
	__le64 host_session_handle;
};


#endif
