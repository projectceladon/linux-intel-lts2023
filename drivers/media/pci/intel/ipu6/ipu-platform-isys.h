/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 - 2024 Intel Corporation */

#ifndef IPU_PLATFORM_ISYS_H
#define IPU_PLATFORM_ISYS_H

#define IPU_ISYS_ENTITY_PREFIX		"Intel IPU6"

/*
 * FW support max 16 streams
 */
#define IPU_ISYS_MAX_STREAMS		16
#define NR_OF_CSI2_BE_SOC_STREAMS	16
#define NR_OF_CSI2_VC			16
#define IPU_ISYS_CSI2_ENTITY_PREFIX	"Intel IPU6 CSI-2"

#define ISYS_UNISPART_IRQS	(IPU_ISYS_UNISPART_IRQ_SW |	\
				 IPU_ISYS_UNISPART_IRQ_CSI0 |	\
				 IPU_ISYS_UNISPART_IRQ_CSI1)

/* IPU6 ISYS compression alignment */
#define IPU_ISYS_COMPRESSION_LINE_ALIGN		512
#define IPU_ISYS_COMPRESSION_HEIGHT_ALIGN	1
#define IPU_ISYS_COMPRESSION_TILE_SIZE_BYTES	512
#define IPU_ISYS_COMPRESSION_PAGE_ALIGN		0x1000
#define IPU_ISYS_COMPRESSION_TILE_STATUS_BITS	4
#define IPU_ISYS_COMPRESSION_MAX		3

#endif
