/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/*
 * Definitions for virtio SPI Controller
 *
 * Copyright (c) 2023 Intel Corporation. All rights reserved.
 */

#ifndef _UAPI_LINUX_VIRTIO_SPI_H
#define _UAPI_LINUX_VIRTIO_SPI_H

#include <linux/const.h>
#include <linux/types.h>

/* Virtio SPI Feature bits */

struct virtio_spi_config {
	/* maximum number of chip selects */
	__le16 num_cs;
} __attribute__((packed));

/**
 * struct virtio_spi_transfer_head - the virtio SPI transfer parameter header
 * @slave_id: the controlled slave chip select
 * @bits_per_word: the number of bits in each SPI transfer word
 * @cs_change: whether to deselect device before starting the next transfer
 * @tx_nbits: bus width for write transfer
 * @rx_nbits: bus width for read transfer
 * @paddings: used to pad to full dword
 * @mode: how data is clocked out and in
 * @freq: the SPI transfer speed in Hz
 * @word_delay_ns: delay between consecutive words of a transfer
 * @cs_setup_ns: delay after chipselect is asserted
 * @cs_delay_hold_ns: delay before chipselect is deasserted
 * @cs_change_delay_inactive_ns: delay between chipselect deassertion and next assertion
 */
struct virtio_spi_transfer_head {
	__u8 slave_id;
	__u8 bits_per_word;
	__u8 cs_change;
	__u8 tx_nbits;
	__u8 rx_nbits;
	__u8 paddings[3];
	__le32 mode;
	__le32 freq;
	__le32 word_delay_ns;
	__le32 cs_setup_ns;
	__le32 cs_delay_hold_ns;
	__le32 cs_change_delay_inactive_ns;
};

/**
 * struct virtio_spi_transfer_result - the virtio SPI transfer reuslt
 * @result: the processing result from the backend
 */
struct virtio_spi_transfer_result {
	__u8 result;
};

/* The final status written by the device */
#define VIRTIO_SPI_TRANS_OK	0
#define VIRTIO_SPI_TRANS_ERR	1

/**
 * struct virtio_spi_event_head - the virtio SPI event unmask request header
 * @slave_id: the controlled slave chip select
 */
struct virtio_spi_event_head {
	__u8 slave_id;
};

/**
 * struct virtio_spi_event_result - the virtio SPI event reuslt
 * @result: the irq event result from the backend
 */
struct virtio_spi_event_result {
	__u8 result;
};

/* The irq event status for the device */
#define VIRTIO_SPI_IRQ_VALID	0
#define VIRTIO_SPI_IRQ_INVALID	1

#endif /* _UAPI_LINUX_VIRTIO_SPI_H */
