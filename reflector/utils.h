/**
* Copyright (c) 2018-present VoerEir AB - All Rights Reserved.
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Created by Ashok Kumar <ashok@voereir.com>, Dec 2018
**/

#ifndef __UTILS_H
#define __UTILS_H
static const struct rte_eth_conf eth_conf = {
    .rxmode = {
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 0, /**< IP checksum offload disabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 1, /**< CRC stripped by hardware */
	.hw_vlan_strip =  1, /** Always strip Vlan so no need to handle it**/
        .max_rx_pkt_len = ETHER_MAX_LEN,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct port_conf {
  uint8_t port_id;
  uint8_t queue_id;
  struct ether_addr eth_addr;
  uint32_t ipaddr;
  uint8_t ipaddr6[16];
};

#endif


