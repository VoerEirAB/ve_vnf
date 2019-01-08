
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
  struct sockaddr_in ipaddr;
};

static inline size_t get_vlan_offset(struct ether_hdr *eth_hdr)
{
        uint16_t ether_type;
        size_t vlan_offset = sizeof(struct ether_hdr);
        ether_type = eth_hdr->ether_type;
        if (ether_type == rte_cpu_to_be_16(ETHER_TYPE_VLAN)) {
                struct vlan_hdr *vlan_hdr = (struct vlan_hdr *)(eth_hdr + 1);
                vlan_offset += sizeof(struct vlan_hdr);
        }
        return vlan_offset;
}

static inline void dump_mac_addr(struct ether_addr *eth_addr){
	printf("MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            eth_addr->addr_bytes[0], eth_addr->addr_bytes[1],
            eth_addr->addr_bytes[2], eth_addr->addr_bytes[3],
            eth_addr->addr_bytes[4], eth_addr->addr_bytes[5]);
 	fflush(stdout);
}
#endif
