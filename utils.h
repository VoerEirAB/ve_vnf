
/**
* Copyright (c) 2018-present VoerEir AB - All Rights Reserved.
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Created by Ashok Kumar <ashok@voereir.com>, Dec 2018
**/
#include <stdio.h>
#include <rte_ether.h>

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

static inline void dump_rx_conf(struct rte_eth_rxconf *rx){
        printf("** RX Conf **\n");
        printf("   pthresh        :%4d, hthresh          :%4d, wthresh        :%6d\n",
                rx->rx_thresh.pthresh,
                rx->rx_thresh.hthresh,
                rx->rx_thresh.wthresh);
        printf("   Free Thresh    :%4d, Drop Enable      :%4d, Deferred Start :%6d\n",
                rx->rx_free_thresh,
                rx->rx_drop_en,
                rx->rx_deferred_start);
}

static inline void dump_tx_conf(struct rte_eth_txconf *tx){
        printf("** TX Conf **\n");
        printf("   pthresh        :%4d, hthresh          :%4d, wthresh        :%6d\n",
                tx->tx_thresh.pthresh,
                tx->tx_thresh.hthresh,
                tx->tx_thresh.wthresh);
        printf("   Free Thresh    :%4d, RS Thresh        :%4d, Deferred Start :%6d, TXQ Flags:%08x\n",
                tx->tx_free_thresh,
                tx->tx_rs_thresh,
                tx->tx_deferred_start,
                tx->txq_flags);
}


static inline void dump_dev_info(struct rte_eth_dev_info *dev_info) {
        printf("\n**Device Info**\n");
        printf("   max_rx_queues  :%4d, max_tx_queues     :%4d\n",
                dev_info->max_rx_queues,
                dev_info->max_tx_queues);
        printf("   max_mac_addrs  :%4d, max_hash_mac_addrs:%4d, max_vmdq_pools:%6d\n",
                dev_info->max_mac_addrs,
                dev_info->max_hash_mac_addrs,
                dev_info->max_vmdq_pools);
        dump_rx_conf(&dev_info->default_rxconf);
        dump_tx_conf(&dev_info->default_txconf);
        printf("\n");
}

#endif
