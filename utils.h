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
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct port_conf {
  uint8_t port_id;
  uint8_t queue_id;
  struct rte_ether_addr eth_addr;
  uint32_t ipaddr;
  uint8_t ipaddr6[16];
};

#endif
