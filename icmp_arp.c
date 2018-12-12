/**
* Copyright (c) 2018-present VoerEir AB - All Rights Reserved.
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Created by Ashok Kumar <ashok@voereir.com>, Dec 2018
**/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_udp.h>
#include <rte_mbuf.h>

#include "icmp.h"
#include "ip.h"
#include "utils.h"

/* generate an echo message from an ipv4 packet.
 * ipv4 header field will not be changed */
void process_icmp_echo(struct port_conf *port, struct rte_mbuf *mbuf)
{
    struct ipv4_hdr *ip_hdr;
    struct icmp_hdr *icmp_hd;
    uint16_t queue_id = 0;
    struct rte_mbuf  *mbuf_arr[1];
    struct ether_addr eth_addr;
    struct ether_hdr *eth_h;
    uint32_t ip_addr;
    uint32_t cksum;

    eth_h = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    //ip_hdr = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr)) + sizeof(struct ether_hdr) ;
    ip_hdr = (struct ipv4_hdr *) &eth_h[1];
    //ipv4_hdr = (struct ipv4_hdr*) (rte_pktmbuf_mtod(mbuf, char *) + mbuf->l2_len);

    icmp_hd = (struct icmp_hdr *) ((char *)ip_hdr + sizeof(struct ipv4_hdr));
    /*
     * Prepare ICMP echo reply to be sent back.
     * - switch ethernet source and destinations addresses,
     * - use the request IP source address as the reply IP
     *    destination address,
     * - if the request IP destination address is a multicast
     *   address:
     *     - choose a reply IP source address different from the
     *       request IP source address,
     *     - re-compute the IP header checksum.
     *   Otherwise:
     *     - switch the request IP source and destination
     *       addresses in the reply IP header,
     *     - keep the IP header checksum unchanged.
     * - set IP_ICMP_ECHO_REPLY in ICMP header.
     * ICMP checksum is computed by assuming it is valid in the
     * echo request and not verified.
     */
     ether_addr_copy(&eth_h->s_addr, &eth_addr);
     ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
     ether_addr_copy(&eth_addr, &eth_h->d_addr);
     ip_addr = ip_hdr->src_addr;
     if (is_multicast_ipv4_addr(ip_hdr->dst_addr)) {
         uint32_t ip_src;
         ip_src = rte_be_to_cpu_32(ip_addr);
         if ((ip_src & 0x00000003) == 1)
             ip_src = (ip_src & 0xFFFFFFFC) | 0x00000002;
         else
             ip_src = (ip_src & 0xFFFFFFFC) | 0x00000001;
         ip_hdr->src_addr = rte_cpu_to_be_32(ip_src);
         ip_hdr->dst_addr = ip_addr;
         ip_hdr->hdr_checksum = ipv4_hdr_cksum(ip_hdr);
    } else {
         ip_hdr->src_addr = ip_hdr->dst_addr;
         ip_hdr->dst_addr = ip_addr;
    }
    icmp_hd->icmp_type = IP_ICMP_ECHO_REPLY;
    cksum = ~icmp_hd->icmp_cksum & 0xffff;
    cksum += ~htons(IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
    cksum += htons(IP_ICMP_ECHO_REPLY << 8);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    icmp_hd->icmp_cksum = ~cksum;

    //no need to change buf->pkt_len
    mbuf_arr[0] = mbuf;
    rte_eth_tx_burst(port->port_id, port->queue_id, mbuf_arr, 1);
}

void process_arp(struct port_conf *port, struct rte_mbuf *mb)
{
    struct rte_mbuf  *mbuf_arr[1];
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    uint16_t arp_op;
    uint16_t arp_pro;
    struct arp_hdr  *arp_h;
    uint16_t queue_id = 0;
    int l2_len;
    uint32_t ip_addr;

    eth_hdr = rte_pktmbuf_mtod(mb, struct ether_hdr *);
    ip_hdr = (struct ipv4_hdr *) &eth_hdr[1];
    //ip_hdr = rte_pktmbuf_mtod_offset(mb, struct ipv4_hdr *, sizeof(struct ether_hdr));
    l2_len = sizeof(struct ether_hdr);

    arp_h = (struct arp_hdr *) ((char *)eth_hdr + l2_len);
    arp_op = rte_cpu_to_be_16(arp_h->arp_op);

    // Do not do anything if ARP is not requested.
    if (arp_op != ARP_OP_REQUEST) {
        rte_pktmbuf_free(mb);
        return;
    }

    ipv4_addr_dump("\nARP Requested from ip=", arp_h->arp_data.arp_sip);
    fflush(stdout);

    /* Use source MAC address as destination MAC address. */
    ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
    /* Set source MAC address with MAC address of TX port */
    ether_addr_copy(&port->eth_addr, &eth_hdr->s_addr);

    arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
    ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
    ether_addr_copy(&port->eth_addr, &arp_h->arp_data.arp_sha);

    /* Swap IP addresses in ARP payload */
    ip_addr = arp_h->arp_data.arp_tip;
    arp_h->arp_data.arp_tip = arp_h->arp_data.arp_sip;
    arp_h->arp_data.arp_sip = port->ipaddr.sin_addr.s_addr;

    mbuf_arr[0] = mb;
    rte_eth_tx_burst(port->port_id, port->queue_id, mbuf_arr, 1);
}

