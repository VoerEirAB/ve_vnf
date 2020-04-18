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

uint16_t icmp6_cksum(struct rte_icmp_hdr * icmp_hd, struct rte_ipv6_hdr * ip6_hd)
{
    uint32_t icmp_cksum;
    icmp_cksum = ipv6_pseudohdr_sum(ip6_hd);
    icmp_cksum += (icmp_hd->icmp_type << 8) + icmp_hd->icmp_code;
    if(icmp_hd->icmp_type == NDP_NEIGHBOUR_SOLICITATION || icmp_hd->icmp_type == NDP_NEIGHBOUR_ADVERTISEMENT) {
        struct ndp_hdr * ndp_hd;
        ndp_hd = (struct ndp_hdr *) icmp_hd;
        icmp_cksum += (ndp_hd->reserved[0] << 8) + ndp_hd->reserved[1];
        icmp_cksum += (ndp_hd->reserved[2] << 8) + ndp_hd->reserved[3];

        for(int i=IPV6_ADDR_LEN - 1; i>0; i-= 2) {
            icmp_cksum += (ndp_hd->address[i-1] << 8) + ndp_hd->address[i];
        }
    }

    /* reduce 32 bit checksum to 16 bits and complement it */
    while (icmp_cksum > 0xFFFF) {
        icmp_cksum = (icmp_cksum & 0xFFFF) + (icmp_cksum >> 16);
    }
    icmp_cksum = (~icmp_cksum) & 0xFFFF;
    return (icmp_cksum == 0) ? 0xFFFF : (uint16_t) icmp_cksum;
}

/* generate an echo message from an ipv4 packet.
 * ipv4 header field will not be changed */
void process_icmp_echo(struct port_conf *port, struct rte_mbuf *mbuf)
{
    struct rte_ipv4_hdr *ip_hdr;
    struct rte_icmp_hdr *icmp_hd;
    uint16_t queue_id = 0;
    struct rte_mbuf  *mbuf_arr[1];
    struct rte_ether_addr eth_addr;
    struct rte_ether_hdr *eth_h;
    uint32_t ip_addr;
    uint32_t cksum;

    eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    //ip_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr)) + sizeof(struct rte_ether_hdr) ;
    ip_hdr = (struct rte_ipv4_hdr *) &eth_h[1];
    //ipv4_hdr = (struct rte_ipv4_hdr*) (rte_pktmbuf_mtod(mbuf, char *) + mbuf->l2_len);

    icmp_hd = (struct rte_icmp_hdr *) ((char *)ip_hdr + sizeof(struct rte_ipv4_hdr));
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
     * - set RTE_IP_ICMP_ECHO_REPLY in ICMP header.
     * ICMP checksum is computed by assuming it is valid in the
     * echo request and not verified.
     */
     rte_ether_addr_copy(&eth_h->s_addr, &eth_addr);
     rte_ether_addr_copy(&eth_h->d_addr, &eth_h->s_addr);
     rte_ether_addr_copy(&eth_addr, &eth_h->d_addr);
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
    icmp_hd->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    cksum = ~icmp_hd->icmp_cksum & 0xffff;
    cksum += ~htons(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
    cksum += htons(RTE_IP_ICMP_ECHO_REPLY << 8);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    cksum = (cksum & 0xffff) + (cksum >> 16);
    icmp_hd->icmp_cksum = ~cksum;

    //no need to change buf->pkt_len
    mbuf_arr[0] = mbuf;
    rte_eth_tx_burst(port->port_id, port->queue_id, mbuf_arr, 1);
}

/* generate an icmp6 reply message from an ipv6 packet.
 */
void process_icmp6(struct port_conf *port, struct rte_mbuf *mbuf)
{
    struct rte_ipv6_hdr *ip6_hd;
    struct rte_icmp_hdr *icmp_hd;
    uint16_t queue_id = 0;
    struct rte_mbuf  *mbuf_arr[1];
    struct rte_ether_hdr *eth_h;
    uint8_t ip6_addr[IPV6_ADDR_LEN];

    eth_h = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    ip6_hd = (struct rte_ipv6_hdr *) &eth_h[1];
    // To convert the stream based interpretation to cpu interpretation
    ip6_hd->payload_len = ntohs(ip6_hd->payload_len);
    icmp_hd = (struct rte_icmp_hdr *) &ip6_hd[1];

    if(icmp_hd->icmp_type == NDP_NEIGHBOUR_SOLICITATION) {
        struct ndp_hdr *ndp_hd;
        char * p;
        ndp_hd = (struct ndp_hdr *) &ip6_hd[1];
        // To convert the stream based interpretation to cpu interpretation
        ndp_hd->icmp_cksum = ntohs(ndp_hd->icmp_cksum);

        memcpy(&ip6_addr, &ip6_hd->src_addr, IPV6_ADDR_LEN);
        memcpy(&ip6_hd->src_addr, &port->ipaddr6, IPV6_ADDR_LEN);
        memcpy(&ip6_hd->dst_addr, &ip6_addr, IPV6_ADDR_LEN);

        // Setting flags that it is in response to solicited request and should refresh the cached-entry.
        ndp_hd->reserved[0] = SOLICITED_FLAG | OVERRIDE_FLAG;
        ndp_hd->icmp_type = NDP_NEIGHBOUR_ADVERTISEMENT;

        ip6_hd->hop_limits = 255;  // max limit

        rte_ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
        rte_ether_addr_copy(&port->eth_addr, &eth_h->s_addr);

        ndp_hd->icmp_cksum = icmp6_cksum(icmp_hd, ip6_hd);

    } else if(icmp_hd->icmp_type == RTE_IP_ICMP_ECHO_REQUEST && icmp_hd->icmp_code == 0) {
        // TODO: pending reply for icmp echo
        return;
    }

    // Reversing checksum after calculation
    icmp_hd->icmp_cksum = htons(icmp_hd->icmp_cksum);

    //no need to change buf->pkt_len
    mbuf_arr[0] = mbuf;
    rte_eth_tx_burst(port->port_id, port->queue_id, mbuf_arr, 1);
}

void process_arp(struct port_conf *port, struct rte_mbuf *mb)
{
    struct rte_mbuf  *mbuf_arr[1];
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ip_hdr;
    uint16_t arp_op;
    uint16_t arp_pro;
    struct rte_arp_hdr  *arp_h;
    uint16_t queue_id = 0;
    int l2_len;
    uint32_t ip_addr;

    eth_hdr = rte_pktmbuf_mtod(mb, struct rte_ether_hdr *);
    ip_hdr = (struct rte_ipv4_hdr *) &eth_hdr[1];
    //ip_hdr = rte_pktmbuf_mtod_offset(mb, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    l2_len = sizeof(struct rte_ether_hdr);

    arp_h = (struct rte_arp_hdr *) ((char *)eth_hdr + l2_len);
    arp_op = rte_cpu_to_be_16(arp_h->arp_opcode);

    // Do not do anything if ARP is not requested.
    if (arp_op != RTE_ARP_OP_REQUEST) {
        rte_pktmbuf_free(mb);
        return;
    }

    ipv4_uint32_t_addr_dump("\nARP Requested from ip=", arp_h->arp_data.arp_sip);
    fflush(stdout);

    /* Use source MAC address as destination MAC address. */
    rte_ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
    /* Set source MAC address with MAC address of TX port */
    rte_ether_addr_copy(&port->eth_addr, &eth_hdr->s_addr);

    arp_h->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
    rte_ether_addr_copy(&port->eth_addr, &arp_h->arp_data.arp_sha);

    /* Swap IP addresses in ARP payload */
    ip_addr = arp_h->arp_data.arp_tip;
    arp_h->arp_data.arp_tip = arp_h->arp_data.arp_sip;
    arp_h->arp_data.arp_sip = port->ipaddr;

    mbuf_arr[0] = mb;
    rte_eth_tx_burst(port->port_id, port->queue_id, mbuf_arr, 1);
}

