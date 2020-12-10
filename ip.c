/**
* Copyright (c) 2018-present VoerEir AB - All Rights Reserved.
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Created by Ashok Kumar <ashok@voereir.com>, Dec 2018
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ether.h>

#include "ip.h"
#include "icmp.h"

#define DOT "."

static void
ipv4_addr_to_dot(uint32_t be_ipv4_addr, char *buf)
{
    uint32_t ipv4_addr;
    ipv4_addr = rte_be_to_cpu_32(be_ipv4_addr);
    sprintf(buf, "%d.%d.%d.%d", (ipv4_addr >> 24) & 0xFF,
        (ipv4_addr >> 16) & 0xFF, (ipv4_addr >> 8) & 0xFF,
        ipv4_addr & 0xFF);
}

static void ipv6_to_str(const uint8_t* ipv6_addr, char *buf) {
   sprintf(buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 ipv6_addr[0] & 0xFF, ipv6_addr[1] & 0xFF,
                 ipv6_addr[2] & 0xFF, ipv6_addr[3] & 0xFF,
                 ipv6_addr[4] & 0xFF, ipv6_addr[5] & 0xFF,
                 ipv6_addr[6] & 0xFF, ipv6_addr[7] & 0xFF,
                 ipv6_addr[8] & 0xFF, ipv6_addr[9] & 0xFF,
                 ipv6_addr[10] & 0xFF, ipv6_addr[11] & 0xFF,
                 ipv6_addr[12] & 0xFF, ipv6_addr[13] & 0xFF,
                 ipv6_addr[14] & 0xFF, ipv6_addr[15] & 0xFF);
}

bool is_ip6_equal(const uint8_t *a, const uint8_t *b) {
    bool equal = true;
    for(int i=0; i<IPV6_ADDR_LEN; ++i) {
        if(a[i] != b[i]) {
            equal = false;
            break;
        }
    }
    return equal;
}

void ipv4_uint32_t_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
    char buf[16];
    ipv4_addr_to_dot(be_ipv4_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
    fflush(stdout);
}

void ipv4_addr_dump(const char *what, const struct in_addr * be_ipv4_addr)
{
    char buf[16];
    ipv4_addr_to_dot(be_ipv4_addr->s_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
    fflush(stdout);
}

void ipv6_addr_dump(const char *what, const struct in6_addr *ipv6_addr)
{
    char buf[40];
    ipv6_to_str(ipv6_addr->s6_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
    fflush(stdout);
}

void ipv6_hdr_dump(const char *what, const struct rte_ipv6_hdr *ipv6_addr)
{
    char src[40], dst[40];
    ipv6_to_str(ipv6_addr->src_addr, src);
    ipv6_to_str(ipv6_addr->dst_addr, dst);
    if (what)
        printf("%s", what);
    printf("Proto: %x, Payload Length: %x, Source IP: %s, Destination IP: %s\n",
        ipv6_addr->proto, ipv6_addr->payload_len, src, dst);
    fflush(stdout);
}

void rte_ether_addr_dump(const char *what, const struct rte_ether_addr *ea)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];

    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, ea);
    if (what)
        printf("%s", what);
    printf("%s", buf);
    fflush(stdout);
}

uint16_t ipv4_hdr_cksum(struct rte_ipv4_hdr *ip_h)
{
    uint16_t *v16_h;
    uint32_t ip_cksum;

    /*
     * Compute the sum of successive 16-bit words of the IPv4 header,
     * skipping the checksum field of the header.
     */
    v16_h = (unaligned_uint16_t *) ip_h;
    ip_cksum = v16_h[0] + v16_h[1] + v16_h[2] + v16_h[3] +
        v16_h[4] + v16_h[6] + v16_h[7] + v16_h[8] + v16_h[9];

    /* reduce 32 bit checksum to 16 bits and complement it */
    ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
    ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    return (ip_cksum == 0) ? 0xFFFF : (uint16_t) ip_cksum;
}

uint16_t ipv6_pseudohdr_sum(const struct rte_ipv6_hdr *ip6_hdr)
{
    uint32_t ip6_sum;

    ip6_sum = ip6_hdr->proto + ip6_hdr->payload_len;
    for(int i=IPV6_ADDR_LEN - 1; i>0; i-= 2) {
        ip6_sum += (ip6_hdr->src_addr[i-1] << 8) + ip6_hdr->src_addr[i];
    }
    for(int i=IPV6_ADDR_LEN - 1; i>0; i-= 2) {
        ip6_sum += (ip6_hdr->dst_addr[i-1] << 8) + ip6_hdr->dst_addr[i];
    }

    /* reduce 32 bit sum to 16 bits */
    while (ip6_sum > 0xFFFF) {
        ip6_sum = (ip6_sum & 0xffff) + (ip6_sum >> 16);
    }
    return (uint16_t) ip6_sum;
}
