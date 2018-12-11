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

#define LEN 16 // Length for holding IP address.
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

static void
ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr)
{
    char buf[16];
    ipv4_addr_to_dot(be_ipv4_addr, buf);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}

static void
ether_addr_dump(const char *what, const struct ether_addr *ea)
{
    char buf[ETHER_ADDR_FMT_SIZE];

    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, ea);
    if (what)
        printf("%s", what);
    printf("%s", buf);
}

static uint16_t
ipv4_hdr_cksum(struct ipv4_hdr *ip_h)
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
