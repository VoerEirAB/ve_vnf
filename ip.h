
#ifndef __IP_H
#define __IP_H

#define is_multicast_ipv4_addr(ipv4_addr)  \
         (((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

static void ipv4_addr_dump(const char *what, uint32_t be_ipv4_addr);

static void ether_addr_dump(const char *what, const struct ether_addr *ea);

static uint16_t ipv4_hdr_cksum(struct ipv4_hdr *ip_h);

#endif
