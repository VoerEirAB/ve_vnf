
#ifndef __IP_H
#define __IP_H

#include <stdbool.h>
#include <rte_ip.h>

#define IPV6_ADDR_LEN 16    // Length of array for holding IPv6 address.
#define ROUTER_FLAG 128     // Flag of NDP advertisement.
#define SOLICITED_FLAG 64   // Flag of NDP advertisement.
#define OVERRIDE_FLAG 32    // Flag of NDP advertisement.

#define is_multicast_ipv4_addr(ipv4_addr)  \
         (((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

bool is_ip6_equal(const uint8_t *a, const uint8_t *b);

void ipv4_uint32_t_addr_dump(const char *what, const uint32_t be_ipv4_addr);

void ipv4_addr_dump(const char *what, const struct in_addr * be_ipv4_addr);

void ipv6_addr_dump(const char *what, const struct in6_addr *ipv6_addr);

void ipv6_hdr_dump(const char *what, const struct rte_ipv6_hdr *ipv6_addr);

void rte_ether_addr_dump(const char *what, const struct rte_ether_addr *ea);

uint16_t ipv4_hdr_cksum(struct rte_ipv4_hdr *ip_h);

uint16_t ipv6_pseudohdr_sum(const struct rte_ipv6_hdr *ip6_hdr);

#endif
