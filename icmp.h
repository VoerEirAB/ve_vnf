
#ifndef __ICMP_H
#define __ICMP_H

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include "utils.h"


#define NDP_NEIGHBOUR_SOLICITATION      135
#define NDP_NEIGHBOUR_ADVERTISEMENT     136

struct ndp_hdr {
	uint8_t  icmp_type;   /* ICMP packet type. */
	uint8_t  icmp_code;   /* ICMP packet code. */
	uint16_t icmp_cksum;  /* ICMP packet checksum. */
	uint8_t reserved[4];  /* Unused Reserved Bytes. */
	uint8_t address[16]; /* Target address. */
} __attribute__((__packed__));

uint16_t icmp6_cksum(struct icmp_hdr * icmp_hd, struct ipv6_hdr * ip6_hd);

/* send an echo reply message from an ipv4 packet.*/
void process_icmp_echo(struct port_conf *port, struct rte_mbuf *buf);

/* send an echo reply message from an ipv4 packet.*/
void process_icmp6(struct port_conf *port, struct rte_mbuf *buf);

/* send icmp echo request. */
void generate_icmp_echo_request(struct port_conf *port, struct rte_mbuf *buf);

/*
* Process an ARP packet.
*/
void process_arp(struct port_conf *port, struct rte_mbuf *mb);
#endif
