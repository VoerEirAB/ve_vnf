
#ifndef __ICMP_H
#define __ICMP_H

#include <rte_mbuf.h>
#include "utils.h"

/* send an echo reply message from an ipv4 packet.*/
void process_icmp_echo(struct port_conf *port, struct rte_mbuf *buf);

/* send icmp echo request. */
void generate_icmp_echo_request(struct port_conf *port, struct rte_mbuf *buf);

/*
* Process an ARP packet.
*/
void process_arp(struct port_conf *port, struct rte_mbuf *mb);
#endif
