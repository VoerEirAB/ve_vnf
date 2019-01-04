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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_mbuf.h>
#include <signal.h>
#include <stdbool.h>
#include <rte_ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_udp.h>
#include <getopt.h>

#include "utils.h"
#include "icmp.h"
#include "ip.h"
#include "parser.h"

#define RX_RING_SIZE 8192
#define TX_RING_SIZE 512
#define BUF_SIZE 2048
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 64
#define LEN 16 // Length for holding IP address.
#define DOT "."

static volatile bool force_quit;
struct ether_addr port_eth_addr;
struct port_conf port;
struct configuration *conf;

uint64_t iteration_no = 0; //Iteration number to identify current iteration.

/* Per-port statistics struct */
struct port_statistics {
    uint64_t tx;
    uint64_t rx;
    uint64_t dropped;
    uint64_t arp;
    uint64_t ipv4;
    uint64_t icmp;
    uint64_t ipv6;
    uint64_t unknown;
    uint64_t udp[];
} __rte_cache_aligned;
struct port_statistics *port_stats;

union payload_t {
        uint8_t  uint8[0];
        uint16_t uint16[0];
        uint32_t uint32[0];
        uint64_t uint64[0];
}__rte_cache_aligned;

/* Signal handler. */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        force_quit = true;
    }
}

/* Classify packets from */
static void pkt_classify(struct port_conf *port, struct configuration *config, struct rte_mbuf *m) {
    uint16_t   pType;
    struct ether_hdr *eth_hdr;
    struct udp_hdr *udp_h;
    struct ipv4_hdr *ipv4_hdr;
    struct icmp_hdr *icmphdr;
    union payload_t *payload;

    //uint32_t offset = 0; // VLAN offset. 0 in VM.
    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    pType = eth_hdr->ether_type;

    switch(rte_cpu_to_be_16(pType)) {
        case ETHER_TYPE_ARP:
            port_stats->arp++;
            process_arp(port, m);
            break;
        case ETHER_TYPE_IPv4:
            ipv4_hdr = (struct ipv4_hdr *) &eth_hdr[1];
            if (ipv4_hdr->next_proto_id == IPPROTO_ICMP) {
                icmphdr = (struct icmp_hdr *) ((char *)ipv4_hdr + sizeof(struct ipv4_hdr));
                if (icmphdr->icmp_type == IP_ICMP_ECHO_REQUEST &&
                    icmphdr->icmp_code == 0) {
                   port_stats->icmp++;
                   process_icmp_echo(port, m);
                }
                break;
            }
            if (ipv4_hdr->src_addr == config->remote_ipaddr.sin_addr.s_addr) {
                if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
                    udp_h = (struct udp_hdr *) &ipv4_hdr[1];
                    payload = (union payload_t *) &udp_h[1];
                    iteration_no = payload->uint64[0];
                    port_stats->udp[iteration_no]++;
                    port_stats->rx++;
                    break;
                 }
            }
            port_stats->unknown++;     break;
        case ETHER_TYPE_IPv6:
            port_stats->ipv6++;      break;
        default:
            port_stats->unknown++;     break;
    }
}

/* Initialize DPDK port. */
static inline int port_init(struct port_conf *port) {
    const uint16_t rx_rings = 1, tx_rings = 1;
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_dev_info dev_info;
    struct rte_mempool *mbuf_pool;
    int retval;
    uint16_t q;

    if (port->port_id >= rte_eth_dev_count())
        return -1;

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port->port_id, rx_rings, tx_rings, &eth_conf);
    if (retval != 0)
        return retval;

    /* Get device info for defaults */
    rte_eth_dev_info_get(-port->port_id, &dev_info);
    /* Allocate and set up 1 RX queue per Ethernet port. */
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.rx_free_thresh = 32;
    rxq_conf.rx_drop_en = 0;
    rxq_conf.rx_deferred_start = 0;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port->port_id, q, RX_RING_SIZE,
                rte_socket_id(), &rxq_conf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    /* Allocate and set up 1 TX queue per Ethernet port. */
    txq_conf = dev_info.default_txconf;
    txq_conf.tx_deferred_start = 0;

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port->port_id, q, TX_RING_SIZE,
                rte_socket_id(), &txq_conf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port->port_id);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    rte_eth_macaddr_get(port->port_id, &(port->eth_addr));
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
            (unsigned)port->port_id,
            port->eth_addr.addr_bytes[0], port->eth_addr.addr_bytes[1],
            port->eth_addr.addr_bytes[2], port->eth_addr.addr_bytes[3],
            port->eth_addr.addr_bytes[4], port->eth_addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_disable(port->port_id);

    return 0;
}

/*
 * Core business logic of application.
 * Process incoming packets and handle accordingly.
 */
static int
lcore_main(void *port_void_type)
{
    const uint8_t nb_ports = rte_eth_dev_count();
    const uint16_t nb_tx = 0;
    struct port_conf *port = (struct port_conf *)port_void_type;
    uint8_t portid = port->port_id;
    uint8_t index = 0;
    /* Initialize port. */
    if (port_init(port) != 0){
        rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
                portid);
        force_quit = true;
     }
    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    if (rte_eth_dev_socket_id(portid) > 0 &&
            rte_eth_dev_socket_id(portid) !=
                    (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n", portid);

    printf("\nCore %u processing packets of port_id: %u\n", rte_lcore_id(), portid);
    /* Run until the application is quit or killed. */
    while (!force_quit) {
        /* Get burst of RX packets, from first port of pair. */
        struct rte_mbuf *bufs[BURST_SIZE];
        const uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);

        if (unlikely(nb_rx == 0))
            continue;

        /* Free any unsent packets. */
        if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++){
                pkt_classify(port, conf, bufs[buf]);
                rte_pktmbuf_free(bufs[buf]);
            }
        }
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
    unsigned lcore_id = 0, result_size;
    force_quit = false;
    uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
    prev_tsc = 0;
    timer_tsc = 0;
    char result[1000];
    FILE *file_handler;
    static uint64_t timer_period = 60;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    conf = parse_args(argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Check that there is an even number of ports to send/receive on. */
    if (rte_eth_dev_count() < 1)
        rte_exit(EXIT_FAILURE, "Error: At least 1 ports is required.\n");

    lcore_id = rte_lcore_id();

    if (rte_lcore_count() < 2)
        rte_exit(EXIT_FAILURE,"\nError: No lcore enabled. At least 2 required.\n");
    lcore_id = rte_get_next_lcore(lcore_id, 1, 1);

    /* initialize port stats */
    memset(&port, 0, sizeof(port));
    port.port_id = 0;
    port.queue_id = 0;
    port.ipaddr = conf->self_ipaddr;

    /* initialize port stats */
    uint8_t len = conf->iteration_no + conf->iterations + 1;
    port_stats = malloc(sizeof(struct port_statistics) + sizeof(uint64_t) * len);
    memset(port_stats, 0, sizeof(struct port_statistics) + sizeof(uint64_t) * len);

    /* Call lcore_main on the master core only. */
    rte_eal_remote_launch(lcore_main, &port, lcore_id);

   /* convert to number of cycles */
    timer_period = conf->timer_period + conf->extra_timer_period + conf->warm_up_time_period;
    timer_period *= rte_get_timer_hz();
    prev_tsc = rte_rdtsc();
    while (!force_quit) {
        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (timer_period > 0) {
        /* advance the timer */
        timer_tsc += diff_tsc;
            /* if timer has reached its timeout */
            if (timer_tsc >= timer_period) {
              force_quit = true;
            }
        }
        prev_tsc = cur_tsc;
    }

    rte_eal_mp_wait_lcore();
    result_size = sprintf(result,"\n{"
               "\"flows\": 0,\n"
               "\"ARP_Packets\": %" PRIu64 ",\n"
               "\"IPV4_received\": %" PRIu64 ",\n"
               "\"ICMP Echo Request\": %" PRIu64 ",\n"
               "\"Unknown packets\": %" PRIu64 ",\n"
               "\"payload\" : {\n",
               port_stats->arp,
               port_stats->ipv4,
               port_stats->icmp,
               port_stats->unknown);

    for(int index=0; index < conf->iterations; index++)
        result_size += sprintf(result + result_size,"\"%d\": %" PRIu64 ",", index, port_stats->udp[index]);

    result_size += sprintf(result+result_size,"\"%"PRIu64"\": %" PRIu64 " }}", conf->iterations, port_stats->udp[conf->iterations]);
 
    printf("%s", result);
    fflush(stdout);
    free(port_stats);
    file_handler = fopen("./rxStats.txt", "w");
    if (file_handler == NULL)
        rte_exit(EXIT_FAILURE, "%s: Open %s failed\n", __func__,
                 "rxStats.txt");
    fwrite(result, 1, result_size, file_handler);
    fclose(file_handler); 
    
    return 0;
}

