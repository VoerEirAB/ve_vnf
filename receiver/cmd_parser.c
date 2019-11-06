/**
* Copyright (c) 2018-present VoerEir AB - All Rights Reserved.
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Created by Ashok Kumar <ashok@voereir.com>, Dec 2018
**/

#include <stdio.h>
#include <ctype.h>
#include <float.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>
#include <signal.h>
#include <stdbool.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_string_fns.h>


#include "parser.h"
#include "ip.h"

struct configuration config;
// Default values.
/*config.iteration_no = 0;
config.extra_timer_period = 10;
config.warm_up_time_period = 2;
config.iteration_no = 1;
config.iterations = 20;
*/
static int parse_number(const char *q_arg) {
    char *end = NULL;
    int n;

    /* parse number string */
    n = strtol(q_arg, &end, 10);
    if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    return n;
}

static int is_valid_digit(const char *c) {
    if (c == NULL)
        return 0;
    while (*c) {
        if (!isdigit(*c)) {
            return 0;
        }
        c++;
    }
    return 1;
}

static int get_ip_address_type(const char *ip_str) {
    struct in6_addr ip6;
    struct in_addr ip4;
    int type = AF_MAX;

    if(inet_pton(AF_INET6, ip_str, &ip6) == 1) {
        type = AF_INET6;
    }
    else if(inet_pton(AF_INET, ip_str, &ip4) == 1) {
        type = AF_INET;
    }

    return type;
}

static int process_ip_addr(const char *what, const char *ip_str, struct sockaddr_in *addr, struct sockaddr_in6 *addr6) {
    int ip_type = get_ip_address_type(ip_str);
    if (ip_type == AF_MAX) {
        rte_exit(EXIT_FAILURE,"Invalid IP Address\n");
    }
    else {
        char *ip = strndup(ip_str, strlen(ip_str));
        if (ip_type == AF_INET) {
            inet_pton(ip_type, ip, &addr->sin_addr);
            ipv4_addr_dump(what, &addr->sin_addr);
        } else {
            inet_pton(ip_type, ip, &addr6->sin6_addr);
            ipv6_addr_dump(what, &addr6->sin6_addr);
        }
    }
    return ip_type;
}


/* Parse the argument given in the command line of the application */
struct configuration *parse_args(int argc, char **argv) {
    int opt, retval;
    char *prgname = argv[0];
    int self_ip_type = AF_MAX;
    int remote_ip_type = AF_MAX;

    // Default values.
    config.iteration_no = 1;
    config.extra_timer_period = 10;
    config.warm_up_time_period = 2;
    config.iterations = 20;
    config.rx_queues = 1;
    /* initialize Configuration */
    //memset(&config, 0, sizeof(config));

    while ((opt = getopt(argc, argv, short_options)) != EOF) {
        switch (opt) {
        /* timer period */
        case 't':
            config.timer_period = parse_number(optarg);
            if (config.timer_period < 0) {
                rte_exit(EXIT_FAILURE, "Invalid execution time period provided.\n");
            }
            break;
        case 'w':
            config.warm_up_time_period = parse_number(optarg);
            if (config.warm_up_time_period < 0) {
                rte_exit(EXIT_FAILURE,"Invalid warmup time provided.\n");
            }
            break;
        case 'e':
            config.extra_timer_period = parse_number(optarg);
            if (config.extra_timer_period < 0) {
                rte_exit(EXIT_FAILURE,"Invalid extra timer provided.\n");
            }
            break;
        case 'i':
            self_ip_type = process_ip_addr("Self IP: ", optarg, &config.self_ipaddr, &config.self_ipaddr6);
            printf("\n\r");
            break;
        case 's':
            remote_ip_type = process_ip_addr("Remote IP: ", optarg, &config.remote_ipaddr, &config.remote_ipaddr6);
            printf("\n\r");
            break;
        /* long options */
        case 'n':
            config.iteration_no = parse_number(optarg);
            if (config.iteration_no < 0) {
                rte_exit(EXIT_FAILURE,"Invalid iteration number provided.\n");
            }
            break;
        /* long options */
        case 'q':
            config.rx_queues = parse_number(optarg);
            if (config.rx_queues < 0) {
                rte_exit(EXIT_FAILURE,"Invalid rx queues provided.\n");
            }
            break;
        /* long options */
        case 'r':
            config.iterations = parse_number(optarg);
            if (config.iterations < 0) {
                rte_exit(EXIT_FAILURE,"Invalid iteration number provided.\n");
            }
            break;
        default:
            //usage(prgname);
            break;
        }
    }

    if (config.iteration_no > config.iterations) {
        rte_exit(EXIT_FAILURE,"Current iteration number cannot be higher than iterations.\n");
    }

    if (self_ip_type != remote_ip_type) {
        rte_exit(EXIT_FAILURE, "Only same type of IP ports are supported.\n");
    }

    config.ipv4 = (self_ip_type == AF_INET) ? true : false;

    if (optind >= 0)
        argv[optind-1] = prgname;

    return &config;
}

