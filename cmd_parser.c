/**
* Copyright (c) 2018-present VoerEir AB - All Rights Reserved.
* Unauthorized copying of this file, via any medium is strictly prohibited
* Proprietary and confidential
* Created by Ashok Kumar <ashok@voereir.com>, Dec 2018
**/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>

#include <rte_ethdev.h>
#include <signal.h>
#include <stdbool.h>
#include <rte_ip.h>
#include <rte_ether.h>

#include "parser.h"

#define LEN 16 // Length for holding IP address.

char ip_string_format[LEN];
struct configuration config;

static int parse_timer_period(const char *q_arg) {
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

static int is_valid_ip_address(const char *ip) {
    char *ptr = NULL;
    int octet = 0;
    uint8_t num_octets = 0;

    if (ip == NULL)
        return 0;

    ptr = strtok(ip, DOT);
    if (ptr == NULL)
        return 0;

    while (ptr) {
        if (!is_valid_digit(ptr))
            return 0;
        octet = atoi(ptr);
        num_octets++;
        if (octet < 0 || octet > 255)
            return 0;
        ptr = strtok(NULL, DOT);
    }
    if (num_octets != 4)
        return 0;
    return 1;
}

static int parse_ip_address(const char *q_arg, char **ip) {
    char *temp_ip = NULL;
    int ret = 0;

    /* Creating a temporary copy of q_arg
     * since strtok modifies the string that it processes
     */
    temp_ip = strndup(q_arg, strlen(q_arg));
        ret = is_valid_ip_address(temp_ip);
        if (ret != 1) {
        return -1;
    }
    /* Free up the temporary copy after validation processing */
    free(temp_ip);
    /* Create a copy of q_arg which contains a valid IP address
     * This memory is being free()'d in main()
         */
    *ip = strndup(q_arg, strlen(q_arg));
    return 0;
}

/* Parse the argument given in the command line of the application */
struct configuration *parse_args(int argc, char **argv) {
    int opt, retval;
    char *prgname = argv[0];
    char *self_ip = NULL;
    char *remote_ip = NULL;

    /* initialize Configuration */
    //memset(&config, 0, sizeof(config));

    while ((opt = getopt(argc, argv, short_options)) != EOF) {

        switch (opt) {
        /* timer period */
        case 't':
            config.timer_period = parse_timer_period(optarg);
            if (config.timer_period < 0) {
                rte_exit(EXIT_FAILURE, "invalid timer period\n");
            }
            break;
        case 'w':
            break;
        case 'e':
            config.extra_timer_period = parse_timer_period(optarg);
            if (config.extra_timer_period < 0) {
                rte_exit(EXIT_FAILURE,"invalid timer period\n");
            }
            break;
        case 'i':
            retval = parse_ip_address(optarg, &self_ip);
            if (retval != 0) {
                rte_exit(EXIT_FAILURE,"invalid self IP Address\n");
            }
            strncpy(ip_string_format, self_ip, strlen(self_ip));
            inet_aton(ip_string_format, &config.self_ipaddr.sin_addr);
            ipv4_addr_dump("Self Ip: ",config.self_ipaddr.sin_addr);
            printf("\n\r");
            break;
        case 's':
            retval = parse_ip_address(optarg, &remote_ip);
            if (retval != 0) {
                rte_exit(EXIT_FAILURE,"invalid remote IP Address\n");
            }
            strncpy(ip_string_format, remote_ip, strlen(remote_ip));
            inet_aton(ip_string_format, &config.remote_ipaddr.sin_addr);
            ipv4_addr_dump("Remote Ip: ",config.remote_ipaddr.sin_addr);
            printf("\n\r");
            break;
        /* long options */
        case 'n':
            config.iteration_no = optarg;
            break;

        default:
            //usage(prgname);
            break;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    return &config;
}

