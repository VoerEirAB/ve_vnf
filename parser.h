#include <rte_ip.h>

#ifndef __VE_PARSER_H
#define __VE_PARSER_H

#define is_multicast_ipv4_addr(ipv4_addr)  \
         (((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

#define DOT "."

static int parse_ip_address(const char *q_arg, char **ip);

struct configuration * parse_args(int argc, char **argv);

static int is_valid_ip_address(const char *ip);

static int is_valid_digit(const char *c);

static int parse_timer_period(const char *q_arg);

struct configuration {
   uint64_t timer_period; /* default period is 60 seconds */
   uint64_t extra_timer_period; /* default extra time period of 5 sec */
   struct sockaddr_in self_ipaddr; /* Self IP address. */
   struct sockaddr_in remote_ipaddr; /* Remote IP address. */
   uint8_t iteration_no;
};

static const char short_options[] =
    "t:"  /* timer period */
    "i:"  /* self IP */
    "s:"  /* remote IP */
    "w:"  /* extra time option */
    "p:"  /* packet size */
    "j:" /* another ip */
    "e:" /* extra time defaults to 10 */
    "n" /* iteration number*/
    ;

#endif
