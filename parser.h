#include <rte_ip.h>

#ifndef __VE_PARSER_H
#define __VE_PARSER_H

#define is_multicast_ipv4_addr(ipv4_addr)  \
         (((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)

#define DOT "."

struct configuration * parse_args(int argc, char **argv);

static int get_ip_address_type(const char *ip);

static int is_valid_digit(const char *c);

static int parse_number(const char *q_arg);

static int process_ip_addr(const char *what, const char *ip_str, struct sockaddr_in *addr, struct sockaddr_in6 *addr6);

struct configuration {
   uint64_t timer_period; /* default period is 60 seconds */
   uint64_t extra_timer_period; /* default extra time period of 10 sec */
   uint64_t warm_up_time_period; /* default warmup time period of 0 sec */
   struct sockaddr_in self_ipaddr; /* Self IP address. */
   struct sockaddr_in6 self_ipaddr6; /* Self IPv6 address. */
   struct sockaddr_in remote_ipaddr; /* Remote IP address. */
   struct sockaddr_in6 remote_ipaddr6; /* Remote IPv6 address. */
   uint64_t iteration_no; /* default iteration number is 1 */
   uint64_t iterations; /* default iterations are 20 */
   bool ipv4; /* Active IP Mode is IPv4 */
};

static const char short_options[] =
    "t:"  /* timer period */
    "i:"  /* self IP */
    "s:"  /* remote IP */
    "w:"  /* extra time option */
    "p:"  /* packet size */
    "j:" /* another ip */
    "e:" /* extra time defaults to 10 */
    "n:" /* iteration number*/
    "r:" /* number of iterations */
    ;

#endif
