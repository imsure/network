/*-----------------------------------------------------------------------------
 * file:  sr_icmp.h
 *
 * Description:
 *
 * Data structures and methods for handeling ARP requests/replies
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_ICMP_H
#define sr_ICMP_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

struct sr_instance;

void sr_icmp_host_unreachable(struct sr_instance *sr, struct sr_arp_request *req);
void sr_icmp_print_header(struct sr_icmphdr *hdr);
uint16_t icmp_checksum(uint16_t *buffer, int length);
void sr_icmp_echo_reply(struct sr_instance *sr, uint8_t * packet,
			unsigned int len, char* interface,
			struct sr_ethernet_hdr *e_hdr,
			struct ip *ip_hdr, struct sr_icmphdr *icmp_hdr);
void sr_icmp_port_unreach(struct sr_instance *sr, uint8_t * packet,
			  unsigned int len, char* interface,
			  struct sr_ethernet_hdr *e_hdr, struct ip *ip_hdr);

#endif /* --  sr_ICMP_H -- */
