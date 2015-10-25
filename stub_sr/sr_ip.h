/*-----------------------------------------------------------------------------
 * file:  sr_arp.h
 *
 * Description:
 *
 * Data structures and methods for handeling ARP requests/replies
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_IP_H
#define sr_IP_H

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

void sr_ip_handler(struct sr_instance* sr, uint8_t * packet,
		   unsigned int len, char* interface);

int send_to_self(struct sr_instance *sr, struct ip *ip_hdr);
uint32_t sr_router_default_nexthop(struct sr_instance* sr);
uint32_t sr_router_nexthop(struct sr_instance* sr, uint32_t target_ip);
void sr_ip_send_packet(struct sr_instance* sr,
		       struct sr_ip_packet *packet,
		       unsigned char *dest_mac);
uint16_t checksum(struct ip *ip, int len);
void sr_ip_handle_packet_sent2self(struct sr_instance* sr, uint8_t * packet,
				   unsigned int len, char* interface);


#endif /* --  sr_IP_H -- */
