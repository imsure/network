/**********************************************************************
 * file:  sr_ip.c 
 *
 * Description:
 * 
 * This file contains all the functions that handle IP forwarding.
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arp.h"
#include "sr_ip.h"
#include "sr_icmp.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
 * Method: sr_router_default_nexthop
 * Scope:  Global
 *
 * Search and return the default next hop (in network byte order).
 *---------------------------------------------------------------------*/
uint32_t sr_router_default_nexthop(struct sr_instance* sr, char *iface_out)
{
  struct sr_rt* rt_walker = sr->routing_table;
  uint32_t default_hop = 0;

  while(rt_walker->next) {
    if (rt_walker->mask.s_addr == 0x0 &&
	rt_walker->dest.s_addr == 0x0) {      
      default_hop = rt_walker->gw.s_addr;
      strncpy(iface_out, rt_walker->interface, sr_IFACE_NAMELEN);
      break;
    }
    rt_walker = rt_walker->next; 
  }

  return default_hop;
}


/*---------------------------------------------------------------------
 * Method: sr_router_nexthop
 * Scope:  Global
 *
 * Search and return the next hop (in network byte order) of
 * target IP 'target_ip' (in network byte order).
 *---------------------------------------------------------------------*/

uint32_t sr_router_nexthop(struct sr_instance* sr, uint32_t target_ip,
			   char *iface_out)
{
  struct sr_rt* rt_walker = sr->routing_table;
  uint32_t nexthop = 0;
  
  while(rt_walker) {
    if (rt_walker->mask.s_addr != 0x0) {
      if (rt_walker->dest.s_addr == (target_ip & rt_walker->mask.s_addr)) {
	if (rt_walker->gw.s_addr != 0x0) {
	  nexthop = rt_walker->gw.s_addr;
	} else {
	  /* If the gateway entry is 0.0.0.0, next hop is the target,
	     the dest column is just a prefix match, not exact match. */
	  nexthop = target_ip;
	}
	strncpy(iface_out, rt_walker->interface, sr_IFACE_NAMELEN);
	break;
      }
    }
    rt_walker = rt_walker->next; 
  }

  if (nexthop) return nexthop;
  else return sr_router_default_nexthop(sr, iface_out);
}


/*---------------------------------------------------------------------
 * Method: sr_router_interface
 * Scope:  Global
 *
 * Look up the interface associate with 'ip' in the routing table.
 *---------------------------------------------------------------------*/

char *sr_router_interface(struct sr_instance* sr, uint32_t ip)
{
  struct sr_rt* rt_walker = sr->routing_table;
  char *interface = NULL;
  
  while(rt_walker) {
    if ((rt_walker->dest.s_addr == ip) ||
	(rt_walker->gw.s_addr == ip)) {
      interface = rt_walker->interface;
      break;
    }
    rt_walker = rt_walker->next; 
  }

  return interface;
}


/*---------------------------------------------------------------------
 * Method: sr_ip_forward
 * Scope:  Local
 *
 * 'sr' forward IP 'packet' with length of 'len' to target IP 'target_ip'.
 *
 * The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * HEADS UP:
 * 'packet' we received are in big-endian, so pay attention to it!
 *---------------------------------------------------------------------*/

void sr_ip_forward(struct sr_instance* sr, uint8_t * packet,
		   unsigned int len, uint32_t target_ip, char *interface)
{
  char *iface_out = (char *) malloc(sr_IFACE_NAMELEN);
  
  /* Find the next hop in the routing table and the interface
     through which to send the packet to the next hop. */
  uint32_t nexthop = sr_router_nexthop(sr, target_ip, iface_out);

  struct ip *ip_hdr = (struct ip *) (packet+14);
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *) packet;
  
  if (ip_hdr->ip_ttl <= 1) { // check TTL
    sr_icmp_ttl_exceeded(sr, packet, len, interface, e_hdr, ip_hdr);
    return;
  }

  /* Look up the ARP cache. if no MAC in the ARP
     cache match target IP, send an ARP request via the
     interface corresponds to nexthop. */
  struct sr_arpcache_entry *entry = sr_arpcache_search(&(sr->arpcache), nexthop);
  
  if (entry == NULL) {

    /* Enqueue the ARP request for next hop. */
    struct sr_arp_request *req = sr_arpreq_enqueue(&(sr->arpcache), nexthop,
						   packet, len, iface_out);
    //sr_arpcache_handle_request(sr, req); // cause potential race condition
  } else {

    /* Construct an ip_packet with necessary information and send. */
    struct sr_ip_packet ip_packet;
    ip_packet.buf = packet;
    ip_packet.len = len;
    ip_packet.iface_out = iface_out;
    sr_ip_send_packet(sr, &ip_packet, entry->mac);
  }
}


/*---------------------------------------------------------------------
 * Method: sr_ip_handler
 * Scope:  Global
 *
 * This method is called each time the router receives a IP packet.

 * The sr instance, packet buffer and the packet length
 * are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * HEADS UP:
 * 'packet' received are in big-endian, so pay attention to it!
 *---------------------------------------------------------------------*/

void sr_ip_handler(struct sr_instance* sr, uint8_t * packet,
		   unsigned int len, char* interface)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);

  struct sr_ethernet_hdr* e_hdr = 0; // Ethernet header
  struct ip*       ip_hdr = 0; // IP header

  /* IP header follows ethernet header. */
  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
  e_hdr = (struct sr_ethernet_hdr *) packet;

  /* TODO: verify the checksum and make sure IP packet meets the
     minimum length. */
  /* sr_ip_sanity_check() */

  if (ip_hdr->ip_ttl <= 1) { // check TTL
    sr_icmp_ttl_exceeded(sr, packet, len, interface, e_hdr, ip_hdr);
    return;
  }


  if (send_to_self(sr, ip_hdr)) {
    
    sr_ip_handle_packet_sent2self(sr, packet, len, interface);
    
  } else {
    
    uint32_t ip_target = ip_hdr->ip_dst.s_addr; // target IP
    sr_ip_forward(sr, packet, len, ip_target, interface);
    
  }

}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method: send_to_self
 * Scope:  Local
 *
 * This method is used to determine if an IP packet is send to the router
 * itself.
 *
 * Return true if it was send to the router, false if it's destined to
 * somewhere else, that means, sr needs to forward it.
 *
 *---------------------------------------------------------------------*/
int send_to_self(struct sr_instance *sr, struct ip *ip_hdr)
{
  uint32_t ip_target = ip_hdr->ip_dst.s_addr;

  struct sr_if *if_walker = sr->if_list;
  while (if_walker) {
    if (if_walker->ip == ip_target)
      return 1;
    if_walker = if_walker->next;
  }

  return 0;
}


/*---------------------------------------------------------------------
 * Method: sr_ip_send_packet
 * Scope:  Global
 *
 * Sends out IP packet 'ip_packet' which is targeted to 'dest_mac'.
 * Note that 'ip_packet' is not the original raw ethernet packet received
 * by sr, it wraps the real IP packet with some additional info.
 *---------------------------------------------------------------------*/

void sr_ip_send_packet(struct sr_instance* sr,
		       struct sr_ip_packet *ip_packet,
		       unsigned char *dest_mac)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr, *ip_hdr2;
  uint16_t checksum_updated;
  uint8_t *packet = ip_packet->buf;

  /* Fill ethernet header with the correct MAC */
  e_hdr = (struct sr_ethernet_hdr *) packet;
  memcpy(e_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
  struct sr_if *interface = sr_get_interface(sr, ip_packet->iface_out);
  memcpy(e_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

  /* IP header */
  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
  ip_hdr->ip_ttl--; // decrement TTL by 1

  ip_hdr2 = (struct ip *) malloc(sizeof(struct ip));
  memcpy(ip_hdr2, ip_hdr, sizeof(struct ip));
  
  ip_hdr2->ip_sum = 0; // set checksum field to 0
  /* Recompute IP header checksum */
  checksum_updated = checksum(ip_hdr2, sizeof(struct ip));
  ip_hdr->ip_sum = checksum_updated;
  free(ip_hdr2);

  int success = sr_send_packet(sr, packet, ip_packet->len, ip_packet->iface_out);
  if (success != 0) {
    fprintf(stderr, "%s: Sending packet failed!\n", __func__);
  }
}


/*------------------------------------------------------
 * Scope:  Local
 *
 * Handles IP packets targeted to sr, which means no IP
 * forwarding is needed.
 *----------------------------------------------------*/

void sr_ip_handle_packet_sent2self(struct sr_instance* sr, uint8_t * packet,
				   unsigned int len, char* interface)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr;
  struct sr_icmphdr *icmp_hdr;

  e_hdr = (struct sr_ethernet_hdr *) packet;
  ip_hdr = (struct ip *) (packet+sizeof(struct sr_ethernet_hdr));
  
  if (ip_hdr->ip_p == 0x1) { // ICMP payload
    
    icmp_hdr = (struct sr_icmphdr *) (packet + 34); // hardcoded constant! anyway...

    if (icmp_hdr->icmp_type == 0x8 &&
	icmp_hdr->icmp_code == 0x0) { // echo request

      sr_icmp_echo_reply(sr, packet, len, interface, e_hdr, ip_hdr, icmp_hdr);
    } 
  } else if (ip_hdr->ip_p == 17 || ip_hdr->ip_p == 6) { // UDP or TCP payload
    
    sr_icmp_port_unreach(sr, packet, len, interface, e_hdr, ip_hdr);
  }
}
