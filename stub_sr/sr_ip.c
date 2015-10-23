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


/*---------------------------------------------------------------------
 * Method: sr_router_default_nexthop
 * Scope:  Global
 *
 * Search and return the default next hop (in network byte order).
 *---------------------------------------------------------------------*/
uint32_t sr_router_default_nexthop(struct sr_instance* sr)
{
  struct sr_rt* rt_walker = sr->routing_table;
  uint32_t default_hop = 0;

  while(rt_walker->next) {
    if (rt_walker->mask.s_addr == 0x0 &&
	rt_walker->dest.s_addr == 0x0) {      
      default_hop = rt_walker->gw.s_addr;
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

uint32_t sr_router_nexthop(struct sr_instance* sr, uint32_t target_ip)
{
  struct sr_rt* rt_walker = sr->routing_table;
  uint32_t nexthop = 0;
  
  while(rt_walker) {
    //    printf("In rt, looking at: %s\n", inet_ntoa(rt_walker->dest));
    if (rt_walker->mask.s_addr != 0x0) {
      if (rt_walker->dest.s_addr == (target_ip & rt_walker->mask.s_addr)) {
	//	printf("Next hop found: %s\n", inet_ntoa(rt_walker->dest));
	nexthop = rt_walker->dest.s_addr;
	break;
      }
    }
    rt_walker = rt_walker->next; 
  }

  if (nexthop) return nexthop;
  else return sr_router_default_nexthop(sr);
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
 * Scope:  Global
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
		   unsigned int len, uint32_t target_ip)
{
  /* Find the next hop in the routing table and the interface
     through which to send the packet to the next hop. */
  uint32_t nexthop = sr_router_nexthop(sr, target_ip);
  char *iface_out = sr_router_interface(sr, nexthop);

  /* Debug("Target IP: "); */
  /* DebugIP(target_ip); */
  /* Debug("Next Hop: "); */
  /* DebugIP(nexthop); */
  /* Debug("Outgoing interface: %s\n", iface_out); */

  /* If packet destined to the application server, then use the
     exact target IP, not the prefix in the routing table. In
     this case, the next hop is the target itself!!! */
  if (nexthop != sr_router_default_nexthop(sr)) {
    nexthop = target_ip;
  }

  /* Look up the ARP cache. if no MAC in the ARP
     cache match target IP, send an ARP request via the
     interface corresponds to nexthop. */
  struct sr_arpcache_entry *entry = sr_arpcache_search(&(sr->arpcache), nexthop);
  
  if (entry == NULL) {
    //printf("ARP cache entry not found\n");
    /* Enqueue the ARP request for next hop. */
    struct sr_arp_request *req = sr_arpreq_enqueue(&(sr->arpcache), nexthop,
						   packet, len, iface_out);
    sr_arpcache_handle_request(sr, req); // possible race condition?
  } else {
    Debug("ARP cache entry found: ");
    sr_arpcache_print_entry(entry);

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

void sr_ip_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);

  struct sr_ethernet_hdr* e_hdr = 0; // Ethernet header
  struct ip*       ip_hdr = 0; // IP header

  /* IP header follows ethernet header. */
  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

  /* TODO: verify the checksum and make sure IP packet meets the
     minimum length. */
  /* sr_ip_sanity_check() */

  if (send_to_self(sr, ip_hdr)) {
    /* TODO: Handles IP packets send to the router itself. */
    printf("IP packet was targeted to SR. Will process it later on...\n");
  } else {
    //Debug("IP packet was NOT targeted to SR.\n");
    uint32_t ip_target = ip_hdr->ip_dst.s_addr; // target IP
    sr_ip_forward(sr, packet, len, ip_target);
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
  uint32_t ip_sender = ip_hdr->ip_src.s_addr;
  uint32_t ip_target = ip_hdr->ip_dst.s_addr;

  /* Debug("Sender IP: "); */
  /* DebugIP(ip_sender); */

  /* Debug("Target IP: "); */
  /* DebugIP(ip_target); */

  struct sr_if *if_walker = sr->if_list;
  while (if_walker) {
    if (if_walker->ip == ip_target)
      return 1;
    if_walker = if_walker->next;
  }

  return 0;
}


uint16_t checksum(struct ip *ip, int len)
{
  long sum = 0;  /* assume 32 bit long, 16 bit short */
  uint16_t *ip_walker = (uint16_t *)ip;

  while(len > 1) {
    sum += *ip_walker++;
    if(sum & 0x80000000)   /* if high order bit set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if(len)       /* take care of left over byte */
    sum += (unsigned short) *(unsigned char *)ip_walker;
          
  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

/*---------------------------------------------------------------------
 * Method: sr_ip_send_packet
 * Scope:  Global
 *
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
  
  printf("Original checksum: %d\n", ip_hdr->ip_sum);
  ip_hdr2->ip_sum = 0; // set checksum field to 0
  checksum_updated = checksum(ip_hdr2, sizeof(struct ip));
  ip_hdr->ip_sum = checksum_updated;
  printf("Computed checksum: %d\n", checksum_updated);

  int success = sr_send_packet(sr, packet, ip_packet->len, ip_packet->iface_out);
  if (success != 0) {
    fprintf(stderr, "%s: Sending packet failed!\n", __func__);
  }
}
