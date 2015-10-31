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
    //    printf("In rt, looking at: %s\n", inet_ntoa(rt_walker->dest));
    if (rt_walker->mask.s_addr != 0x0) {
      if (rt_walker->dest.s_addr == (target_ip & rt_walker->mask.s_addr)) {
	//	printf("Next hop found: %s\n", inet_ntoa(rt_walker->dest));
	if (rt_walker->gw.s_addr != 0x0) {
	  nexthop = rt_walker->gw.s_addr;
	} else {
	  //nexthop = rt_walker->dest.s_addr;
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
		   unsigned int len, uint32_t target_ip, char *interface)
{
  char *iface_out = (char *) malloc(sr_IFACE_NAMELEN);
  /* Find the next hop in the routing table and the interface
     through which to send the packet to the next hop. */
  uint32_t nexthop = sr_router_nexthop(sr, target_ip, iface_out);

  struct sr_if *iface = sr_get_interface(sr, interface);
  struct ip *ip_hdr = (struct ip *) (packet+14);
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *) packet;
  if (ip_hdr->ip_ttl <= 1) {
    /* Send ICMP time exceeded message. This is
       need for traceroute to work. */
    uint8_t *new_pkt = (uint8_t *) calloc(1, 70);
    struct sr_ethernet_hdr *new_e_hdr = (struct sr_ethernet_hdr *) new_pkt;
    struct ip *new_ip_hdr = (struct ip *) (new_pkt + 14);
    struct sr_icmphdr *new_icmp_hdr = (struct sr_icmphdr *) (new_pkt + 34);

    /* ethernet header */
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost, 6);
    memcpy(new_e_hdr->ether_shost, e_hdr->ether_dhost, 6);
    new_e_hdr->ether_type = htons(0x0800);

    /* IP header */
    new_ip_hdr->ip_hl = 5;
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(56);
    new_ip_hdr->ip_id = ip_hdr->ip_id;
    new_ip_hdr->ip_off = ip_hdr->ip_off;
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = 1;
    new_ip_hdr->ip_src.s_addr = iface->ip;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = checksum(new_ip_hdr, 20);

    /* ICMP ttl exceeded: type: 11, code: 0 */
    new_icmp_hdr->icmp_type = 11;
    new_icmp_hdr->icmp_code = 0;
    new_icmp_hdr->id = 0;
    new_icmp_hdr->seqno = 0;
    memcpy(new_pkt+42, ip_hdr, 28);
    new_icmp_hdr->icmp_chksum = 0;
    new_icmp_hdr->icmp_chksum = icmp_checksum((uint16_t *)new_icmp_hdr, 36);

    int success = sr_send_packet(sr, new_pkt, 70, interface);
    if (success != 0) {
      fprintf(stderr, "%s: Sending packet failed!\n", __func__);
    }

    return;
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
    //sr_arpcache_handle_request(sr, req); // possible race condition?
  } else {
    //Debug("ARP cache entry found: ");
    //sr_arpcache_print_entry(entry);

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

  /* TODO: verify the checksum and make sure IP packet meets the
     minimum length. */
  /* sr_ip_sanity_check() */

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
  uint32_t ip_sender = ip_hdr->ip_src.s_addr;
  uint32_t ip_target = ip_hdr->ip_dst.s_addr;

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
  
  ip_hdr2->ip_sum = 0; // set checksum field to 0
  checksum_updated = checksum(ip_hdr2, sizeof(struct ip));
  ip_hdr->ip_sum = checksum_updated;

  int success = sr_send_packet(sr, packet, ip_packet->len, ip_packet->iface_out);
  if (success != 0) {
    fprintf(stderr, "%s: Sending packet failed!\n", __func__);
  }
}


void sr_ip_handle_packet_sent2self(struct sr_instance* sr, uint8_t * packet,
				   unsigned int len, char* interface)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr;
  struct sr_icmphdr *icmp_hdr;

  e_hdr = (struct sr_ethernet_hdr *) packet;
  ip_hdr = (struct ip *) (packet+sizeof(struct sr_ethernet_hdr));
  if (ip_hdr->ip_p == 0x1) { // ICMP
    icmp_hdr = (struct sr_icmphdr *) (packet + 34);
    //    sr_icmp_print_header(icmp_hdr);
    if (icmp_hdr->icmp_type == 0x8 && icmp_hdr->icmp_code == 0x0) { // echo request
      /* Ethernet header */
      uint8_t addr_tmp[6];
      memcpy(addr_tmp, e_hdr->ether_dhost, 6);
      memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, 6);
      memcpy(e_hdr->ether_shost, addr_tmp, 6);

      /* IP header */
      struct in_addr ip_addr_tmp = ip_hdr->ip_src;
      ip_hdr->ip_src = ip_hdr->ip_dst;
      ip_hdr->ip_dst = ip_addr_tmp;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

      /* ICMP header */
      icmp_hdr->icmp_type = 0x0;
      icmp_hdr->icmp_chksum = 0x0;
      icmp_hdr->icmp_chksum = icmp_checksum((uint16_t *)icmp_hdr,
					    ntohs(ip_hdr->ip_len) - 20);
      int success = sr_send_packet(sr, packet, len, interface);
      if (success != 0) {
	fprintf(stderr, "%s: Sending packet failed!\n", __func__);
      }
    } 
  } else if (ip_hdr->ip_p == 17 || ip_hdr->ip_p == 6) { // UDP or TCP payload
    uint8_t *new_pkt = (uint8_t *) calloc(1, 70);
    struct sr_ethernet_hdr *new_e_hdr = (struct sr_ethernet_hdr *) new_pkt;
    struct ip *new_ip_hdr = (struct ip *) (new_pkt + 14);
    struct sr_icmphdr *new_icmp_hdr = (struct sr_icmphdr *) (new_pkt + 34);

    /* ethernet header */
    memcpy(new_e_hdr->ether_dhost, e_hdr->ether_shost, 6);
    memcpy(new_e_hdr->ether_shost, e_hdr->ether_dhost, 6);
    new_e_hdr->ether_type = htons(0x0800);

    /* IP header */
    new_ip_hdr->ip_hl = 5;
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(56);
    new_ip_hdr->ip_id = ip_hdr->ip_id;
    new_ip_hdr->ip_off = ip_hdr->ip_off;
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = 1;
    new_ip_hdr->ip_src = ip_hdr->ip_dst;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = checksum(new_ip_hdr, 20);

    /* ICMP port unreachable */
    new_icmp_hdr->icmp_type = 3;
    new_icmp_hdr->icmp_code = 3;
    new_icmp_hdr->id = 0;
    new_icmp_hdr->seqno = 0;
    memcpy(new_pkt+42, ip_hdr, 28);
    new_icmp_hdr->icmp_chksum = 0;
    new_icmp_hdr->icmp_chksum = icmp_checksum((uint16_t *)new_icmp_hdr, 36);

    int success = sr_send_packet(sr, new_pkt, 70, interface);
    if (success != 0) {
      fprintf(stderr, "%s: Sending packet failed!\n", __func__);
    }
  }
}
