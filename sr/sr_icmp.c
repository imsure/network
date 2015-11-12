/**********************************************************************
 * file:  sr_icmp.c 
 *
 * Description:
 * 
 * This file contains all the functions that handle ICMP.
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <netinet/in.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arp.h"
#include "sr_ip.h"

void sr_icmp_print_header(struct sr_icmphdr *hdr)
{
  printf("Type: %d, code: %d, chksum: %d, id: %d, seqno: %d\n",
	 hdr->icmp_type, hdr->icmp_code, hdr->icmp_chksum,
	 hdr->id, hdr->seqno);
}

uint16_t icmp_checksum(uint16_t *buffer, int length)
{
  unsigned long sum; 

  // initialize sum to zero and loop until length (in words) is 0 
  for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words 
    sum += *buffer++;// add 1 word of buffer to sum and proceed to the next 

  // we may have an extra byte 
  if (length > 0)
    sum += *(char *)buffer;

  while (sum >> 16)
    sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16 

  return ~sum;
}


/*---------------------------------------------------------------------
 * Scope:  Global
 *
 * Send ICMP echo reply. It will be called by IP module, so pointers
 * to ethernet, ip and icmp headers will be passed as well.
 *---------------------------------------------------------------------*/

void sr_icmp_echo_reply(struct sr_instance *sr, uint8_t * packet,
			unsigned int len, char* interface,
			struct sr_ethernet_hdr *e_hdr,
			struct ip *ip_hdr, struct sr_icmphdr *icmp_hdr)
{
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


/*---------------------------------------------------------------------
 * Scope:  Global
 *
 * Send ICMP port unreachable. It will be called by IP module, so 
 * pointers to ethernet and ip headers will be passed as well.
 *---------------------------------------------------------------------*/

void sr_icmp_port_unreach(struct sr_instance *sr, uint8_t * packet,
			  unsigned int len, char* interface,
			  struct sr_ethernet_hdr *e_hdr, struct ip *ip_hdr)
{
  /* 70: minimum length for ICMP port unreachable reply. */
  uint8_t *new_pkt = (uint8_t *) calloc(1, 70); // hardcoded constant! anyway...
    
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
  new_ip_hdr->ip_len = htons(56); // hardcoded constant! anyway...
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


/*---------------------------------------------------------------------
 * Scope:  Global
 *
 * Send ICMP TTL excedded. It will be called by IP module, so 
 * pointers to ethernet and ip headers will be passed as well.
 *---------------------------------------------------------------------*/

void sr_icmp_ttl_exceeded(struct sr_instance *sr, uint8_t * packet,
			  unsigned int len, char* interface,
			  struct sr_ethernet_hdr *e_hdr, struct ip *ip_hdr)
{
  struct sr_if *iface = sr_get_interface(sr, interface);
  
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
}


/*---------------------------------------------------------------------
 * Method: sr_icmp_host_unreachable
 * Scope:  Global
 *
 * Send ICMP host unreachable to all the packets waiting on ARP
 * request 'req'.
 *---------------------------------------------------------------------*/

void sr_icmp_host_unreachable(struct sr_instance *sr, struct sr_arp_request *req)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr, *ip_hdr2;
  struct sr_icmphdr *icmp_hdr, *icmp_hdr_waited;
  uint8_t *packet_waited;
  uint16_t ip_id; // identification field in IP header

  assert(req);

  char iface_out[32];
  uint32_t default_hop = sr_router_default_nexthop(sr, iface_out);
  struct sr_arpcache_entry *entry = sr_arpcache_search(&(sr->arpcache),
						       default_hop);
  uint8_t default_mac[ETHER_ADDR_LEN];
  if (entry == NULL) {
    uint8_t *arp_req_packet = (uint8_t *) malloc(sizeof(struct sr_ethernet_hdr)
						 + sizeof(struct sr_arphdr));
    struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *) arp_req_packet;
    struct sr_arphdr *a_hdr = (struct sr_arphdr *) (arp_req_packet+
						    sizeof(struct sr_ethernet_hdr));
    struct sr_if *interface = sr_get_interface(sr, iface_out);

    /* ethernet header */
    memset(e_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN); // broadcast
    memcpy(e_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); // sender MAC
    e_hdr->ether_type = htons(ETHERTYPE_ARP);

    /* ARP payload */
    a_hdr->ar_hrd = htons(0x0001); // Ethernet
    a_hdr->ar_pro = htons(0x0800); // IPv4
    a_hdr->ar_hln = 0x06; // hardware address length: 6
    a_hdr->ar_pln = 0x04; // protocol length: 4
    a_hdr->ar_op  = htons(ARP_REQUEST); // ARP request: 1
    memcpy(a_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN); // sender MAC
    a_hdr->ar_sip = interface->ip; // sender IP
    memset(a_hdr->ar_tha, 0x0, ETHER_ADDR_LEN); // target MAC: empty
    a_hdr->ar_tip = default_hop; // target IP

    int success = sr_send_packet(sr, arp_req_packet, 42, iface_out);
    if (success != 0) {
      fprintf(stderr, "%s: Sending packet failed!\n", __func__);
    }

    //sleep(1);
    usleep(500000);
    //    sleep(1);
    //    entry = sr_arpcache_search(&(sr->arpcache), default_hop);

  } else {
    //Debug("ARP cache entry found: ");
    //sr_arpcache_print_entry(entry);
    memcpy(default_mac, entry->mac, 6);
  }

  for (struct sr_ip_packet *pkt = req->packets; pkt != NULL; pkt = pkt->next) {
    packet_waited = pkt->buf;
    uint8_t dest_mac[ETHER_ADDR_LEN], src_mac[ETHER_ADDR_LEN];
    memcpy(src_mac, packet_waited, ETHER_ADDR_LEN);
    memcpy(dest_mac, packet_waited+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    uint32_t icmp_target_ip =
      ((struct ip *)(packet_waited+sizeof(struct sr_ethernet_hdr)))->ip_src.s_addr;
    struct ip *ip_hdr_waited = (struct ip *)(packet_waited+sizeof(struct sr_ethernet_hdr));

    struct sr_if *interface = sr_get_interface_by_mac(sr, src_mac);

    /* Totol length of the to-be-sent ethernet frame:
       14 (ethernet header) + 20 (IP header) + 8 (ICMP header)
       + 28 (ICMP payload: IP header + first 8 bytes of payload
       of the IP packet we are responding to)*/
    int ether_frame_len = 70;
    uint8_t *packet_to_send = (uint8_t *) calloc(1, ether_frame_len);

    /* Fill ethernet header with the correct MAC */
    e_hdr = (struct sr_ethernet_hdr *) packet_to_send;
    memcpy(e_hdr->ether_dhost, dest_mac, ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_shost, src_mac, ETHER_ADDR_LEN);
    e_hdr->ether_type = htons(ETHERTYPE_IP);

    /*--- Fill IP header ---*/
    
    ip_hdr = (struct ip *) (packet_to_send + sizeof(struct sr_ethernet_hdr));
    /* Copy and existing IP header and modify upon it. */
    memcpy(ip_hdr, packet_waited+sizeof(struct sr_ethernet_hdr), 20);
    ip_hdr->ip_len = htons(ether_frame_len-sizeof(struct sr_ethernet_hdr));
    //    ip_hdr->ip_id = htons(rand() & 0xffff);
    ip_hdr->ip_id = ip_hdr_waited->ip_id;
    //    ip_hdr->ip_id = htons(1234);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = 0x1; // protocol: ICMP
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = interface->ip;
    ip_hdr->ip_dst = ip_hdr_waited->ip_src;
    ip_hdr->ip_off = ip_hdr_waited->ip_off;
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

    /*--- End of Filling IP header ---*/

    /*--- Fill ICMP header & payload ---*/

    icmp_hdr_waited = (struct sr_icmphdr *) (packet_waited+34);

    icmp_hdr = (struct sr_icmphdr *) (packet_to_send +
				    sizeof(struct sr_ethernet_hdr)
				    + sizeof(struct ip));
    icmp_hdr->icmp_type = 0x3; // destinational unreachable
    icmp_hdr->icmp_code = 0x1; // host unreachable
    icmp_hdr->id = 0;
    icmp_hdr->seqno = 0;
    icmp_hdr->icmp_chksum = 0;

    /* Fill ICMP payload */
    memcpy(packet_to_send+42,
	   packet_waited+sizeof(struct sr_ethernet_hdr),
	   28);

    icmp_hdr->icmp_chksum = icmp_checksum((uint16_t *)icmp_hdr, 36);
    //    sr_icmp_print_header(icmp_hdr_waited);
    //    sr_icmp_print_header(icmp_hdr);

    /*--- End of filling ICMP header & payload ---*/

    int success = sr_send_packet(sr, packet_to_send, ether_frame_len, interface->name);
    if (success != 0) {
      fprintf(stderr, "%s: Sending packet failed!\n", __func__);
    }
  }
}
