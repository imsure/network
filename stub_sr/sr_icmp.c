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

/* uint16_t icmp_checksum(uint16_t *buffer, int length) */
/* { */
/*   long sum = 0;  /\* assume 32 bit long, 16 bit short *\/ */

/*   while(len > 1) { */
/*     sum += *icmp++; */
/*     if(sum & 0x80000000)   /\* if high order bit set, fold *\/ */
/*       sum = (sum & 0xFFFF) + (sum >> 16); */
/*     len -= 2; */
/*   } */

/*   if(len)       /\* take care of left over byte *\/ */
/*     sum += (unsigned short) *(unsigned char *)icmp; */
          
/*   while(sum>>16) */
/*     sum = (sum & 0xFFFF) + (sum >> 16); */

/*   return ~sum; */
/* } */

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
  //  sum += (sum >> 16);     // add carry 
  return ~sum;
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

  for (struct sr_ip_packet *pkt = req->packets; pkt != NULL; pkt = pkt->next) {
    packet_waited = pkt->buf;
    uint8_t dest_mac[ETHER_ADDR_LEN], src_mac[ETHER_ADDR_LEN];
    memcpy(src_mac, packet_waited, ETHER_ADDR_LEN);
    memcpy(dest_mac, packet_waited+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    uint32_t icmp_target_ip =
      ((struct ip *)(packet_waited+sizeof(struct sr_ethernet_hdr)))->ip_src.s_addr;
    struct ip *ip_hdr_waited = (struct ip *)(packet_waited+sizeof(struct sr_ethernet_hdr));
    /* Debug("Target IP of ICMP: "); */
    /* DebugIP(icmp_target_ip); */
    /* Debug("Source MAC of ICMP: "); */
    /* DebugMAC(src_mac); */
    /* Debug("Target MAC of ICMP: "); */
    /* DebugMAC(dest_mac); */

    struct sr_if *interface = sr_get_interface_by_mac(sr, src_mac);
    //    Debug("ICMP outgoing interface: %s\n", interface->name);

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
    //    ip_hdr->ip_id = ip_hdr_waited->ip_id;
    ip_hdr->ip_id = htons(1234);
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = 0x1; // protocol: ICMP
    ip_hdr->ip_sum = 0;
    //    ip_hdr->ip_src.s_addr = interface->ip;
    ip_hdr->ip_src.s_addr = interface->ip;
    ip_hdr->ip_dst = ip_hdr_waited->ip_src;
    //    ip_hdr->ip_off = IP_DF;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

    printf("IP total len: %d, ip_ttl: %d, src: ",
	   ntohs(ip_hdr->ip_len), ip_hdr->ip_ttl);
    DebugIP(ip_hdr->ip_src);
    printf("dst: ");
    DebugIP(ip_hdr->ip_dst);

    /*--- End of Filling IP header ---*/

    /*--- Fill ICMP header & payload ---*/

    icmp_hdr_waited = (struct sr_icmphdr *) (packet_waited+34);

    icmp_hdr = (struct sr_icmphdr *) (packet_to_send +
				    sizeof(struct sr_ethernet_hdr)
				    + sizeof(struct ip));
    icmp_hdr->icmp_type = 0x3; // destinational unreachable
    icmp_hdr->icmp_code = 0x1; // host unreachable
    //    icmp_hdr->id = icmp_hdr_waited->id;
    //    icmp_hdr->seqno = icmp_hdr_waited->seqno;
    icmp_hdr->id = 0;
    icmp_hdr->seqno = 0;
    //icmp_hdr->seqno = htons(28);
    icmp_hdr->icmp_chksum = 0;

    /* Fill ICMP payload */
    memcpy(packet_to_send+42,
	   packet_waited+sizeof(struct sr_ethernet_hdr),
	   28);

    icmp_hdr->icmp_chksum = icmp_checksum((uint16_t *)icmp_hdr, 36);
    sr_icmp_print_header(icmp_hdr_waited);
    sr_icmp_print_header(icmp_hdr);
    //Debug("Orinial ICMP chksum=%d\n", *(uint16_t *)(packet_waited+14+20+2));
    *(uint16_t *)(packet_waited+14+20+2) = 0x0;
    Debug("Calculated ICMP chksum=%d\n",
    	  icmp_checksum((uint16_t *)(packet_waited+14+20),
    			ntohs(ip_hdr_waited->ip_len) - 20));
    /* Debug("IP totol of the waited packet: %d\n", ntohs(ip_hdr_waited->ip_len)); */

    /*--- End of filling ICMP header & payload ---*/

    int success = sr_send_packet(sr, packet_to_send, ether_frame_len, interface->name);
    if (success != 0) {
      fprintf(stderr, "%s: Sending packet failed!\n", __func__);
    }
    Debug("ICMP msg sent\n");
  }
}
