/**********************************************************************
 * file:  sr_arp.c 
 *
 * Description:
 * 
 * This file contains all the functions that handle ARP requests/replies.
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arp.h"

/*---------------------------------------------------------------------
 * Method: sr_arp_reply
 * Scope:  Global
 *
 * This method is called each time the router receives a ARP request
 * packet on the 'interface'. It processes ARP request that target the
 * sr and generate appropriate ARP reply and send it along 'interface'
 * back to the ARP request sender immediately.

 * The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_arp_reply(struct sr_instance* sr, 
		  uint8_t * packet/* lent */,
		  unsigned int len,
		  char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if* iface = sr_get_interface(sr, interface); // get the ethernet interface
  struct sr_ethernet_hdr* e_hdr = 0; // Ethernet header
  struct sr_arphdr*       a_hdr = 0; // ARP header

  e_hdr = (struct sr_ethernet_hdr*) packet;
  a_hdr = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));

  /*-- Construct ARP reply in place, ie, modify 'packet' buffer directly. --*/

  /* Fill Ethernet header: Sender becomes target (dest) */
  memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* Fill ARP header */
  memcpy(a_hdr->ar_tha, a_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(a_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  a_hdr->ar_op = htons(0x2); // opcode: reply
  a_hdr->ar_tip = a_hdr->ar_sip; // swap IPs
  a_hdr->ar_sip = iface->ip; // swap IPs

  int success = sr_send_packet(sr, packet, len, interface);
  if (success != 0) {
    fprintf(stderr, "%s: Sending packet failed!\n", __func__);
  }

}/* end sr_ForwardPacket */

