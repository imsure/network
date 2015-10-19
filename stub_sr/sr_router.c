/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
		     uint8_t * packet/* lent */,
		     unsigned int len,
		     char* interface/* lent */)
{
  uint8_t *ether_shost, *ether_thost;
  uint16_t ether_type;
  uint32_t ar_sip, ar_tip;
  int i;
  
  struct sr_if* iface = sr_get_interface(sr, interface); // get the ethernet interface
  struct sr_ethernet_hdr* e_hdr = 0; // Ethernet header
  struct sr_arphdr*       a_hdr = 0; // ARP header

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  e_hdr = (struct sr_ethernet_hdr*) packet;
  a_hdr = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));

  /* Extract sender MAC and IP which becomes destination */
  ether_shost = e_hdr->ether_shost;
  ar_sip = a_hdr->ar_sip;
  //  DebugMAC(ether_shost);
  //  DebugIP(ar_sip);
  //  printf("Sender IP: %u\n", ntohl(ar_sip));

  /* Extract target IP in order to get target MAC. */
  ar_tip = a_hdr->ar_tip;
  //  DebugIP(ar_tip);
  //  printf("Target IP: %u\n", ntohl(ar_tip));

  ether_thost = iface->addr; // target host MAC

  /*-- Construct ARP reply in place, ie, modify 'packet' buffer directly. --*/

  /* Ethernet header: Sender becomes target */
  for (i = 0; i < 6; ++i) {
    e_hdr->ether_dhost[i] = e_hdr->ether_shost[i];
    a_hdr->ar_tha[i] = ether_shost[i];
  }

  /* Ethernet header: fill sender's MAC */
  for (i = 0; i < 6; ++i) {
    e_hdr->ether_shost[i] = ether_thost[i];
  }

  /* ARP header */
  a_hdr->ar_op = htons(0x2);
  for (i = 0; i < 6; ++i) {
    a_hdr->ar_sha[i] = ether_thost[i];
  }
  a_hdr->ar_tip = ar_sip;
  a_hdr->ar_sip = iface->ip;

  //  DebugMAC(e_hdr->ether_dhost);

  sr_send_packet(sr, packet, len, interface);

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
