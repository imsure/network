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
 * Method: sr_ip_handler
 * Scope:  Global
 *
 * This method is called each time the router receives a IP packet
 * packet on the 'interface'.

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

void sr_ip_handler(struct sr_instance* sr, 
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
  struct ip*       ip_hdr = 0; // ARP header

  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

  if (send_to_self(sr, ip_hdr)) {
    /* TODO: Handles IP packets send to the router itself. */
    printf("IP packet was targeted to SR. Will process it later on...\n");
  } else {
    printf("IP packet was NOT targeted to SR.\n");
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
