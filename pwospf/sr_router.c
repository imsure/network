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
#include "sr_arp.h"
#include "sr_ip.h"
#include "sr_pwospf.h"

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

    /* Initialize ARP cache and start its time out deamon thread. */
    pthread_t arp_thread;
    sr_arpcache_init(&(sr->arpcache));
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);

    pthread_create(&arp_thread, &(sr->attr),
		   sr_arpcache_timeout_handler, sr);

} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * ethernet interface are passed in as parameters. The packet is complete
 * with ethernet headers. (raw ethernet packet)
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
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr*) packet; // Ethernet header

  printf("*** -> Received packet of length %d (ether_type=%04x) at %s\n",
	 len, ntohs(e_hdr->ether_type), interface);

  /* The ethernet payload can be either ARP or IP */
  switch(ntohs(e_hdr->ether_type)) {
  case ETHERTYPE_ARP:
    sr_arp_handler(sr, packet, len, interface);
    break;
    
  case ETHERTYPE_IP:
    sr_ip_handler(sr, packet, len, interface);
    break;
    
  default:
    break;
  }

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
