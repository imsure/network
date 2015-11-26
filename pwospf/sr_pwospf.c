/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_if.h"
#include "sr_pwospf.h"
#include "sr_router.h"
#include "pwospf_protocol.h"
#include "sr_protocol.h"
#include "sr_utils.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);

void pwospf_print_if(struct pwospf_if* iface)
{
  struct in_addr ip_addr;
  struct in_addr mask_addr;

  ip_addr.s_addr = iface->ip;
  mask_addr.s_addr = iface->mask;

  Debug("Interface: %s  ",iface->name);
  print_mac(iface->mac);
  Debug("  (mask) %s",inet_ntoa(mask_addr));
  Debug("  (ip) %s",inet_ntoa(ip_addr));
  
  Debug("  neighbors: ");
  struct neighbor *nb = iface->nlist;
  struct in_addr rid_addr;
  while (nb) {
    rid_addr.s_addr = nb->rid;
    ip_addr.s_addr = nb->ip;
    Debug("[(rid) %s  (ip) %s]", inet_ntoa(rid_addr), inet_ntoa(ip_addr));
    nb = nb->next;
  }
  Debug("\n");
}

void pwospf_print_iflist(struct sr_instance* sr)
{
  struct pwospf_if *pwif_walker = sr->ospf_subsys->iflist;
  while (pwif_walker) {
    pwospf_print_if(pwif_walker);
    pwif_walker = pwif_walker->next;
  }
}

/*---------------------------------------------------------------------
 * Create the interface list for PWOSPF subsystem by copying interface
 * list of sr.
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

void pwospf_create_iflist(struct sr_instance* sr)
{
  struct sr_if* if_walker = 0;
  
  if(sr->if_list == 0) {
    printf(" Interface list empty \n");
    return;
  }

  if_walker = sr->if_list;
  struct pwospf_if *pwif_walker = sr->ospf_subsys->iflist;

  while(if_walker) {
    pwif_walker->ip = if_walker->ip;
    pwif_walker->mask = if_walker->mask;
    pwif_walker->helloint = OSPF_DEFAULT_HELLOINT;
    memcpy(pwif_walker->name, if_walker->name, sr_IFACE_NAMELEN);
    memcpy(pwif_walker->mac, if_walker->addr, 6);
    pwif_walker->nlist = NULL;

    if (if_walker->next)
      pwif_walker->next = (struct pwospf_if *)malloc(sizeof(struct pwospf_if));
    
    pwif_walker = pwif_walker->next;
    if_walker = if_walker->next;
  }
}

/*---------------------------------------------------------------------
 *
 * Get the router ID (IP of eth0) for the current router.
 *
 *---------------------------------------------------------------------*/

void pwospf_get_router_id(struct sr_instance* sr)
{
  struct sr_if *eth0 = sr_get_interface(sr, "eth0");
  sr->ospf_subsys->rid = eth0->ip;
}


/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);


    /* -- handle subsystem initialization here! -- */

    /* Initialze list of interfaces */
    sr->ospf_subsys->iflist = (struct pwospf_if *)malloc(sizeof(struct pwospf_if));
    pwospf_create_iflist(sr);
    pwospf_print_iflist(sr);
    
    pwospf_get_router_id(sr);
    sr->ospf_subsys->aid = OSPF_DEFAULT_AREA_ID;

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */


/*---------------------------------------------------------------------
 *
 * Broadcast HELLO packet to neighbors.
 *
 *---------------------------------------------------------------------*/

void pwospf_broadcase_hello(struct sr_instance *sr)
{
  uint16_t packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
    + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr);
  
  uint8_t *hello_packet = (uint8_t *)malloc(packet_size);
  
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)hello_packet;
  struct ip *ip_hdr = (struct ip *) (hello_packet +
				     sizeof(struct sr_ethernet_hdr));
  struct ospfv2_hdr *pw_hdr = (struct ospfv2_hdr*) (hello_packet +
						    sizeof(struct sr_ethernet_hdr) +
						    sizeof(struct ip));
  struct ospfv2_hello_hdr *pw_hello_hdr =
    (struct ospfv2_hello_hdr *) (hello_packet +
				 sizeof(struct sr_ethernet_hdr) +
				 sizeof(struct ip) + sizeof(struct ospfv2_hdr));

  /* Fill ethernet header */
  e_hdr->ether_type = htons(ETHERTYPE_IP);
  memset(e_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);

  /* Fill IP header */
  ip_hdr->ip_hl = (sizeof(struct ip)) / 4;
  ip_hdr->ip_v = IP_V4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(packet_size - sizeof(struct sr_ethernet_hdr));
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = OSPF_MAX_LSU_TTL;
  ip_hdr->ip_p = IPPROTO_OSPFv2;
  ip_hdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);

  /* Fill PWOSPF header */
  pw_hdr->version = OSPF_V2;
  pw_hdr->type = OSPF_TYPE_HELLO;
  pw_hdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_hello_hdr));
  pw_hdr->rid = sr->ospf_subsys->rid;
  pw_hdr->aid = sr->ospf_subsys->aid;
  pw_hdr->autype = 0;
  pw_hdr->audata = 0;

  /* Fill HELLO header */
  pw_hello_hdr->helloint = OSPF_DEFAULT_HELLOINT;
  pw_hello_hdr->padding = 0;


  /* Broadcast HELLO packets out of all interfaces */
  
  struct pwospf_if *pwif_walker = sr->ospf_subsys->iflist;
  while (pwif_walker) {
    /* set up network mask of source interface */
    pw_hello_hdr->nmask = pwif_walker->mask;

    /* PWOSPF header checksum */
    pw_hdr->csum = 0;
    pw_hdr->csum = checksum(pw_hdr, sizeof(struct ospfv2_hdr)-8);

    /* complete IP header with src address and checksum */
    ip_hdr->ip_src.s_addr = pwif_walker->ip;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

    /* complete ether header with src mac */
    memcpy(e_hdr->ether_shost, pwif_walker->mac, ETHER_ADDR_LEN);

    int success = sr_send_packet(sr, hello_packet,
				 packet_size, pwif_walker->name);
    if (success != 0) {
      fprintf(stderr, "%s: Sending packet failed!\n", __func__);
    }

    pwif_walker = pwif_walker->next;
  }
  
}


/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

	int i;
	for (i = 0; i < OSPF_DEFAULT_LSUINT; i += OSPF_DEFAULT_HELLOINT) {
	  pwospf_lock(sr->ospf_subsys);
	  pwospf_broadcase_hello(sr);
	  pwospf_unlock(sr->ospf_subsys);
	  sleep(OSPF_DEFAULT_HELLOINT);
	}
	//        printf(" pwospf subsystem sleeping \n");

	//        sleep(2);
        printf(" pwospf subsystem awake \n");
    }

    return NULL;
} /* -- run_ospf_thread -- */

