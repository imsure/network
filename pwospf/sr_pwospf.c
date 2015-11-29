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
#include "sr_rt.h"

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

  assert(iface);

  ip_addr.s_addr = iface->ip;
  mask_addr.s_addr = iface->mask;

  Debug("Interface: %s  ",iface->name);
  print_mac(iface->mac);
  Debug("  (mask) %s",inet_ntoa(mask_addr));
  Debug("  (ip) %s",inet_ntoa(ip_addr));
  
  Debug("  neighbors: ");
  struct neighbor *nb = iface->nlist;
  while (nb) {
    struct in_addr rid_addr;
    struct in_addr nb_ip_addr;

    rid_addr.s_addr = nb->rid;
    nb_ip_addr.s_addr = nb->ip;
    Debug("[(rid) %s ", inet_ntoa(rid_addr));
    Debug("(ip) ");
    print_ip(nb->ip);
    Debug(" ");
    print_mac(nb->mac);
    Debug("]");
    nb = nb->next;
  }
  Debug("\n");
}

void pwospf_print_link(struct pwospf_link *link)
{
  struct in_addr subnet_addr;
  struct in_addr mask_addr;
  struct in_addr rid_addr;

  subnet_addr.s_addr = link->subnet;
  mask_addr.s_addr = link->mask;
  rid_addr.s_addr = link->nbor_rid;

  Debug("Interface: %s  ", link->interface);
  Debug("  (subnet) %s",inet_ntoa(subnet_addr));
  Debug("  (mask) %s",inet_ntoa(mask_addr));
  Debug("  (neighbor id) %s",inet_ntoa(rid_addr));  
  Debug(" (is down?) %d\n", link->isdown);
}

void pwospf_print_iflist(struct sr_instance* sr)
{
  struct pwospf_if *pwif_walker = sr->ospf_subsys->iflist;
  while (pwif_walker) {
    pwospf_print_if(pwif_walker);
    pwif_walker = pwif_walker->next;
  }
}


void pwospf_print_links(struct sr_instance* sr)
{
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  printf("\nList of links:\n");
  while (link_walker) {
    pwospf_print_link(link_walker);
    link_walker = link_walker->next;
  }
}


struct pwospf_link *pwospf_get_link_by_name(struct sr_instance* sr, char *ifname)
{
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  while (link_walker) {
    if (strcmp(link_walker->interface, ifname) == 0) {
      return link_walker;
    }
    link_walker = link_walker->next;
  }
  return NULL;
}

struct pwospf_link *pwospf_get_num_links(struct sr_instance* sr)
{
  int num_links = 0;
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  while (link_walker) {
    num_links++;
    link_walker = link_walker->next;
  }
  return num_links;
}


struct pwospf_if *get_pwospf_if_by_name(struct sr_instance* sr, char *name)
{
  struct pwospf_if *pwif_walker = sr->ospf_subsys->iflist;
  while (pwif_walker) {
    if (strcmp(pwif_walker->name, name) == 0) {
      return pwif_walker;
    }
    pwif_walker = pwif_walker->next;
  }

  return NULL;
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
 * Initlialize a list of links associated with the router.
 *
 *---------------------------------------------------------------------*/

void pwospf_init_links(struct sr_instance* sr)
{
  struct pwospf_if *pwif_walker = sr->ospf_subsys->iflist;
  struct pwospf_link *link_walker = sr->ospf_subsys->links;

  /*--- Derive link information through known interfaces ---*/
  while(pwif_walker) {
    link_walker->subnet = pwif_walker->ip & pwif_walker->mask;
    link_walker->mask = pwif_walker->mask;
    memcpy(link_walker->interface, pwif_walker->name, sr_IFACE_NAMELEN);
    link_walker->nbor_rid = 0; /* initial value, update once HELLO received */
    link_walker->isdown = 0;
    link_walker->next = NULL;
    if (pwif_walker->next) {
      link_walker->next = (struct pwospf_link *) malloc(sizeof(struct pwospf_link));
      link_walker = link_walker->next;
    }
    pwif_walker = pwif_walker->next;
  }

  /*--- Read from static routing table for default route to Internet. ---*/
  struct sr_rt* rt_walker = sr->routing_table;
  while (rt_walker) {
    if (rt_walker->mask.s_addr == 0x0 && rt_walker->dest.s_addr == 0x0) {
      link_walker->next = (struct pwospf_link *) malloc(sizeof(struct pwospf_link));
      link_walker->next->subnet = 0;
      link_walker->next->mask = 0;
      memcpy(link_walker->next->interface, rt_walker->interface, sr_IFACE_NAMELEN);
      link_walker->next->nbor_rid = 0;
      link_walker->next->isdown = 0;
      link_walker->next->next = NULL;
      break;
    }
    rt_walker = rt_walker->next;
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
    sr->ospf_subsys->links = (struct pwospf_link *)malloc(sizeof(struct pwospf_link));
    pwospf_create_iflist(sr);
    pwospf_init_links(sr);
    pwospf_print_iflist(sr);
    pwospf_print_links(sr);
    
    pwospf_get_router_id(sr);
    sr->ospf_subsys->aid = OSPF_DEFAULT_AREA_ID;
    /* Initially, set to true to flood states of links directly connect to router */
    sr->ospf_subsys->topo_changed = 1;

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

void pwospf_broadcast_hello(struct sr_instance *sr)
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
  free(hello_packet);
}


/*---------------------------------------------------------------------
 *
 * Handle received HELLO packet from neighbors.
 * Try to match the source of the HELLO packet to one of the receiving
 * interface's neighbor.
 *
 *---------------------------------------------------------------------*/

void pwospf_handle_hello(struct sr_instance *sr, uint8_t * packet,
			 unsigned int len, char* interface)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr;
  struct ospfv2_hdr *pw_hdr;
  struct ospfv2_hello_hdr *hello_hdr;

  pwospf_lock(sr->ospf_subsys);
  
  e_hdr = (struct sr_ethernet_hdr *) packet;
  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
  pw_hdr = (struct ospfv2_hdr*) (packet +
				 sizeof(struct sr_ethernet_hdr) +
				 sizeof(struct ip));
  hello_hdr = (struct ospfv2_hello_hdr*) (packet +
					  sizeof(struct sr_ethernet_hdr) +
					  sizeof(struct ip) +
					  sizeof(struct ospfv2_hdr));

  /*--- Check the network configuration (mask * helloint) of the
    received packet and that of the receiving interface. ---*/
  struct pwospf_if *iface = get_pwospf_if_by_name(sr, interface);
  if (iface->mask != hello_hdr->nmask ||
      iface->helloint != hello_hdr->helloint) {
    fprintf(stderr, "Hello header not match! Packet dropped.\n");
  } else {
    /*--- If the receiving interface doesn't have a neighbor,
      create one. ---*/
    if (!(iface->nlist)) {
      iface->nlist = (struct neighbor *) malloc(sizeof(struct neighbor));
      iface->nlist->rid = pw_hdr->rid;
      iface->nlist->ip = ip_hdr->ip_src.s_addr;
      iface->nlist->next = NULL;
      memcpy(iface->nlist->mac, e_hdr->ether_shost, ETHER_ADDR_LEN);
      iface->nlist->last_hello_received = time(NULL);

      /* Get the local link associated with the receving interface */
      struct pwospf_link *link = pwospf_get_link_by_name(sr, interface);
      link->nbor_rid = iface->nlist->rid; /* update neighbor ID of the link */

      /* adding a new neighbor indicates a topological change*/
      sr->ospf_subsys->topo_changed = 1;
      
      Debug("New neighbor added!\n");
      pwospf_print_if(iface);
      pwospf_print_links(sr);
    } else {
      struct neighbor *nbor = iface->nlist;
      int match_found = 0;
      while (nbor) {
	if (nbor->rid == pw_hdr->rid && nbor->ip == ip_hdr->ip_src.s_addr) {
	  match_found = 1; /* HELLO packet matches a current neighbor */
	  nbor->last_hello_received = time(NULL); /* update timer */
	  Debug("Last hello received timer updated\n");
	  break;
	}
	nbor = nbor->next;
      }
      if (!match_found) {
	printf("None of the interface' neighbors matches the HELLO packet\n");
	/* TODO: add a new neighbor to the list */	
      }
    }
  }

  pwospf_unlock(sr->ospf_subsys);
}


/*---------------------------------------------------------------------
 *
 * Handle received PWOSPF packet (either HELLO or LSU).
 *
 *---------------------------------------------------------------------*/

void pwospf_handle_packet(struct sr_instance *sr, uint8_t * packet,
			  unsigned int len, char* interface)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr;
  struct ospfv2_hdr *pw_hdr;

  e_hdr = (struct sr_ethernet_hdr *) packet;
  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
  pw_hdr = (struct ospfv2_hdr*) (packet +
				 sizeof(struct sr_ethernet_hdr) +
				 sizeof(struct ip));

  /*--- Check the PWOSPF header ---*/
  if (pw_hdr->version != OSPF_V2 || pw_hdr->aid != OSPF_DEFAULT_AREA_ID) {
    /* TODO: verify checksum & auth-fields */
    fprintf(stderr, "Incoming PWOSPF packet is malformed!\n");
  }

  /*--- Handle HELLO packet ---*/
  if (ip_hdr->ip_dst.s_addr == htonl(OSPF_AllSPFRouters)) {
    pwospf_handle_hello(sr, packet, len, interface);
  } else {
    printf("Received LSU\n");
  }
}


/*---------------------------------------------------------------------
 * Flood link state updates to neighbors whenever a link change is
 * detected (adding or deleting a link).
 *
 *---------------------------------------------------------------------*/

void pwospf_flood_lsu(struct sr_instance *sr)
{
  pwospf_lock(sr->ospf_subsys);

  int num_links = pwospf_get_num_links(sr);
  Debug("Number of local links: %d\n", num_links);
  uint16_t packet_size = sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) +
    + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) +
    sizeof(struct ospfv2_lsa) * num_links;
  
  uint8_t *lsu_packet = (uint8_t *)malloc(packet_size);
  
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *)lsu_packet;
  struct ip *ip_hdr = (struct ip *) (lsu_packet +
				     sizeof(struct sr_ethernet_hdr));
  struct ospfv2_hdr *pw_hdr = (struct ospfv2_hdr*) (lsu_packet +
						    sizeof(struct sr_ethernet_hdr) +
						    sizeof(struct ip));
  struct ospfv2_lsu_hdr *pw_lsu_hdr =
    (struct ospfv2_lsu_hdr *) (lsu_packet + sizeof(struct sr_ethernet_hdr) +
			       sizeof(struct ip) + sizeof(struct ospfv2_hdr));

  /* Fill ethernet header */
  e_hdr->ether_type = htons(ETHERTYPE_IP);

  /* Fill IP header */
  ip_hdr->ip_hl = (sizeof(struct ip)) / 4;
  ip_hdr->ip_v = IP_V4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(packet_size - sizeof(struct sr_ethernet_hdr));
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = OSPF_MAX_LSU_TTL;
  ip_hdr->ip_p = IPPROTO_OSPFv2;

  /* Fill PWOSPF header */
  pw_hdr->version = OSPF_V2;
  pw_hdr->type = OSPF_TYPE_LSU;
  pw_hdr->len = htons(packet_size - sizeof(struct sr_ethernet_hdr) - sizeof(struct ip));
  pw_hdr->rid = sr->ospf_subsys->rid;
  pw_hdr->aid = sr->ospf_subsys->aid;
  pw_hdr->autype = 0;
  pw_hdr->audata = 0;

  struct pwospf_if *if_walker = sr->ospf_subsys->iflist;
  while (if_walker) {
    /*--- Since each router only has one neighbor per interface,
      so I simplified a bit not to traverse the neighbor list. ---*/
    if (if_walker->nlist) { /* send lsu out of interfaces with router neighbors */
      /* Complete ethernet header */
      memcpy(e_hdr->ether_dhost, if_walker->nlist->mac, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, if_walker->mac, ETHER_ADDR_LEN);

      /* Complete IP header */
      ip_hdr->ip_src.s_addr = if_walker->ip;
      ip_hdr->ip_dst.s_addr = if_walker->nlist->ip;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

      /* PWOSPF header checksum */
      pw_hdr->csum = 0;
      pw_hdr->csum = checksum(pw_hdr, sizeof(struct ospfv2_hdr)-8);

      /* Fill LSU header */
      pw_lsu_hdr->seq = sr->ospf_subsys->last_lsu_seq_sent++;
      pw_lsu_hdr->unused = 0;
      pw_lsu_hdr->ttl = OSPF_MAX_LSU_TTL;
      pw_lsu_hdr->num_adv = num_links;

      /* Fill LSA */
      struct pwospf_link *link_walker = sr->ospf_subsys->links;
      struct ospfv2_lsa *lsa;
      int lsa_counter = 0;
      while (link_walker) {
	lsa = (struct ospfv2_lsa *)((uint8_t *)pw_lsu_hdr +
				    sizeof(struct ospfv2_lsu_hdr) +
				    sizeof(struct ospfv2_lsa) * lsa_counter);
	lsa->subnet = link_walker->subnet;
	lsa->mask = link_walker->mask;
	lsa->rid = link_walker->nbor_rid;
	
	lsa_counter++;
	link_walker = link_walker->next;
      }

      int success = sr_send_packet(sr, lsu_packet,
				   packet_size, if_walker->name);
      if (success != 0) {
	fprintf(stderr, "%s: Sending packet failed!\n", __func__);
      }
    }
    if_walker = if_walker->next;
  }

  pwospf_unlock(sr->ospf_subsys);
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
	  pwospf_broadcast_hello(sr);
	  pwospf_unlock(sr->ospf_subsys);

	  if (sr->ospf_subsys->topo_changed) {
	    pwospf_flood_lsu(sr);
	  }
	  
	  sleep(OSPF_DEFAULT_HELLOINT);
	}
	//        printf(" pwospf subsystem sleeping \n");

	//        sleep(2);
        printf(" pwospf subsystem awake \n");
    }

    return NULL;
} /* -- run_ospf_thread -- */

