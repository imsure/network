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

void pwospf_flood_lsu(struct sr_instance *sr);

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

void pwospf_print_topo_entry(struct pwospf_topo_entry *entry)
{
  printf("Sending host: ");
  print_ip(entry->sending_host);
  printf("  Source router: ");
  print_ip(entry->src_rid);
  printf("  last seq# received: %d  # of lsa: %d\n",
	 entry->last_seqnum_received, entry->num_adv);
  for (int i = 0; i < 4; ++i) {
    printf("\tsubnet: ");
    print_ip(entry->lsa_array[i].subnet);
    printf("  mask: ");
    print_ip(entry->lsa_array[i].mask);
    printf("  rid: ");
    print_ip(entry->lsa_array[i].rid);
    putchar('\n');
  }
}

void pwospf_print_topo_db(struct sr_instance *sr)
{
  printf("\nTopology DB:\n");
  for (int i = 0; i < 4; ++i)
    pwospf_print_topo_entry(&(sr->ospf_subsys->topo_entries[i]));
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

int pwospf_get_num_uplinks(struct sr_instance* sr)
{
  int num_links = 0;
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  while (link_walker) {
    if (link_walker->isdown) {
      link_walker = link_walker->next;
      continue;
    }
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

void pwospf_print_routing_entry(struct pwospf_rt* entry)
{
  printf("\t"); print_ip(entry->dest);
  printf("\t"); print_ip(entry->gw);
  printf("\t"); print_ip(entry->mask);
  printf("\t%s\n",entry->interface);
}


void pwospf_print_routing_table(struct sr_instance* sr)
{
    struct pwospf_rt* rt_walker = 0;

    if(sr->ospf_subsys->rt == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("\tDestination\tGateway\t\tMask\t\tIface\n");

    rt_walker = sr->ospf_subsys->rt;
    
    pwospf_print_routing_entry(rt_walker);
    while(rt_walker->next)
    {
        rt_walker = rt_walker->next; 
        pwospf_print_routing_entry(rt_walker);
    }
}

void pwospf_rt_delete_route2(struct sr_instance *sr, uint32_t dest, uint32_t gw)
{
  struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
  struct pwospf_rt *rt_prev, *rt_tmp;
  while (rt_walker) {
    if (rt_walker->dest == dest && rt_walker->gw == gw) {
      rt_tmp = rt_walker;
      if (rt_walker == sr->ospf_subsys->rt) {
	sr->ospf_subsys->rt = rt_walker->next;
      } else {
	rt_prev->next = rt_walker->next;
      }
      rt_walker = rt_walker->next;
      free(rt_tmp);
      continue;
    }
    rt_prev = rt_walker;
    rt_walker = rt_walker->next;
  }
}

void pwospf_rt_delete_route(struct sr_instance *sr, uint32_t dest,
			    struct pwospf_if *iface)
{
  struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
  struct pwospf_rt *rt_prev, *rt_tmp;
  rt_prev = NULL;
  /*--- Delete routes with dest as 'dest' and those use iface->nlist->ip
    as nexthop (gw) ---*/
  while (rt_walker) {
    if (rt_walker->dest == dest && rt_walker->gw == 0) {
      rt_tmp = rt_walker;
      if (rt_walker == sr->ospf_subsys->rt) {
	sr->ospf_subsys->rt = rt_walker->next;
      } else {
	rt_prev->next = rt_walker->next;
      }
      rt_walker = rt_walker->next;
      free(rt_tmp);
      continue;
    } else if (iface->nlist && iface->nlist->ip == rt_walker->gw) {
      rt_tmp = rt_walker;
      if (rt_walker == sr->ospf_subsys->rt) {
	sr->ospf_subsys->rt = rt_walker->next;
      } else {
	rt_prev->next = rt_walker->next;
      }
      rt_walker = rt_walker->next;
      free(rt_tmp);
      continue;      
    }
    rt_prev = rt_walker;
    rt_walker = rt_walker->next;
  }
}

void pwospf_init_rt(struct sr_instance *sr)
{
  struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  while (link_walker) {
    rt_walker->dest = link_walker->subnet;
    rt_walker->gw = 0; /* no gateway for subnet directly connected to router */
    rt_walker->mask = link_walker->mask;
    memcpy(rt_walker->interface, link_walker->interface, sr_IFACE_NAMELEN);
    rt_walker->next = NULL;
    
    if (link_walker->next) {
      if (link_walker->next->subnet == 0 && link_walker->next->mask == 0) {
	break;
      }

      rt_walker->next = (struct pwospf_rt *)malloc(sizeof(struct pwospf_rt));
    }
    rt_walker = rt_walker->next;
    link_walker = link_walker->next;
  }
}

uint32_t pwospf_rt_default_nexthop(struct sr_instance* sr, char *iface_out)
{
  pwospf_lock(sr->ospf_subsys);
  struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
  uint32_t default_hop = 0;

  while(rt_walker) {
    if (rt_walker->mask == 0x0 && rt_walker->dest == 0x0) {      
      default_hop = rt_walker->gw;
      strncpy(iface_out, rt_walker->interface, sr_IFACE_NAMELEN);
      break;
    }
    rt_walker = rt_walker->next; 
  }

  pwospf_unlock(sr->ospf_subsys);
  return default_hop;
}

uint32_t pwospf_rt_nexthop(struct sr_instance* sr,
			   uint32_t target_ip,
			   char *iface_out)
{
  struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
  uint32_t nexthop = 0;

  pwospf_lock(sr->ospf_subsys);

  /* printf("Target IP: "); */
  /* print_ip(target_ip); */
  /* printf("\n"); */
  while(rt_walker) {
    if (rt_walker->mask != 0x0) {
      if (rt_walker->dest == (target_ip & rt_walker->mask)) {
	if (rt_walker->gw != 0x0) {
	  nexthop = rt_walker->gw;
	} else {
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

  pwospf_unlock(sr->ospf_subsys);

  return nexthop;
}

uint32_t pwospf_ftable_default_nexthop(struct sr_instance* sr, char *iface_out)
{
  pwospf_lock(sr->ospf_subsys);
  uint32_t default_hop = 0;

  for (int i = 0; i < sr->ospf_subsys->ftable_size; ++i) {
    struct pwospf_ftable entry = sr->ospf_subsys->ft[i];
    if (entry.mask == 0x0 && entry.dest == 0x0) {      
      default_hop = entry.gw;
      strncpy(iface_out, entry.interface, sr_IFACE_NAMELEN);
      break;
    }
  }

  pwospf_unlock(sr->ospf_subsys);
  return default_hop;
}

uint32_t pwospf_ftable_nexthop(struct sr_instance* sr,
			       uint32_t target_ip, char *iface_out)
{
  uint32_t nexthop = 0;
  pwospf_lock(sr->ospf_subsys);
  
  for (int i = 0; i < sr->ospf_subsys->ftable_size; ++i) {
    struct pwospf_ftable entry = sr->ospf_subsys->ft[i];
    if (entry.mask != 0) { /* Ignore the default route to Internet */
      if (entry.dest == (target_ip & entry.mask)) {
	if (entry.gw != 0) {
	  nexthop = entry.gw;
	} else {
	  nexthop = target_ip;
	}
	strncpy(iface_out, entry.interface, sr_IFACE_NAMELEN);
	break;
      }
    }
  }
  pwospf_unlock(sr->ospf_subsys);

  return nexthop;  
}

void pwospf_print_ft_entry(struct pwospf_ftable *entry)
{
  printf("\t"); print_ip(entry->dest);
  printf("\t"); print_ip(entry->gw);
  printf("\t"); print_ip(entry->mask);
  printf("\t%s\n",entry->interface);
}


void pwospf_print_ftable(struct sr_instance* sr)
{
    printf("Forwarding Table:\n");
    printf("\tDestination\tGateway\t\tMask\t\tIface\n");

    for (int i = 0; i < sr->ospf_subsys->ftable_size; ++i)
    {
      pwospf_print_ft_entry(&(sr->ospf_subsys->ft[i]));
    }
}

void pwospf_clear_ftable(struct sr_instance *sr)
{
  for (int i = 0; i < 20; ++i) {
    memset(&(sr->ospf_subsys->ft[i]), 0, sizeof(struct pwospf_ftable));
  }
  sr->ospf_subsys->ftable_size = 0;
}

int is_direct_subnet(struct sr_instance *sr, uint32_t subnet)
{
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  while (link_walker) {
    if (link_walker->subnet == subnet) {
      return 1;
    }
    link_walker = link_walker->next;
  }
  return 0;
}

void pwospf_compute_shortest_path(struct sr_instance *sr)
{
  pwospf_clear_ftable(sr);

  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  int entry_cnt = 0;

  /*-- Routes to the directly connected subnets,
    one hop only, thus is the shortest --*/
  while (link_walker) {
    if (link_walker->isdown) { /* Ignore failed links */
      link_walker = link_walker->next;
      continue;
    }
    if (link_walker->subnet == 0 && link_walker->mask == 0) {
      link_walker = link_walker->next;
      continue;
    }

    sr->ospf_subsys->ft[entry_cnt].dest = link_walker->subnet;
    /* no gateway for subnet directly connected to router */
    sr->ospf_subsys->ft[entry_cnt].gw = 0; 
    sr->ospf_subsys->ft[entry_cnt].mask = link_walker->mask;
    memcpy(sr->ospf_subsys->ft[entry_cnt].interface,
	   link_walker->interface, sr_IFACE_NAMELEN);
    entry_cnt++;

    link_walker = link_walker->next;
  }
  
  /*-- Shortest path derived from topo DB --*/
  
  /* For each neighbor, check if there is an topo entry for it. */
  struct pwospf_if *if_walker = sr->ospf_subsys->iflist;
  while (if_walker) {
    if (if_walker->nlist && if_walker->nlist->rid != 0) {
      int found_nbor_match = 0;
      for (int i = 0; i < 4; ++i) {
	if (sr->ospf_subsys->topo_entries[i].src_rid == if_walker->nlist->rid &&
	    sr->ospf_subsys->topo_entries[i].sending_host == if_walker->nlist->ip) {
	  found_nbor_match = 1;
	  for (int j = 0; j < sr->ospf_subsys->topo_entries[i].num_adv; ++j) {
	    struct ospfv2_lsa lsa = sr->ospf_subsys->topo_entries[i].lsa_array[j];
	    if (!is_direct_subnet(sr, lsa.subnet)) {
	      sr->ospf_subsys->ft[entry_cnt].dest = lsa.subnet;
	      sr->ospf_subsys->ft[entry_cnt].gw =
		sr->ospf_subsys->topo_entries[i].sending_host; 
	      sr->ospf_subsys->ft[entry_cnt].mask = lsa.mask;
	      memcpy(sr->ospf_subsys->ft[entry_cnt].interface,
		     if_walker->name, sr_IFACE_NAMELEN);
	      entry_cnt++;
	    }
	  }
	  break;
	}
      }
      if (!found_nbor_match) {
	for (int i = 0; i < 4; ++i) {
	  if (sr->ospf_subsys->topo_entries[i].src_rid == if_walker->nlist->rid &&
	      sr->ospf_subsys->topo_entries[i].sending_host != if_walker->nlist->ip) {
	    struct pwospf_if *if_walker2 = sr->ospf_subsys->iflist;
	    while (if_walker2) {
	      if (if_walker2->nlist && (if_walker2->nlist->ip == sr->ospf_subsys->topo_entries[i].sending_host)) {
		break;
	      }
	      if_walker2 = if_walker2->next;
	    }

	    for (int j = 0; j < sr->ospf_subsys->topo_entries[i].num_adv; ++j) {
	      struct ospfv2_lsa lsa = sr->ospf_subsys->topo_entries[i].lsa_array[j];
	      if (!is_direct_subnet(sr, lsa.subnet)) {
		sr->ospf_subsys->ft[entry_cnt].dest = lsa.subnet;
		sr->ospf_subsys->ft[entry_cnt].gw =
		  sr->ospf_subsys->topo_entries[i].sending_host; 
		sr->ospf_subsys->ft[entry_cnt].mask = lsa.mask;
		memcpy(sr->ospf_subsys->ft[entry_cnt].interface,
		       if_walker2->name, sr_IFACE_NAMELEN);
		entry_cnt++;
	      }
	    }
	    break;
	  }
	}
      }
    }
    if_walker = if_walker->next;
  }
  sr->ospf_subsys->ftable_size = entry_cnt;
}

void pwospf_init_ftable(struct sr_instance *sr)
{
  int entry_cnt = 0;
  struct pwospf_link *link_walker = sr->ospf_subsys->links;
  while (link_walker) {
    if (link_walker->subnet == 0 && link_walker->mask == 0) {
      link_walker = link_walker->next;
      continue;
    }
    sr->ospf_subsys->ft[entry_cnt].dest = link_walker->subnet;
    /* no gateway for subnet directly connected to router */
    sr->ospf_subsys->ft[entry_cnt].gw = 0; 
    sr->ospf_subsys->ft[entry_cnt].mask = link_walker->mask;
    memcpy(sr->ospf_subsys->ft[entry_cnt].interface,
	   link_walker->interface, sr_IFACE_NAMELEN);
    entry_cnt++;

    link_walker = link_walker->next;
  }
  sr->ospf_subsys->ftable_size = entry_cnt;
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

    /* Initialze list of interfaces, links and rt */
    sr->ospf_subsys->iflist = (struct pwospf_if *)malloc(sizeof(struct pwospf_if));
    sr->ospf_subsys->links = (struct pwospf_link *)malloc(sizeof(struct pwospf_link));
    sr->ospf_subsys->rt = (struct pwospf_rt *)malloc(sizeof(struct pwospf_rt));

    pwospf_create_iflist(sr);
    pwospf_init_links(sr);
    pwospf_init_rt(sr);
    pwospf_print_iflist(sr);
    pwospf_print_links(sr);
    //    pwospf_print_routing_table(sr);
    pwospf_init_ftable(sr);
    pwospf_print_ftable(sr);
    
    pwospf_get_router_id(sr);
    sr->ospf_subsys->aid = OSPF_DEFAULT_AREA_ID;
    /* Start LSU periodically flooding timer */
    sr->ospf_subsys->last_lsu_sent = time(NULL);

    /* Indicate empty entries and mark all entries as invalid */
    for (int i = 0; i < 4; ++i) {
      sr->ospf_subsys->topo_entries[i].src_rid = 0;
      sr->ospf_subsys->topo_entries[i].sending_host = 0;
      memset(&(sr->ospf_subsys->topo_entries[i].lsa_array),
	   0xff, sizeof(struct ospfv2_lsa) * 4);
    }

    //pwospf_print_topo_db(sr);

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
      iface->nlist->islost = 0;
      iface->nlist->next = NULL;
      memcpy(iface->nlist->mac, e_hdr->ether_shost, ETHER_ADDR_LEN);
      iface->nlist->last_hello_received = time(NULL);

      /* Get the local link associated with the receving interface */
      struct pwospf_link *link = pwospf_get_link_by_name(sr, interface);
      link->nbor_rid = iface->nlist->rid; /* update neighbor ID of the link */

      /* adding a new neighbor indicates a topological change*/
      sr->ospf_subsys->topo_changed = 1;
      
      Debug("New neighbor added!\n");
      pwospf_compute_shortest_path(sr);
      pwospf_print_ftable(sr);
      pwospf_print_if(iface);
      pwospf_print_links(sr);

      time_t current_time = time(NULL);
      printf("%s", ctime(&current_time));
      Debug("\tFlooding LSU because a new neighbor was added.\n");
      pwospf_flood_lsu(sr);
      sr->ospf_subsys->last_lsu_sent = time(NULL); /* update timer */
    } else if (iface->nlist->islost) { /* neighbor has been recovered */
      Debug("New neighbor has been recovered!\n");
      iface->nlist->last_hello_received = time(NULL);
      iface->nlist->islost = 0;
      //      pwospf_recover_link(sr, ...);
      /*--- Recovery the failed link and add the recovered link back to rt!---*/
      struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
      while (rt_walker->next) {
	rt_walker = rt_walker->next;
      }
      struct pwospf_link *link_walker = sr->ospf_subsys->links;
      while (link_walker) {
	if (link_walker->nbor_rid == iface->nlist->rid) {
	  link_walker->isdown = 0;
	  rt_walker->next = (struct pwospf_rt *)malloc(sizeof(struct pwospf_rt));
	  rt_walker->next->dest = link_walker->subnet;
	  rt_walker->next->gw = 0;
	  rt_walker->next->mask = link_walker->mask;
	  memcpy(rt_walker->next->interface, link_walker->interface, sr_IFACE_NAMELEN);
	  rt_walker->next->next = NULL;
	}
	link_walker = link_walker->next;
      }

      Debug("Link recovered!\n");
      pwospf_compute_shortest_path(sr);
      pwospf_print_ftable(sr);

      pwospf_print_if(iface);
      pwospf_print_links(sr);

      Debug("\tFlooding LSU because a new neighbor has been recovered.\n");
      pwospf_flood_lsu(sr);
      sr->ospf_subsys->last_lsu_sent = time(NULL); /* update timer */

    } else {
      struct neighbor *nbor = iface->nlist;
      int match_found = 0;
      while (nbor) {
	if (nbor->rid == pw_hdr->rid && nbor->ip == ip_hdr->ip_src.s_addr) {
	  match_found = 1; /* HELLO packet matches a current neighbor */
	  nbor->last_hello_received = time(NULL); /* update timer */
	  // Debug("Last hello received timer updated\n");
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

int topo_get_entry_index(struct sr_instance *sr,
		    uint32_t sending_host, uint32_t src_rid)
{
  int i;
  for (i = 0; i < 4; ++i) {
    if (sending_host == sr->ospf_subsys->topo_entries[i].sending_host &&
	src_rid == sr->ospf_subsys->topo_entries[i].src_rid) {
      return i;
    }
  }

  /* No match found */
  return -1;
}

int topo_get_free_entry_index(struct sr_instance *sr)
{
  int i;
  for (i = 0; i < 4; ++i) {
    if (sr->ospf_subsys->topo_entries[i].sending_host == 0 &&
	sr->ospf_subsys->topo_entries[i].src_rid == 0) {
      return i;
    }
  }

  /* Should not reach here! */
  return -1;
}

void pwospf_add_rt(struct sr_instance *sr, int index, uint32_t rid_originator,
		   struct pwospf_if *iface)
{
  uint32_t sending_host = sr->ospf_subsys->topo_entries[index].sending_host;

  int num_adv = sr->ospf_subsys->topo_entries[index].num_adv;
  for (int i = 0; i < num_adv; ++i) {
    struct ospfv2_lsa lsa = sr->ospf_subsys->topo_entries[index].lsa_array[i];
    /* ignore invalid route */
    if (lsa.subnet == 0xffffffff) {
      continue;
    }
    /* Discard route that is sent directly from neighbor routers */
    if (lsa.rid == sr->ospf_subsys->rid && iface->nlist &&
	iface->nlist->rid == rid_originator) {
      continue;
    }

    if (lsa.subnet != 0 &&
	lsa.subnet == (sending_host & lsa.mask)) {
      continue;
    }

    struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
    int route_exist = 0;
    while (rt_walker->next) {
      if (rt_walker->dest == lsa.subnet &&
	  rt_walker->gw == sr->ospf_subsys->topo_entries[index].sending_host &&
	  rt_walker->mask == lsa.mask) {
	route_exist = 1;
	break;
      }
      rt_walker = rt_walker->next;
    }

    if (route_exist) continue; /* do not add repeated ruote */

    rt_walker->next = (struct pwospf_rt *) malloc(sizeof(struct pwospf_rt));
    rt_walker->next->dest = lsa.subnet;
    rt_walker->next->gw = sr->ospf_subsys->topo_entries[index].sending_host;
    rt_walker->next->mask = lsa.mask;
    rt_walker->next->next = NULL;
    memcpy(rt_walker->next->interface,
	   sr->ospf_subsys->topo_entries[index].interface, sr_IFACE_NAMELEN);
  }
}

void pwospf_update_rt(struct sr_instance *sr, int index)
{
  uint32_t sending_host = sr->ospf_subsys->topo_entries[index].sending_host;

  int num_adv = sr->ospf_subsys->topo_entries[index].num_adv;
  for (int i = 0; i < num_adv; ++i) {
    struct ospfv2_lsa lsa = sr->ospf_subsys->topo_entries[index].lsa_array[i];
    /* ignore invalid route */
    if (lsa.subnet == 0xffffffff) {
      continue;
    }
    /* Discard route directly connect to the router */
    if (lsa.rid == sr->ospf_subsys->rid) {
      continue;
    }

    /* Delete route that matches routes in topo_entries[index]
       from the current rt then add routes  */
    struct pwospf_rt *rt_walker = sr->ospf_subsys->rt;
    while (rt_walker->next) {      
      rt_walker = rt_walker->next;
    } 
  }
}

void topo_delete_entry(struct sr_instance *sr, uint32_t sending_host,
		       uint32_t src_rid)
{
  int i;
  for (i = 0; i < 4; ++i) {
    if (sending_host == sr->ospf_subsys->topo_entries[i].sending_host) {
      sr->ospf_subsys->topo_entries[i].sending_host = 0;
      sr->ospf_subsys->topo_entries[i].src_rid = 0;
      memset(&(sr->ospf_subsys->topo_entries[i].lsa_array),
	     0xff, sizeof(struct ospfv2_lsa) * 4);
    }
  }
}

void topo_add_entry(struct sr_instance *sr, uint32_t sending_host,
		    uint32_t src_rid, struct ospfv2_lsu_hdr *pw_lsu_hdr,
		    int index, char *interface)
{
    /* Put received LSU into entry[index] */
    sr->ospf_subsys->topo_entries[index].sending_host = sending_host;
    sr->ospf_subsys->topo_entries[index].src_rid = src_rid;
    sr->ospf_subsys->topo_entries[index].last_seqnum_received = ntohs(pw_lsu_hdr->seq);
    sr->ospf_subsys->topo_entries[index].last_received_time = time(NULL);
    sr->ospf_subsys->topo_entries[index].num_adv = ntohl(pw_lsu_hdr->num_adv);
    memcpy(sr->ospf_subsys->topo_entries[index].interface,
	   interface, sr_IFACE_NAMELEN);

    struct ospfv2_lsa *lsa;
    for (int i = 0; i < ntohl(pw_lsu_hdr->num_adv); ++i) {
      lsa = (struct ospfv2_lsa *)((uint8_t *)pw_lsu_hdr +
  				  sizeof(struct ospfv2_lsu_hdr) +
  				  sizeof(struct ospfv2_lsa) * i);
      sr->ospf_subsys->topo_entries[index].lsa_array[i] = *lsa;
    }
}

void pwospf_forward_lsu(struct sr_instance *sr, uint8_t * packet,
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


  struct pwospf_if *if_walker = sr->ospf_subsys->iflist;
  while (if_walker) {
    if (if_walker->nlist) {
      //      if (if_walker->nlist->rid != pw_hdr->rid &&
      //	  strcmp(if_walker->name, interface) != 0) {
      if (strcmp(if_walker->name, interface) != 0) {
	memcpy(e_hdr->ether_shost, if_walker->mac, 6);
	memcpy(e_hdr->ether_dhost, if_walker->nlist->mac, 6);

	ip_hdr->ip_src.s_addr = if_walker->ip;
	ip_hdr->ip_dst.s_addr = if_walker->nlist->ip;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

	int success = sr_send_packet(sr, packet, len, if_walker->name);
	if (success != 0) {
	  fprintf(stderr, "%s: Sending packet failed!\n", __func__);
	}
	//	Debug("Forword LSU packet\n");
      } else {
	//	Debug("No need to forward LSU to the incoming neighbor\n");
      }
    }
    if_walker = if_walker->next;
  }
}

int topo_check_entry_content(struct sr_instance *sr,
			     struct ospfv2_lsu_hdr *pw_lsu_hdr,
			     int index, uint32_t src_rid, struct pwospf_if *iface)
{
  int changed = 0;
  uint32_t num_adv = sr->ospf_subsys->topo_entries[index].num_adv;
  if (ntohl(pw_lsu_hdr->num_adv) == num_adv) {
    struct ospfv2_lsa *lsa;
    for (int i = 0; i < num_adv; ++i) {
      lsa = (struct ospfv2_lsa *)((uint8_t *)pw_lsu_hdr +
				  sizeof(struct ospfv2_lsu_hdr) +
				  sizeof(struct ospfv2_lsa) * i);
      struct ospfv2_lsa *lsa_stored;
      /* subnet and mask should remain the same, rid could be different */
      for (int j = 0; j < num_adv; ++j) {
	lsa_stored = &(sr->ospf_subsys->topo_entries[index].lsa_array[j]);
	if (lsa_stored->subnet == lsa->subnet && lsa_stored->mask == lsa->mask) {
	  if (lsa_stored->rid != lsa->rid) {
	    lsa_stored->rid = lsa->rid;
	  }
	  break;
	}
      }
    }
  } else {
    if (ntohl(pw_lsu_hdr->num_adv) < num_adv) {
      changed = -1;
      //      Debug("Number of LSA dropped!\n");
      for (int i = 0; i < num_adv; ++i) {
	int failed = 1;
	uint32_t dest = sr->ospf_subsys->topo_entries[index].lsa_array[i].subnet;
	uint32_t gw = sr->ospf_subsys->topo_entries[index].sending_host;
	struct ospfv2_lsa *lsa;
	for (int j = 0; j < ntohl(pw_lsu_hdr->num_adv); ++j) {
	  lsa = (struct ospfv2_lsa *)((uint8_t *)pw_lsu_hdr +
				      sizeof(struct ospfv2_lsu_hdr) +
				      sizeof(struct ospfv2_lsa) * j);
	  // printf("LSA subnet: "); print_ip(lsa->subnet); putchar('\n');
	  if (dest == lsa->subnet) {
	    failed = 0;
	  }
	}
	if (failed) {
	  if (iface->nlist && iface->nlist->rid == src_rid) {
	    // printf("Delete route "); print_ip(dest);
	    // printf("  "); print_ip(gw); printf("\n");
	    pwospf_rt_delete_route2(sr, dest, gw);
	  }
	}
      }
    } else {
      changed = 1;
      //      Debug("Number of LSA increased!\n");
    }
    sr->ospf_subsys->topo_entries[index].num_adv = ntohl(pw_lsu_hdr->num_adv);
    /* Reset LSA array */
    memset(&(sr->ospf_subsys->topo_entries[index].lsa_array),
	   0xff, sizeof(struct ospfv2_lsa) * 4);
    struct ospfv2_lsa *lsa;
    for (int i = 0; i < ntohl(pw_lsu_hdr->num_adv); ++i) {
      lsa = (struct ospfv2_lsa *)((uint8_t *)pw_lsu_hdr +
  				  sizeof(struct ospfv2_lsu_hdr) +
  				  sizeof(struct ospfv2_lsa) * i);
      sr->ospf_subsys->topo_entries[index].lsa_array[i] = *lsa;
    }
  }

  return changed;
}

/*---------------------------------------------------------------------
 *
 * Handle received HELLO packet from neighbors.
 * Try to match the source of the HELLO packet to one of the receiving
 * interface's neighbor.
 *
 *---------------------------------------------------------------------*/

void pwospf_handle_lsu(struct sr_instance *sr, uint8_t * packet,
		       unsigned int len, char* interface)
{
  struct sr_ethernet_hdr *e_hdr;
  struct ip *ip_hdr;
  struct ospfv2_hdr *pw_hdr;
  struct ospfv2_lsu_hdr *pw_lsu_hdr;
  int forward_flag = 0;

  pwospf_lock(sr->ospf_subsys);
  
  e_hdr = (struct sr_ethernet_hdr *) packet;
  ip_hdr = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
  pw_hdr = (struct ospfv2_hdr*) (packet +
				 sizeof(struct sr_ethernet_hdr) +
				 sizeof(struct ip));
  pw_lsu_hdr = (struct ospfv2_lsu_hdr *) (packet +
					  sizeof(struct sr_ethernet_hdr) +
					  sizeof(struct ip) +
					  sizeof(struct ospfv2_hdr));

  struct pwospf_if *iface = get_pwospf_if_by_name(sr, interface);

  uint32_t sending_host = ip_hdr->ip_src.s_addr;
  uint32_t src_rid = pw_hdr->rid;

  /* If LSU packet originally from this router, drop the packet */
  if (src_rid == sr->ospf_subsys->rid) {
    //    Debug("Packet is originally from this router, dropped\n");
  } else {
    int entry_index = topo_get_entry_index(sr, sending_host, src_rid);
    if (entry_index < 0) { /* No entry found */
      /* printf("Received topo entry for router: "); */
      /* print_ip(src_rid); */
      /* printf("  and sending host: "); */
      /* print_ip(sending_host); */
      /* printf("\n"); */
      /* printf("Entry index: %d\n", entry_index); */

      int free_entry_index = topo_get_free_entry_index(sr);
      topo_add_entry(sr, sending_host, src_rid, pw_lsu_hdr,
		     free_entry_index, interface);
      pwospf_add_rt(sr, free_entry_index, pw_hdr->rid, iface);
      //pwospf_print_routing_table(sr);
      Debug("Adding topo entry!\n");
      pwospf_compute_shortest_path(sr);
      pwospf_print_topo_db(sr);
      pwospf_print_ftable(sr);
      /* Forward the newly added LSU */
      pwospf_forward_lsu(sr, packet, len, interface);
    } else { /* entry found */
      uint16_t last_seqnum =
	sr->ospf_subsys->topo_entries[entry_index].last_seqnum_received;
      if (ntohs(pw_lsu_hdr->seq) == last_seqnum ) {
	//fprintf(stderr, "Repeated sequence number! Packet dropped\n");
      } else {
	/* update seq# and timer */
	sr->ospf_subsys->topo_entries[entry_index].last_seqnum_received =
	  ntohs(pw_lsu_hdr->seq);
	sr->ospf_subsys->topo_entries[entry_index].last_received_time = time(NULL);
	/* Debug("Update timer for entry "); */
	/* print_ip(sending_host); */
	/* Debug(" , "); */
	/* print_ip(src_rid); */
	/* Debug(" , seq# = %d\n", ntohs(pw_lsu_hdr->seq)); */
	/* Debug("\n"); */

	/* Check if packet conent is equivalent to the content of
	   the packet last received from the sending host */
	//Debug("Checking LSU (seq#=%d)...\n", ntohs(pw_lsu_hdr->seq));
	int changed = topo_check_entry_content(sr, pw_lsu_hdr, entry_index,
					       src_rid, iface);
	if (changed) {
	  Debug("Topo entry changed!\n");
	  pwospf_compute_shortest_path(sr);
	  pwospf_print_ftable(sr);

	  /* TODO: Update routing table and Recompute the shortest path */
	  //	  pwospf_update_rt(sr, entry_index);
	  if (changed < 0) { /* Link failure */
	  } else { /* Link recovery */
	  }
	  Debug("Topo entry changed!\n");
	  pwospf_print_topo_db(sr);
	  //	  pwospf_print_routing_table(sr);
	}
	/* Forward the received LSU with new seq# */
	pwospf_forward_lsu(sr, packet, len, interface);	
      }
    }
  }
  //  pwospf_print_topo_db(sr);
  //  pwospf_print_routing_table(sr);

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
    pwospf_handle_lsu(sr, packet, len, interface);
  }
}


/*---------------------------------------------------------------------
 * Flood link state updates to neighbors whenever a link change is
 * detected (adding or deleting a link).
 *
 *---------------------------------------------------------------------*/

void pwospf_flood_lsu(struct sr_instance *sr)
{
  int num_links = pwospf_get_num_uplinks(sr);
  //  Debug("Number of local links: %d\n", num_links);
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
  pw_hdr->csum = 0;
  pw_hdr->csum = checksum(pw_hdr, sizeof(struct ospfv2_hdr)-8);

  /* Fill LSU header */
  pw_lsu_hdr->seq = htons(sr->ospf_subsys->last_lsu_seq_sent++);
  pw_lsu_hdr->unused = 0;
  pw_lsu_hdr->ttl = OSPF_MAX_LSU_TTL;
  pw_lsu_hdr->num_adv = htonl(num_links);

  struct pwospf_if *if_walker = sr->ospf_subsys->iflist;
  while (if_walker) {
    /*--- Since each router only has one neighbor per interface,
      so I simplified a bit not to traverse the neighbor list. ---*/
    if (if_walker->nlist) {
      /*--- send lsu out of interfaces with router neighbors ---*/
      
      /* Complete ethernet header */
      memcpy(e_hdr->ether_dhost, if_walker->nlist->mac, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_shost, if_walker->mac, ETHER_ADDR_LEN);

      /* Complete IP header */
      ip_hdr->ip_src.s_addr = if_walker->ip;
      ip_hdr->ip_dst.s_addr = if_walker->nlist->ip;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = checksum(ip_hdr, sizeof(struct ip));

      /* Fill LSA */
      struct pwospf_link *link_walker = sr->ospf_subsys->links;
      struct ospfv2_lsa *lsa;
      int lsa_counter = 0;
      while (link_walker) {
	if (link_walker->isdown) { /* do not advertise failed link */
	  link_walker = link_walker->next;
	  continue;
	}
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
}

void pwospf_check_nbor_timeout(struct sr_instance *sr)
{
  pwospf_lock(sr->ospf_subsys);

  int nbor_timedout = 0;
  struct pwospf_if *if_walker = sr->ospf_subsys->iflist;
  time_t current_time = time(NULL);
  while (if_walker) {
    if (if_walker->nlist && !if_walker->nlist->islost) {
      double time_elapsed = difftime(current_time,
				     if_walker->nlist->last_hello_received);
      if (time_elapsed > (double)OSPF_NEIGHBOR_TIMEOUT) {
	/* printf("%s", ctime(&current_time)); */
	/* Debug("\tNeighbor "); */
	/* print_ip(if_walker->nlist->rid); */
	/* Debug(" has timed out!\n");      */
	nbor_timedout = 1;

	/*--- Mark the corresponding link as failed ---*/
	struct pwospf_link *link_walker = sr->ospf_subsys->links;
	while (link_walker) {
	  if (link_walker->nbor_rid == if_walker->nlist->rid) {
	    link_walker->isdown = 1;
	    pwospf_rt_delete_route(sr, link_walker->subnet & link_walker->mask,
				   if_walker);
	    topo_delete_entry(sr, if_walker->nlist->ip, if_walker->nlist->rid);
	    if_walker->nlist->islost = 1; /* mark neighbor as lost */
	    //pwospf_print_routing_table(sr);
	    Debug("Neighbor timed out!\n");
	    pwospf_compute_shortest_path(sr);
	    pwospf_print_ftable(sr);
	    pwospf_print_topo_db(sr);
	  }
	  link_walker = link_walker->next;
	}
      }
    }
    if_walker = if_walker->next;
  }

  if (nbor_timedout) {
    pwospf_print_links(sr);
    //Debug("\tFlooding LSU because a link failed...\n");
    pwospf_flood_lsu(sr);
    sr->ospf_subsys->last_lsu_sent = time(NULL); /* update timer */
  }

  pwospf_unlock(sr->ospf_subsys);
}

void pwospf_check_topo_entry_timeout(struct sr_instance *sr)
{
  pwospf_lock(sr->ospf_subsys);
  
  time_t current_time = time(NULL);
  for (int i = 0; i < 4; ++i) {
    if (sr->ospf_subsys->topo_entries[i].src_rid != 0 &&
	sr->ospf_subsys->topo_entries[i].sending_host != 0) {
      double time_elapsed = difftime(current_time,
				     sr->ospf_subsys->topo_entries[i].last_received_time);
      //      printf("Time elapsed: %lf\n", time_elapsed);
      if (time_elapsed > (double)OSPF_TOPO_ENTRY_TIMEOUT) {
	for (int j = 0; j < 4; ++j) {
	  uint32_t dest = sr->ospf_subsys->topo_entries[i].lsa_array[j].subnet;
	  uint32_t gw = sr->ospf_subsys->topo_entries[i].sending_host;
	  pwospf_rt_delete_route2(sr, dest, gw);
	}

	sr->ospf_subsys->topo_entries[i].src_rid = 0;
	sr->ospf_subsys->topo_entries[i].sending_host = 0;
	memset(&(sr->ospf_subsys->topo_entries[i].lsa_array),
	       0xff, sizeof(struct ospfv2_lsa) * 4);

	/* TODO: recompute the shortest path */
	
	printf("Topo entry timed out!\n");
	pwospf_print_topo_db(sr);
	Debug("Topo entry timed out!\n");
	pwospf_compute_shortest_path(sr);
	pwospf_print_ftable(sr);
	//	pwospf_print_routing_table(sr);
      }
    }
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
  time_t current_time;

  while(1)
    {
      current_time = time(NULL);
      /* -- PWOSPF subsystem functionality should start  here! -- */
      pwospf_lock(sr->ospf_subsys);
      /* printf("%s", ctime(&current_time)); */
      /* printf("\tBroadcasting HELLO...\n"); */
      pwospf_broadcast_hello(sr);
      pwospf_unlock(sr->ospf_subsys);      

      sleep(OSPF_DEFAULT_HELLOINT);

      /* Check neighbor timeout */
      pwospf_check_nbor_timeout(sr);

      pwospf_check_topo_entry_timeout(sr);

      /*--- Periodically LSU flood ---*/
      current_time = time(NULL);
      double time_elapsed = difftime(current_time, sr->ospf_subsys->last_lsu_sent);
      if (time_elapsed >= (double) OSPF_DEFAULT_LSUINT) {
	//	printf("%s", ctime(&current_time));
	//	printf("\tPeriodically LSU flooding...\n");
	pwospf_flood_lsu(sr);
	sr->ospf_subsys->last_lsu_sent = time(NULL);
      }

      /*--- TODO: Check validity of topology DB entries ---*/
    }

  return NULL;
} /* -- run_ospf_thread -- */

