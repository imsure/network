/**********************************************************************
 * file:  sr_arp.c 
 *
 * Description:
 * 
 * This file contains all the functions that handle ARP requests,
 * replies and ARP cache.
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
#include "sr_icmp.h"


/*------------------------------------------------------------------
 * Scope: Global
 *
 * Entry point of handling raw ethernet packet with a ARP payload.
 *-----------------------------------------------------------------*/

void sr_arp_handler(struct sr_instance* sr, uint8_t * packet/* lent */,
		    unsigned int len, char* interface/* lent */)
{
  struct sr_if *iface = sr_get_interface(sr, interface);
  struct sr_arphdr *a_hdr; // ARP header

  a_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));
  if (iface->ip == a_hdr->ar_tip) { // am I the target of this ARP packet?
    
    if (ntohs(a_hdr->ar_op) == ARP_REQUEST) {
      /* Someone in the same local network requested to know my MAC. */
      sr_arp_send_reply(sr, packet, len, interface);
      
    } else if (ntohs(a_hdr->ar_op) == ARP_REPLY) {
      /* Someone in the same local network replied my ARP request. */
      sr_arp_handle_reply(sr, packet, len, interface);
      
    } else {
      fprintf(stderr, "Unknown ARP opcode %d!\n", ntohs(a_hdr->ar_op));
    }
  } else
    fprintf(stderr, "Get an ARP request not targeted to me!\n");
}

void sr_arp_send_request(struct sr_instance* sr, struct sr_arp_request *req)
{
  /* raw ethernet frame: 14 bytes ethernet header, 28 bytes ARP payload */
  uint8_t *arp_req_packet = (uint8_t *) malloc(sizeof(struct sr_ethernet_hdr)
					       + sizeof(struct sr_arphdr));
  struct sr_ethernet_hdr *e_hdr = (struct sr_ethernet_hdr *) arp_req_packet;
  struct sr_arphdr *a_hdr = (struct sr_arphdr *) (arp_req_packet+
						  sizeof(struct sr_ethernet_hdr));
  struct sr_if *interface = sr_get_interface(sr, req->iface_out);

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
  a_hdr->ar_tip = req->ip; // target IP

  int success = sr_send_packet(sr, arp_req_packet, 42, req->iface_out);
  if (success != 0) {
    fprintf(stderr, "%s: Sending packet failed!\n", __func__);
  }  
}


/*---------------------------------------------------------------------
 * Method: sr_arp_handle_reply
 * Scope:  Global
 *
 * This method is called each time the router receives a ARP reply
 * packet on the 'interface'.
 *
 * On receiving an ARP reply, router needs to update ARP cache with
 * newly gotten IP --> MAC mapping and look up the cache to see if 
 * there is any ARP request pending on this IP, now since we know its
 * MAC, we are ready to forward IP packets waiting on this request.
 *---------------------------------------------------------------------*/

void sr_arp_handle_reply(struct sr_instance* sr, uint8_t * packet /*lent*/,
			 unsigned int len, char* interface /*lent*/)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_ethernet_hdr *e_hdr;
  struct sr_arphdr *a_hdr;
  uint32_t sender_ip;
  unsigned char *sender_mac = (unsigned char *)malloc(ETHER_ADDR_LEN);
  
  e_hdr = (struct sr_ethernet_hdr*) packet;
  a_hdr = (struct sr_arphdr *)(packet + sizeof(struct sr_ethernet_hdr));

  memcpy(sender_mac, e_hdr->ether_shost, ETHER_ADDR_LEN);
  sender_ip = a_hdr->ar_sip;

  /* Insert IP --> MAC to ARP cache and get the request created
     for the inserted IP. */
  struct sr_arp_request *req = sr_arpcache_insert(&(sr->arpcache),
						  sender_ip, sender_mac);
  if (req) {
    struct sr_ip_packet *pkt;

    /* Since sender_mac is the dest_mac for the packets wait on the 'req',
       now we iterate through all these packets to send them out. */
    for (pkt = req->packets; pkt != NULL; pkt = pkt->next) {
      sr_ip_send_packet(sr, pkt, sender_mac);
    }    

    /* Free this request and IP packets associated with it. */
    sr_arpreq_destroy(&(sr->arpcache), req);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_arp_send_reply
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

void sr_arp_send_reply(struct sr_instance* sr, 
		       uint8_t * packet/* lent */,
		       unsigned int len,
		       char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if* iface = sr_get_interface(sr, interface);
  struct sr_ethernet_hdr* e_hdr = 0;
  struct sr_arphdr*       a_hdr = 0;

  e_hdr = (struct sr_ethernet_hdr *) packet;
  a_hdr = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));

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


/************************************
 *
 * Start of ARP Cache Routines
 *
 ***********************************/

/*---------------------------------------------------------------------
 * Method: sr_arpcache_search
 * Scope:  Global
 *
 * Search for IP --> MAC mapping in the ARP cache. 'ip' is in network
 * byte order. Note that caller is responsible for freeing the returned
 * arp cache entry if not NULL.
 *---------------------------------------------------------------------*/

struct sr_arpcache_entry *sr_arpcache_search(struct sr_arpcache *arpcache, uint32_t ip)
{
  assert(arpcache);
  
  struct sr_arpcache_entry *entry = NULL, *entry_copy = NULL;

  pthread_mutex_lock( &(arpcache->lock) );

  /* Searching */
  for (int i = 0; i < SR_ARPCACHE_SIZE; ++i) {
    if ( (arpcache->entries[i].is_valid) &&
	 (arpcache->entries[i].ip == ip) ) {
      entry = &(arpcache->entries[i]);
    }
  }

  /* Must return a copy of the matched entry because another thread
     (for handling ARP cache time out) could modify the cache after
     we return. */
  if (entry) {
    entry_copy = (struct sr_arpcache_entry *) malloc(sizeof(struct sr_arpcache_entry));
    memcpy(entry_copy, entry, sizeof(struct sr_arpcache_entry));
  }

  pthread_mutex_unlock( &(arpcache->lock) );

  return entry_copy;
}


/*---------------------------------------------------------------------
 * Method: sr_arpreq_enqueue
 * Scope:  Global
 *
 * Add an ARP request into arp cache's request queue if it is not on the
 * queue yet.
 * If the request is already on the queue, adds the 'packet' to the list
 * of packets waiting on the request.
 *
 * Return the corresponding ARP request. It should not be freed by caller,
 * only sr_arpreq_destroy can be used to free the request.
 *---------------------------------------------------------------------*/

struct sr_arp_request *sr_arpreq_enqueue(struct sr_arpcache *arpcache,
					 uint32_t ip, uint8_t *packet,
					 unsigned int len, char *iface_out)
{
  assert(arpcache);
  assert(packet);
  assert(iface_out);

  pthread_mutex_lock( &(arpcache->lock) );

  struct sr_ip_packet *new_packet;
  struct sr_arp_request *req;
  
  for (req = arpcache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) { // a request has been created for the given ip.
      break;
    }
  }

  /* If not found, create a new request. */
  if (!req) {
    req = (struct sr_arp_request *) calloc(1, sizeof(struct sr_arp_request));
    req->ip = ip;
    strncpy(req->iface_out, iface_out, sr_IFACE_NAMELEN);
    req->sent_times = 0;
    req->time_sent = 0;
    /* place 'req' at the beginning of the queue */
    req->next = arpcache->requests;
    arpcache->requests = req;
  }

  /* Add the 'packet' to the list of the packets waiting
     on this request 'req'. */
  new_packet = (struct sr_ip_packet *) malloc(sizeof(struct sr_ip_packet));
  new_packet->buf = (uint8_t *) malloc(len);
  memcpy(new_packet->buf, packet, len);
  new_packet->len = len;
  new_packet->iface_out = (char *) malloc(sr_IFACE_NAMELEN);
  strncpy(new_packet->iface_out, iface_out, sr_IFACE_NAMELEN);
  new_packet->next = req->packets;
  req->packets = new_packet;

  pthread_mutex_unlock( &(arpcache->lock) );

  return req;
}


/*---------------------------------------------------------------------
 * Method: sr_arpcache_insert
 * Scope:  Global
 *
 * Insert a mapping of IP --> MAC into arpcache and mark it as valid.
 *
 * IF 'ip' was found in the arp request queue, return a pointer to
 * the sr_arp_request corresponds with 'ip'.
 * Otherwise, return NULL.
 *
 * Caller needs to check the return value!
 *---------------------------------------------------------------------*/

struct sr_arp_request *sr_arpcache_insert(struct sr_arpcache *arpcache,
					  uint32_t ip, unsigned char *mac)
{
  assert(arpcache);
  assert(mac);

  pthread_mutex_lock( &(arpcache->lock) );

  int i;
  struct sr_arp_request *req, *prev_req, *next_req;
  prev_req = next_req = NULL;

  for (req = arpcache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      if (prev_req) {
	next_req = req->next;
	prev_req->next = next_req;
      } else {
	next_req = req->next;
	arpcache->requests = next_req;
      }
      break;
    }
    prev_req = req;
  }

  for (i = 0; i < SR_ARPCACHE_SIZE; ++i) {
    if (!(arpcache->entries[i].is_valid)) {
      break;
    }
  }

  if (i < SR_ARPCACHE_SIZE) {
    memcpy(arpcache->entries[i].mac, mac, ETHER_ADDR_LEN);
    arpcache->entries[i].ip = ip;
    arpcache->entries[i].time_added = time(NULL);
    arpcache->entries[i].is_valid = 1;

    //sr_arpcache_print_entry(&(arpcache->entries[i]));
    //Debug("Inserted at %s\n", ctime(&(arpcache->entries[i].time_added)));
  } else { // cache is full
    /* TODO: Kick out an ARP cache entry randomly */
  }
 
  pthread_mutex_unlock( &(arpcache->lock) );
  return req;
}


/*---------------------------------------------------------------------
 * Method: sr_arpreq_destroy
 * Scope:  Global
 *
 * Free all memory associated with the ARP request 'arpreq'. Remove it
 * from queue if 'arpreq' is on the ARP cache request queue.
 *---------------------------------------------------------------------*/

void sr_arpreq_destroy(struct sr_arpcache *arpcache,
			struct sr_arp_request *arpreq)
{
  assert(arpcache);
  assert(arpreq);

  pthread_mutex_lock( &(arpcache->lock) );

  struct sr_arp_request *req, *prev_req, *next_req;
  prev_req = next_req = NULL;

  for (req = arpcache->requests; req != NULL; req = req->next) {
    if (req == arpreq) {
      if (prev_req) {
	next_req = req->next;
	prev_req->next = next_req;
      } else {
	next_req = req->next;
	arpcache->requests = next_req;
      }
      break;
    }
    prev_req = req;
  }

  struct sr_ip_packet *pkt, *next_pkt;

  for (pkt = arpreq->packets; pkt != NULL; pkt = next_pkt) {
    next_pkt = pkt->next;
    if (pkt->buf) free(pkt->buf);
    if (pkt->iface_out) free(pkt->iface_out);
    free(pkt);
  }

  free(arpreq);

  pthread_mutex_unlock( &(arpcache->lock) );
}

void sr_arpcache_dump(struct sr_arpcache *arpcache)
{
  printf("\nMAC            IP         TIME_ADDED               VALID\n");
  printf("----------------------------------------------------------\n");

  for (int i = 0; i < SR_ARPCACHE_SIZE; ++i) {
    struct sr_arpcache_entry *entry = &(arpcache->entries[i]);
    unsigned char *mac = entry->mac;
    printf("%.1x%.1x%.1x%.1x%.1x%.1x  %.8x  %.24s  %d\n", mac[0], mac[1],
	   mac[2], mac[3], mac[4], mac[5], ntohl(entry->ip),
	   ctime(&(entry->time_added)), entry->is_valid);
  }
  putchar('\n');
}

int sr_arpcache_init(struct sr_arpcache *arpcache)
{
  assert(arpcache);

  /* Seed RNG to kick out a random entry when cache is full. */
  srand(time(NULL));

  /* Invalidate all entries. */
  for (int i = 0; i < SR_ARPCACHE_SIZE; ++i) {
    memset(&(arpcache->entries[i]), 0, sizeof(struct sr_arpcache_entry));
  }

  arpcache->requests = NULL;

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(arpcache->attr));
  pthread_mutexattr_settype(&(arpcache->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(arpcache->lock), &(arpcache->attr));

  return success;
}

void sr_arpcache_destroy(struct sr_arpcache *arpcache)
{
  pthread_mutex_destroy(&(arpcache->lock));
  pthread_mutexattr_destroy(&(arpcache->attr));
}


/*---------------------------------------------------------------------
 * Method: sr_arpcache_handle_request
 * Scope:  Global
 *
 *---------------------------------------------------------------------*/

void sr_arpcache_handle_request(struct sr_instance *sr, struct sr_arp_request *req)
{
  time_t current_time = time(NULL);
  double time_since_last_sent = difftime(current_time, req->time_sent);

  if (time_since_last_sent > 1.0) {
    if (req->sent_times >= 5) {
      sr_icmp_host_unreachable(sr, req);

      sr_arpreq_destroy(&(sr->arpcache), req);
      //Debug("ARP request for ... destroyed\n");
    } else {
      sr_arp_send_request(sr, req);
      req->time_sent = time(NULL);
      req->sent_times++;
      //Debug("ARP request sent for %d times\n", req->sent_times);
    }
  }
}

/*---------------------------------------------------------------------
 * Method: sr_arpcache_sweep_reqs
 * Scope:  Global
 *
 * Gets called every second by the ARP cache time out daemon thread to
 * sweep through the ARP request queue to send out pending ARP requests.
 *---------------------------------------------------------------------*/

void sr_arpcache_sweep_reqs(struct sr_instance *sr)
{
  struct sr_arp_request *req, *req_next;
  
  for (req = sr->arpcache.requests; req != NULL; ) {
    req_next = req->next;
    sr_arpcache_handle_request(sr, req);
    req = req_next;
  }
}

/*---------------------------------------------------------------------
 * Method: sr_arpcache_timeout_handler()
 * Scope:  Global
 *
 * Thread handler for ARP cache time out. Pointer to the SR instance
 * is passed as the argument.
 *
 * It sweeps through the cache entries and invalidates those that were
 * added more than SR_ARPCACHE_TIME_OUT seconds ago.
 *---------------------------------------------------------------------*/

void *sr_arpcache_timeout_handler(void *sr_ptr)
{
  struct sr_instance *sr = sr_ptr;
  struct sr_arpcache *arpcache = &(sr->arpcache);

  while (1) {
    sleep(1);

    pthread_mutex_lock(&(arpcache->lock));

    time_t current_time = time(NULL);

    for (int i = 0; i < SR_ARPCACHE_SIZE; ++i) {
      double time_since_added = difftime(current_time, arpcache->entries[i].time_added);
      if ((arpcache->entries[i].is_valid) &&
	  (time_since_added > SR_ARPCACHE_TIME_OUT)) {
	arpcache->entries[i].is_valid = 0; // mark as invalid
	//Debug("Time out the entry ");
	//sr_arpcache_print_entry(&(arpcache->entries[i]));
      }
    }

    /* Called every second */
    sr_arpcache_sweep_reqs(sr);

    pthread_mutex_unlock( &(arpcache->lock) );
  }

  return NULL;
}

void sr_arpcache_print_entry(struct sr_arpcache_entry *entry)
{
  int i;
  uint8_t *ip = (uint8_t *)&(entry->ip);

  for (i = 0; i < 3; ++i) {
    printf("%d.", ip[i]);
  }
  printf("%d", ip[3]);
  printf(" ====> ");

  for (i = 0; i < 5; ++i) {
    printf("%02x:", entry->mac[i]);
  }
  printf("%02x\n", entry->mac[5]);
}

/************************************
 *
 * End of ARP Cache Routines
 *
 ***********************************/
