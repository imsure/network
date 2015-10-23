/*-----------------------------------------------------------------------------
 * file:  sr_arp.h
 *
 * Description:
 *
 * Data structures and methods for handeling ARP requests/replies
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_ARP_H
#define sr_ARP_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#include <time.h>
#include <pthread.h>
#include "sr_if.h"
#include "sr_protocol.h"

#define SR_ARPCACHE_SIZE 128 // # of cache entries
#define SR_ARPCACHE_TIME_OUT 15.0 // 15 seconds

struct sr_instance;

/* ARP cache entry. Maps IP --> MAC */
struct sr_arpcache_entry {
  uint32_t ip; // IP address in network byte order (big endian)
  unsigned char mac[ETHER_ADDR_LEN];

  time_t time_added; // time when the entry was added
  int is_valid; // not zero: vald; zero: invalid
};

/* IP packets arrived at SR and waiting to be sent out. */
struct sr_ip_packet {
  uint8_t *buf; // raw Ethernet frame, presumably with dest MAC empty
  unsigned int len; // raw Ethernet frame length
  char *iface_out; // outgoing interface
  struct sr_ip_packet *next; // next IP packt waiting on the same ARP request
};

/* ARP request for a target MAC */
struct sr_arp_request {
  uint32_t ip;
  char iface_out[sr_IFACE_NAMELEN]; // interface through which to send ARP request
  time_t time_sent; // last time this ARP request was sent. default is 0.
  int sent_times; // # of times this request was sent. Max=5

  struct sr_ip_packet *packets; // list of packets waiting on the ARP request
  struct sr_arp_request *next;
};

/* ARP  cache instance */
struct sr_arpcache {
  struct sr_arpcache_entry entries[SR_ARPCACHE_SIZE];
  struct sr_arp_request *requests; // list of ARP requests
  pthread_mutex_t lock; // for protecting access to arpcache
  pthread_mutexattr_t attr;
};

void sr_arp_send_reply(struct sr_instance* sr, 
		       uint8_t * packet/* lent */,
		       unsigned int len,
		       char* interface/* lent */);

void *sr_arpcache_timeout_handler(void *sr_ptr);
struct sr_arpcache_entry *sr_arpcache_search(struct sr_arpcache *arpcache, uint32_t ip);
struct sr_arpcache_entry *sr_arpcache_search(struct sr_arpcache *arpcache, uint32_t ip);
struct sr_arp_request *sr_arpreq_enqueue(struct sr_arpcache *arpcache,
					 uint32_t ip, uint8_t *packet,
					 unsigned int len, char *iface_out);

#endif /* --  sr_ARP_H -- */
