/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>
#include "pwospf_protocol.h"

/* forward declare */
struct sr_instance;

struct pwospf_rt {
  uint32_t dest;
  uint32_t gw;
  uint32_t mask;
  char   interface[sr_IFACE_NAMELEN];
  struct pwospf_rt* next;
};

/* Entry of topology DB of the router */
struct pwospf_topo_entry {
  uint32_t sending_host; /* who sent this entry */
  uint32_t src_rid; /* who originally flooded this entry */
  uint16_t last_seqnum_received;
  time_t last_received_time;
  char   interface[sr_IFACE_NAMELEN]; /* which interface receives this entry*/
  int num_adv; /* # of lsa this entry contains */
  struct ospfv2_lsa lsa_array[4]; /* array of received lsa */
};

struct pwospf_subsys
{
  /* -- pwospf subsystem state variables here -- */
  struct pwospf_if *iflist;
  uint32_t rid;
  uint32_t aid; /* area ID */
  struct pwospf_link *links; /* a list of links router knows */
  struct pwospf_rt *rt;

  uint16_t last_lsu_seq_sent;
  int topo_changed; /* indicate whether the topology changed or not */
  time_t last_lsu_sent;

  struct pwospf_topo_entry topo_entries[4];

  /* -- thread and single lock for pwospf subsystem -- */
  pthread_t thread;
  pthread_mutex_t lock;
};

struct neighbor {
  uint32_t rid;
  uint32_t ip;
  unsigned char mac[6];
  time_t last_hello_received;
  int islost;
  struct neighbor *next;
};

/* PWOSPF subsystem uses its own interface structure
   which is an extention to the one defined in sr_if.h */
struct pwospf_if {
  char name[sr_IFACE_NAMELEN];
  unsigned char mac[6];
  uint32_t ip;
  uint32_t mask;
  uint16_t helloint;
  struct neighbor *nlist;
  
  struct pwospf_if *next;
};

/* Local link connectivity */
struct pwospf_link {
  char interface[sr_IFACE_NAMELEN];
  uint32_t subnet;
  uint32_t mask;
  uint32_t nbor_rid;
  int isdown;
  struct pwospf_link *next;
};

int pwospf_init(struct sr_instance* sr);
void pwospf_lock(struct pwospf_subsys* subsys);
void pwospf_unlock(struct pwospf_subsys* subsys);
void pwospf_handle_hello(struct sr_instance *sr, uint8_t * packet,
			 unsigned int len, char* interface);
uint32_t pwospf_rt_nexthop(struct sr_instance* sr, uint32_t target_ip, char *iface_out);
uint32_t pwospf_rt_default_nexthop(struct sr_instance* sr, char *iface_out);
void pwospf_handle_packet(struct sr_instance *sr, uint8_t * packet,
			  unsigned int len, char* interface);

#endif /* SR_PWOSPF_H */
