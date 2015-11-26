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

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
  /* -- pwospf subsystem state variables here -- */
  struct pwospf_if *iflist;
  uint32_t rid;
  uint32_t aid; /* area ID */

  /* -- thread and single lock for pwospf subsystem -- */
  pthread_t thread;
  pthread_mutex_t lock;
};

struct neighbor {
  uint32_t rid;
  uint32_t ip;
  unsigned char mac[6];
  time_t last_hello_received;
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

int pwospf_init(struct sr_instance* sr);
void pwospf_lock(struct pwospf_subsys* subsys);
void pwospf_unlock(struct pwospf_subsys* subsys);


#endif /* SR_PWOSPF_H */
