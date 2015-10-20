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

struct sr_instance;

void sr_arp_reply(struct sr_instance* sr, 
		  uint8_t * packet/* lent */,
		  unsigned int len,
		  char* interface/* lent */);


#endif /* --  sr_ARP_H -- */
