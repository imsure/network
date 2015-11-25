#ifndef sr_UTILS_H
#define sr_UTILS_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

uint16_t checksum(void *data, int len);

#endif /* --  sr_UTILS_H -- */
