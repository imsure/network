#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_utils.h"

uint16_t checksum(void *data, int len)
{
  long sum = 0;  /* assume 32 bit long, 16 bit short */
  uint16_t *_data = (uint16_t *)data;

  while(len > 1) {
    sum += *_data++;
    if(sum & 0x80000000)   /* if high order bit set, fold */
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
  }

  if(len)       /* take care of left over byte */
    sum += (unsigned short) *(unsigned char *)_data;
          
  while(sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return ~sum;
}

void print_mac(uint8_t *mac)
{
  for (int i = 0; i < 5; i++) {
    printf("%02x:", mac[i]);
  }
  printf("%02x", mac[5]);
}

void print_ip(uint32_t ip)
{
  uint8_t *ip_addr = (uint8_t *)&ip;
  for (int i = 0; i < 3; i++) {
    printf("%d.", ip_addr[i]);
  }
  printf("%d", ip_addr[3]);
}
