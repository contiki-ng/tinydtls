#ifndef DTLS_SUPPORT_CONF_H_
#define DTLS_SUPPORT_CONF_H_

#include "ip/uip.h"
typedef struct {
  unsigned char size;
  uip_ipaddr_t addr;
  unsigned short port;
  int ifindex;
} session_t;

#endif /* DTLS_SUPPORT_CONF_H_ */
