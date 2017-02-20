#include "support.h"

static dtls_context_t the_dtls_context;

dtls_context_t *malloc_context() {
  return &the_dtls_context;
}

void free_context(dtls_context_t *context) {
}

PROCESS(dtls_retransmit_process, "DTLS retransmit process");


#ifndef NDEBUG

static size_t
dsrv_print_addr(const session_t *addr, char *buf, size_t len) {
#ifdef HAVE_ARPA_INET_H
  const void *addrptr = NULL;
  in_port_t port;
  char *p = buf;

  switch (addr->addr.sa.sa_family) {
  case AF_INET:
    if (len < INET_ADDRSTRLEN)
      return 0;

    addrptr = &addr->addr.sin.sin_addr;
    port = ntohs(addr->addr.sin.sin_port);
    break;
  case AF_INET6:
    if (len < INET6_ADDRSTRLEN + 2)
      return 0;

    *p++ = '[';

    addrptr = &addr->addr.sin6.sin6_addr;
    port = ntohs(addr->addr.sin6.sin6_port);

    break;
  default:
    memcpy(buf, "(unknown address type)", min(22, len));
    return min(22, len);
  }

  if (inet_ntop(addr->addr.sa.sa_family, addrptr, p, len) == 0) {
    perror("dsrv_print_addr");
    return 0;
  }

  p += dtls_strnlen(p, len);

  if (addr->addr.sa.sa_family == AF_INET6) {
    if (p < buf + len) {
      *p++ = ']';
    } else
      return 0;
  }

  p += snprintf(p, buf + len - p + 1, ":%d", port);

  return p - buf;
#else /* HAVE_ARPA_INET_H */
# if WITH_CONTIKI
  char *p = buf;
#  ifdef UIP_CONF_IPV6
  uint8_t i;
  const char hex[] = "0123456789ABCDEF";

  if (len < 41)
    return 0;

  *p++ = '[';

  for (i=0; i < 16; i += 2) {
    if (i) {
      *p++ = ':';
    }
    *p++ = hex[(addr->addr.u8[i] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i] & 0x0f)];
    *p++ = hex[(addr->addr.u8[i+1] & 0xf0) >> 4];
    *p++ = hex[(addr->addr.u8[i+1] & 0x0f)];
  }
  *p++ = ']';
#  else /* UIP_CONF_IPV6 */
#   warning "IPv4 network addresses will not be included in debug output"

  if (len < 21)
    return 0;
#  endif /* UIP_CONF_IPV6 */
  if (buf + len - p < 6)
    return 0;

  p += sprintf(p, ":%d", uip_htons(addr->port));

  return p - buf;
# else /* WITH_CONTIKI */
  /* TODO: output addresses manually */
#   warning "inet_ntop() not available, network addresses will not be included in debug output"
# endif /* WITH_CONTIKI */
  return 0;
#endif
}

#endif /* NDEBUG */


void
dsrv_log(log_t level, char *format, ...) {
  static char timebuf[32];
  va_list ap;

  if (maxlog < level)
    return;

  if (print_timestamp(timebuf,sizeof(timebuf), clock_time()))
    PRINTF("%s ", timebuf);

  if (level <= DTLS_LOG_DEBUG) 
    PRINTF("%s ", loglevels[level]);

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
}

void
dtls_dsrv_hexdump_log(log_t level, const char *name, const unsigned char *buf, size_t length, int extend) {
  static char timebuf[32];
  int n = 0;

  if (dtls_get_log_level() < level)
    return;

  if (print_timestamp(timebuf,sizeof(timebuf), clock_time()))
    PRINTF("%s ", timebuf);

  if (level >= 0 && level <= DTLS_LOG_DEBUG)
    PRINTF("%s ", loglevels[level]);

  if (extend) {
    PRINTF("%s: (%zu bytes):\n", name, length);

    while (length--) {
      if (n % 16 == 0)
	PRINTF("%08X ", n);

      PRINTF("%02X ", *buf++);

      n++;
      if (n % 8 == 0) {
	if (n % 16 == 0)
	  PRINTF("\n");
	else
	  PRINTF(" ");
      }
    }
  } else {
    PRINTF("%s: (%zu bytes): ", name, length);
    while (length--)
      PRINTF("%02X", *buf++);
  }
  PRINTF("\n");
}

/* --------- time support --------- */

clock_time_t dtls_clock_offset;

void
dtls_clock_init(void) {
  clock_init();
  dtls_clock_offset = clock_time();
}

void
dtls_ticks(dtls_tick_t *t) {
  *t = clock_time();
}


int
dtls_get_random(unsigned int *rand)
{
  *rand = clock_time();
}


static void dtls_retransmit_callback((void *) ptr);

void
dtls_support_init(void) {
  /* Start the ctimer */
  ctimer_set(&the_dtls_context.retransmit_timer, 0xFFFF,
             dtls_retransmit_callback, NULL);
}

/*---------------------------------------------------------------------------*/
/* message retransmission */
/*---------------------------------------------------------------------------*/
static void dtls_retransmit_callback((void *) ptr)
{
  clock_time_t now;
  clock_time_t next;

  now = clock_time();
  /* Just one retransmission per timer scheduling */
  dtls_check_retransmit(&the_dtls_context, &next, 0);

  /* need to set timer to some value even if no nextpdu is available */
  if (next != 0) {
    ctimer_set(&the_dtls_context.retransmit_timer,
               next <= now ? 1 : next - now,
               dtls_retransmit_callback, NULL);
  } else {
    ctimer_set(&the_dtls_context.retransmit_timer, 0xFFFF,
               dtls_retransmit_callback, NULL);
  }
}

void
dtls_session_init(session_t *sess) {
  assert(sess);
  memset(sess, 0, sizeof(session_t));
  sess->size = sizeof(sess->addr);
}

int
dtls_session_equals(const session_t *a, const session_t *b) {
  assert(a); assert(b);
  return (a->size == b->size
          && a->port == b->port
          && uip_ipaddr_cmp(&((a)->addr),&(b->addr))
          && a->ifindex == b->ifindex);
}



void dtls_support_init(void)
{
  /* setup whatever */
}
