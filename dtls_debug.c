/*******************************************************************************
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *    Hauke Mehrtens - memory optimization, ECC integration
 *
 *******************************************************************************/

#include "tinydtls.h"
#include "dtls_config.h"

#if defined(HAVE_ASSERT_H) && !defined(assert)
#include <assert.h>
#endif

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "global.h"
#include "dtls_debug.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

static int maxlog = DTLS_LOG_WARN;	/* default maximum log level */

const char *dtls_package_name() {
  return PACKAGE_NAME;
}

const char *dtls_package_version() {
  return PACKAGE_VERSION;
}

log_t
dtls_get_log_level() {
  return maxlog;
}

void
dtls_set_log_level(log_t level) {
#ifdef NDEBUG
  maxlog = min(level, DTLS_LOG_INFO);
#else /* !NDEBUG */
  maxlog = level;
#endif /* NDEBUG */
}

/* this array has the same order as the type log_t */
char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "WARN", "NOTE", "INFO", "DEBG" 
};

#ifndef NDEBUG
/** dumps packets in usual hexdump format */
void hexdump(const unsigned char *packet, int length) {
  int n = 0;

  while (length--) { 
    if (n % 16 == 0)
      printf("%08X ",n);

    printf("%02X ", *packet++);

    n++;
    if (n % 8 == 0) {
      if (n % 16 == 0)
	printf("\n");
      else
	printf(" ");
    }
  }
}

/** dump as narrow string of hex digits */
void dump(unsigned char *buf, size_t len) {
  while (len--) 
    printf("%02x", *buf++);
}

void dtls_dsrv_log_addr(log_t level, const char *name, const session_t *addr)
{
  char addrbuf[73];
  int len;

  len = dsrv_print_addr(addr, addrbuf, sizeof(addrbuf));
  if (!len)
    return;
  dsrv_log(level, "%s: %s\n", name, addrbuf);
}

#endif /* NDEBUG */
