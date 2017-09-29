/* Support function needed for using tinyDTLS in a specific environment */

#ifndef DTLS_SUPPORT_H_
#define DTLS_SUPPORT_H_

#include "tinydtls.h"
#include "dtls.h"

/* Support functions needed by the tinyDTLS codebase */
dtls_context_t *malloc_context(void);
void free_context(dtls_context_t *context);
int dtls_get_random(unsigned long *rand);
void dtls_set_retransmit_timer(dtls_context_t *context, unsigned int);
void dtls_support_init(void);

/**
 * Resets the given session_t object @p sess to its default
 * values.  In particular, the member rlen must be initialized to the
 * available size for storing addresses.
 *
 * @param sess The session_t object to initialize.
 */
void dtls_session_init(session_t *sess);

/**
 * Compares the given session objects. This function returns @c 0
 * when @p a and @p b differ, @c 1 otherwise.
 */
int dtls_session_equals(const session_t *a, const session_t *b);

/**
 * Get the address information for this session as an opaque (void *)
 */
void *dtls_session_get_address(const session_t *a);

/**
 * Get the address information size for this session.
 */
int dtls_session_get_address_size(const session_t *a);

/**
 * print the session info
 */
void dtls_session_print(const session_t *a);

/**
 * sn-print the session info
 */
void dtls_session_snprint(const session_t *a, char *buf, size_t size);


#endif /* DTLS_SUPPORT_H_ */
