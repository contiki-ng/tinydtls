/* Support function needed for using tinyDTLS in a specific environment */

#include "dtls.h"

/* Support functions needed by the tinyDTLS codebase */
dtls_context_t *malloc_context();
void free_context(dtls_context_t *context);
int dtls_get_random(unsigned long *rand);
void dtls_set_retransmit_timer(dtls_context_t *context, unsigned int);
void dtls_support_init(void);
