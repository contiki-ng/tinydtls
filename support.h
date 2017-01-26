/* Support function needed for using tinyDTLS in a specific environment */

#import "dtls.h"

dtls_context_t *malloc_context();
void free_context(dtls_context_t *context);
