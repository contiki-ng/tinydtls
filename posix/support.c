/* POSIX support for memb alloc / free and other functions needed to
   run the tinyDTSL applications */

#include "memb.h"
#include <stdlib.h>

void
memb_init(struct memb *m)
{
}


void *
memb_alloc(struct memb *m)
{
  return malloc(m->size);
}

char
memb_free(struct memb *m, void *ptr)
{
  free(ptr);
  return 1;
}
