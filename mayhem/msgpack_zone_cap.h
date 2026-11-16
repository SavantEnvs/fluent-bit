/* Force-included (-include) into lib/msgpack-c/src/zone.c by mayhem/fuzz_build_hooks.cmake.
   Allocations over 10 MB fail, as with the sed patch OSS-Fuzz's fluent-bit build.sh applies to that
   file: a msgpack length header can ask msgpack_zone_malloc_expand for any size, and that is the
   decoder's contract, not a bug. Done at compile time so the upstream file stays untouched. */
#include <stdlib.h>

static inline void *mayhem_capped_malloc(size_t n)
{
    return n > 10u * 1024u * 1024u ? NULL : malloc(n);
}

#define malloc(n) mayhem_capped_malloc(n)
