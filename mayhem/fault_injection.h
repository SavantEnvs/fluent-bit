/* Allocation-failure selector for the mayhem/ harnesses, driving the same flb_malloc fault
   injection (FLB_TESTS_OSSFUZZ) the upstream harnesses use. Selector 0 never fails; any other value
   makes every Nth flb_malloc/flb_calloc/flb_realloc fail (N = 2..64), so the decoders' out-of-memory
   paths get exercised. flb_malloc_p is reset so the outcome depends on the input alone. */
#ifndef MAYHEM_FAULT_INJECTION_H
#define MAYHEM_FAULT_INJECTION_H

#include <fluent-bit/flb_mem.h>
#include <limits.h>
#include <stdint.h>

static inline void mayhem_set_fault_selector(uint8_t selector)
{
    flb_malloc_p = 0;
    flb_malloc_mod = selector == 0 ? INT_MAX : 2 + (selector % 63);
}

#endif
