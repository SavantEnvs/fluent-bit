/* tests/internal/fuzzers/engine_fuzzer.c with a fresh engine for every input.
   Upstream builds one engine in LLVMFuzzerInitialize, starts it, and never stops it, so every input
   adds input/filter/output instances and chunks to the same running engine. Here the upstream
   initializer runs once per input to build a new context, the upstream test runs on it, and the
   context is stopped and destroyed afterwards. The upstream file is included unchanged. */
#include <fluent-bit.h>

#include <stddef.h>
#include <stdint.h>

#define LLVMFuzzerInitialize mayhem_upstream_engine_init
#define LLVMFuzzerTestOneInput mayhem_upstream_engine_test
#include "../tests/internal/fuzzers/engine_fuzzer.c"
#undef LLVMFuzzerInitialize
#undef LLVMFuzzerTestOneInput

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int ret;
    int argc = 0;
    char **argv = NULL;

    /* The upstream test returns before it touches the engine for inputs under 100 bytes, so
       building one for them would only cost time. */
    if (size < 100) {
        return 0;
    }

    mayhem_upstream_engine_init(&argc, &argv);
    ret = mayhem_upstream_engine_test(data, size);

    /* When flb_start() failed it has already joined the engine thread (status FLB_LIB_ERROR) and
       flb_stop() would join it a second time. */
    if (ctx->status == FLB_LIB_OK) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
    ctx = NULL;
    return ret;
}
