/* tests/internal/fuzzers/input_fuzzer.c with its chunk storage made per-input.
   Upstream points storage.path at the fixed /tmp/input-chunk-test/ with storage.type=filesystem and
   never empties it, so chunk files from earlier inputs are reloaded by later ones. Here the
   storage.path value is replaced by a per-process directory (under $TMPDIR) that is deleted before
   and after every input. The upstream file is included unchanged. */
#include <fluent-bit.h>
#include <fluent-bit/flb_config.h>
#include <chunkio/cio_utils.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *mayhem_storage_dir(void)
{
    static char dir[512];
    const char *tmp;

    if (dir[0] == '\0') {
        tmp = getenv("TMPDIR");
        if (tmp == NULL || tmp[0] == '\0') {
            tmp = "/tmp";
        }
        snprintf(dir, sizeof(dir), "%s/input-chunk-test.%d/", tmp, (int) getpid());
    }
    return dir;
}

/* flb_service_set() with the value of "storage.path" swapped for mayhem_storage_dir() */
static int mayhem_service_set(flb_ctx_t *ctx, ...)
{
    char *key;
    char *value;
    va_list va;

    va_start(va, ctx);
    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            va_end(va);
            return -1;
        }
        if (strcmp(key, "storage.path") == 0) {
            value = (char *) mayhem_storage_dir();
        }
        if (flb_config_set_property(ctx->config, key, value) != 0) {
            va_end(va);
            return -1;
        }
    }
    va_end(va);
    return 0;
}

#define flb_service_set(ctx, ...) mayhem_service_set(ctx, __VA_ARGS__)
#define LLVMFuzzerTestOneInput mayhem_upstream_input_fuzzer
#include "../tests/internal/fuzzers/input_fuzzer.c"
#undef LLVMFuzzerTestOneInput
#undef flb_service_set

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int ret;

    cio_utils_recursive_delete(mayhem_storage_dir());
    ret = mayhem_upstream_input_fuzzer(data, size);
    cio_utils_recursive_delete(mayhem_storage_dir());
    return ret;
}
