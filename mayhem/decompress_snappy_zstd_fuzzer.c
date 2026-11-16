/* Request-body decoders for snappy and zstd: the payload is the compressed bytes.
   in_http, in_opentelemetry, in_prometheus_remote_write and in_forward hand the body of a request
   straight to these functions. Every call gets the whole input, then frees what it returned. */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_zstd.h>
#include <fluent-bit/flb_compression.h>

#include "fault_injection.h"

#include <stddef.h>
#include <stdint.h>

/* Expanded-size budget the HTTP inputs pass to the bounded decoders. */
#define DECODE_LIMIT (10 * 1024 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *out = NULL;
    size_t out_len = 0;
    void *payload = NULL;
    size_t payload_len = 0;
    int algorithm;

    /* First byte: allocation-failure selector (mayhem/fault_injection.h). */
    if (size < 1) {
        return 0;
    }
    mayhem_set_fault_selector(data[0]);
    data++;
    size--;

    if (flb_snappy_uncompress((char *) data, size, &out, &out_len) == 0) {
        flb_free(out);
    }

    out = NULL;
    if (flb_snappy_uncompress_framed_data((char *) data, size, &out, &out_len) == 0) {
        flb_free(out);
    }

    out = NULL;
    if (flb_snappy_uncompress_bounded(&out, &out_len, (char *) data, size,
                                      DECODE_LIMIT) == 0) {
        flb_free(out);
    }

    payload = NULL;
    if (flb_zstd_uncompress((void *) data, size, &payload, &payload_len) == 0) {
        flb_free(payload);
    }

    /* The decompression front end the OpenTelemetry input uses for a whole payload. */
    for (algorithm = FLB_COMPRESSION_ALGORITHM_ZSTD;
         algorithm <= FLB_COMPRESSION_ALGORITHM_SNAPPY; algorithm++) {
        payload = NULL;
        if (flb_decompress_buffer(algorithm, (void *) data, size, DECODE_LIMIT,
                                  &payload, &payload_len) == 0) {
            flb_free(payload);
        }
    }

    return 0;
}
