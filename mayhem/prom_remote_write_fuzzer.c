/*
 * Prometheus remote-write request body: the protobuf (WriteRequest) that in_prometheus_remote_write's
 * process_payload_metrics_ng() hands to cmt_decode_prometheus_remote_write_create() once the HTTP
 * layer has inflated it. The decoded context is then encoded to msgpack, which is what the plugin's
 * ingest step (flb_input_metrics_append) does with it, and destroyed. Snappy framing of the body is
 * covered by mayhem-fuzz-decompress_snappy_zstd.
 */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_encode_msgpack.h>
#include <cmetrics/cmt_decode_prometheus_remote_write.h>

#include "fault_injection.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct cmt *context;
    char       *encoded;
    size_t      encoded_size;
    char       *body;

    if (size < 1) {
        return 0;
    }

    /* First byte: allocation-failure selector (mayhem/fault_injection.h). */
    mayhem_set_fault_selector(data[0]);
    data++;
    size--;

    /* The request body is a NUL-terminated cfl_sds in the plugin. */
    body = flb_malloc(size + 1);
    if (body == NULL) {
        return 0;
    }
    memcpy(body, data, size);
    body[size] = '\0';

    context = NULL;
    if (cmt_decode_prometheus_remote_write_create(&context, body, size) ==
        CMT_DECODE_PROMETHEUS_REMOTE_WRITE_SUCCESS) {
        encoded = NULL;
        if (cmt_encode_msgpack_create(context, &encoded, &encoded_size) == 0) {
            cmt_encode_msgpack_destroy(encoded);
        }
        cmt_decode_prometheus_remote_write_destroy(context);
    }

    flb_free(body);
    return 0;
}
