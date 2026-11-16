/*
 * OTLP/HTTP JSON request bodies for metrics and traces: the two decoders in_opentelemetry runs when
 * the request's Content-Type is JSON (process_payload_metrics -> flb_opentelemetry_metrics_json_to_cmt,
 * opentelemetry_traces.c process_json -> flb_opentelemetry_json_traces_to_ctrace). The OTLP logs and the
 * protobuf metrics and traces decoders have upstream harnesses; these two JSON paths had none. The
 * results are destroyed the way the plugin does when ingest does not take them over.
 */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_decode_opentelemetry.h>
#include <ctraces/ctraces.h>

#include "fault_injection.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct cfl_list contexts;
    struct ctrace  *trace;
    char           *body;
    int             error_status;
    int             traces;

    if (size < 2) {
        return 0;
    }

    /* First byte: allocation-failure selector (mayhem/fault_injection.h); second byte: 0 = metrics,
       anything else = traces. */
    mayhem_set_fault_selector(data[0]);
    traces = data[1] != 0;
    data += 2;
    size -= 2;

    body = flb_malloc(size + 1);
    if (body == NULL) {
        return 0;
    }
    memcpy(body, data, size);
    body[size] = '\0';

    if (traces) {
        error_status = 0;
        trace = flb_opentelemetry_json_traces_to_ctrace(body, size, &error_status);
        if (trace != NULL) {
            ctr_destroy(trace);
        }
    }
    else {
        if (flb_opentelemetry_metrics_json_to_cmt(&contexts, body, size) ==
            CMT_DECODE_OPENTELEMETRY_SUCCESS) {
            cmt_decode_opentelemetry_destroy(&contexts);
        }
    }

    flb_free(body);
    return 0;
}
