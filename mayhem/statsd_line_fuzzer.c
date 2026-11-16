/*
 * in_statsd datagram decoder. The plugin's cb_statsd_receive() recv()s one UDP
 * datagram and then either hands it to cmt_decode_statsd_create() (metrics
 * mode) or splits it on '\n' and runs the static statsd_process_line() on
 * each line (log mode). This harness feeds the datagram in directly and
 * repeats those two branches; only the recv() and the append to the engine
 * are left out. The upstream source is included unchanged to reach the
 * static function.
 */
#define in_statsd_plugin mayhem_upstream_in_statsd_plugin
#include "../plugins/in_statsd/statsd.c"
#undef in_statsd_plugin

#include <cmetrics/cmt_decode_statsd.h>
#include "fault_injection.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct flb_input_instance instance;
    struct flb_statsd         ctx;
    struct cfl_split_entry   *entry;
    struct cfl_list          *head;
    struct cfl_list          *lines;
    struct cmt               *cmt;
    char                     *buf;
    int                       metrics;

    if (size < 2) {
        return 0;
    }

    /* First byte: allocation-failure selector (mayhem/fault_injection.h); second byte: 0 = log
       events, anything else = metrics. */
    mayhem_set_fault_selector(data[0]);
    metrics = data[1] != 0;
    data += 2;
    size -= 2;

    /* The datagram is read into a NUL-terminated MAX_PACKET_SIZE buffer. */
    if (size > MAX_PACKET_SIZE - 1) {
        size = MAX_PACKET_SIZE - 1;
    }

    buf = flb_malloc(size + 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, data, size);
    buf[size] = '\0';

    if (metrics) {
        cmt = NULL;
        if (cmt_decode_statsd_create(&cmt, buf, size,
                                     CMT_DECODE_STATSD_GAUGE_OBSERVER) ==
            CMT_DECODE_STATSD_SUCCESS) {
            cmt_destroy(cmt);
        }
        flb_free(buf);
        return 0;
    }

    memset(&instance, 0, sizeof(instance));
    memset(&ctx, 0, sizeof(ctx));
    ctx.ins = &instance;
    ctx.buf = buf;
    ctx.log_encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ctx.log_encoder == NULL) {
        flb_free(buf);
        return 0;
    }

    lines = cfl_utils_split(buf, '\n', -1);
    if (lines != NULL) {
        cfl_list_foreach(head, lines) {
            entry = cfl_list_entry(head, struct cfl_split_entry, _head);
            if (statsd_process_line(&ctx, entry->value) !=
                FLB_EVENT_ENCODER_SUCCESS) {
                break;
            }
        }
        cfl_utils_split_free(lines);
    }

    flb_log_event_encoder_destroy(ctx.log_encoder);
    flb_free(buf);
    return 0;
}
