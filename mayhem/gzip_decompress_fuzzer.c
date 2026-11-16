/* Gzip request-body decoders: one-shot multi-member decoding (flb_gzip_uncompress_multi) and the
   streaming decompressor (flb_decompress -> flb_gzip_decompressor_dispatch) that in_forward,
   in_tail and the HTTP server feed with data as it arrives. */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_compression.h>

#include "fault_injection.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Expanded-size budget the HTTP inputs give a decompression context. */
#define DECODE_LIMIT (10 * 1024 * 1024)

/* Append `chunk` bytes at a time, draining the decoder after each one, as in_forward does. */
static void stream_decode(const uint8_t *data, size_t size, size_t chunk)
{
    struct flb_decompression_context *context;
    uint8_t out[512];
    size_t out_len;
    size_t offset = 0;
    size_t length;
    int ret;

    context = flb_decompression_context_create(FLB_COMPRESSION_ALGORITHM_GZIP,
                                               FLB_DECOMPRESSION_BUFFER_SIZE);
    if (context == NULL) {
        return;
    }
    context->output_limit = DECODE_LIMIT;

    while (offset < size) {
        length = size - offset < chunk ? size - offset : chunk;

        if (length > flb_decompression_context_get_available_space(context)) {
            if (flb_decompression_context_resize_buffer(
                    context, context->input_buffer_length + length) != 0) {
                break;
            }
        }
        memcpy(flb_decompression_context_get_append_buffer(context), data + offset, length);
        context->input_buffer_length += length;
        offset += length;
        if (offset == size) {
            context->input_complete = FLB_TRUE;
        }

        do {
            out_len = sizeof(out);
            ret = flb_decompress(context, out, &out_len);
        } while (ret == FLB_DECOMPRESSOR_SUCCESS && out_len > 0);

        if (ret != FLB_DECOMPRESSOR_SUCCESS) {
            break;
        }
    }

    flb_decompression_context_destroy(context);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    void *out;
    size_t out_len;
    size_t remaining;
    size_t consumed = 0;
    size_t total = 0;

    /* First byte: allocation-failure selector (mayhem/fault_injection.h). */
    if (size < 1) {
        return 0;
    }
    mayhem_set_fault_selector(data[0]);
    data++;
    size--;

    /* A stream of concatenated members, decoded one member at a time. */
    while (consumed < size) {
        out = NULL;
        remaining = 0;
        if (flb_gzip_uncompress_multi((void *) (data + consumed), size - consumed,
                                      &out, &out_len, &remaining) != 0) {
            break;
        }
        flb_free(out);
        /* One member can already expand to ~100 MB (flb_gzip.c's own limit); do not chain them. */
        total += out_len;
        if (total >= DECODE_LIMIT || remaining == 0 || remaining >= size - consumed) {
            break;
        }
        consumed = size - remaining;
    }

    stream_decode(data, size, size > 0 ? size : 1);
    stream_decode(data, size, 64);

    return 0;
}
