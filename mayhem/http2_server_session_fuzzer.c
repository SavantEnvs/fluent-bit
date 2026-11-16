/*
 * HTTP/2 server session ingest: the nghttp2-driven counterpart of http1_server_session_fuzzer.c, behind
 * the same input plugins (in_http, in_opentelemetry, in_splunk, in_prometheus_remote_write) when a
 * client speaks h2. The input is fed in chunks through flb_http_server_session_ingest() on a session
 * created for HTTP/2 (the plugins' servers can be configured to h2; the connection preface and frames
 * come from the input). The queued requests are then drained the way
 * flb_http_server_client_activity_event_handler() does it: begin a response, inflate the body per
 * Content-Encoding (FLB_HTTP_SERVER_FLAG_AUTO_INFLATE), commit a rejection, release the stream. The
 * socket write at the end of the real handler is not reachable without a connection; the queued
 * response bytes are dropped instead.
 */
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_compression.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/http_server/flb_http_server.h>

#include "fault_injection.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MAYHEM_DECODED_LIMIT (10 * 1024 * 1024)

static void drain_requests(struct flb_http_server_session *session,
                           struct flb_http_server *server)
{
    struct cfl_list          *iterator;
    struct cfl_list          *backup;
    struct flb_http_request  *request;
    struct flb_http_response *response;
    struct flb_http_stream   *stream;
    int                       result;

    cfl_list_foreach_safe(iterator, backup, &session->request_queue) {
        request = cfl_list_entry(iterator, struct flb_http_request, _head);
        stream = (struct flb_http_stream *) request->stream;
        response = flb_http_response_begin(session, stream);

        if (request->body != NULL && request->content_length == 0) {
            request->content_length = cfl_sds_len(request->body);
        }

        result = flb_http_request_uncompress_body(request,
                                                  server->max_decoded_body_size);
        if (result != 0 && response != NULL) {
            flb_http_response_set_status(response,
                                         result == FLB_DECOMPRESSOR_LIMIT_EXCEEDED ?
                                         413 : 400);
            flb_http_response_commit(response);
        }

        /* nghttp2 might still need the response (deferred DATA) */
        flb_http2_server_stream_release(stream);
    }

    cfl_sds_set_len(session->outgoing_data, 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct flb_http_server          server;
    struct flb_http_server_session *session;
    size_t                          chunk;
    size_t                          offset;
    size_t                          length;
    int                             result;

    if (size < 2) {
        return 0;
    }

    /* First byte: allocation-failure selector (mayhem/fault_injection.h); second byte: ingest
       chunk size (0 = the whole input in one call). */
    mayhem_set_fault_selector(data[0]);
    chunk = data[1];
    data += 2;
    size -= 2;

    memset(&server, 0, sizeof(server));
    server.flags = FLB_HTTP_SERVER_FLAG_AUTO_INFLATE;
    server.protocol_version = HTTP_PROTOCOL_VERSION_20;
    server.buffer_max_size = 4 * 1024 * 1024;
    server.http1_max_header_size = 64 * 1024;
    server.max_decoded_body_size = MAYHEM_DECODED_LIMIT;
    cfl_list_init(&server.clients);
    cfl_list_init(&server.detached_clients);

    session = flb_http_server_session_create(HTTP_PROTOCOL_VERSION_20);
    if (session == NULL) {
        return 0;
    }
    session->parent = &server;
    cfl_sds_set_len(session->outgoing_data, 0);

    offset = 0;
    while (offset < size) {
        length = size - offset;
        if (chunk > 0 && length > chunk) {
            length = chunk;
        }

        result = flb_http_server_session_ingest(session,
                                                (unsigned char *) &data[offset],
                                                length);
        drain_requests(session, &server);
        if (result < 0) {
            break;
        }
        offset += length;
    }

    flb_http_server_session_destroy(session);
    return 0;
}
