/*
 * in_collectd network packet decoder. in_collectd_callback() recv()s one UDP datagram into its
 * buffer and passes it, unchanged, to netprot_to_msgpack() with the plugin's TypesDB and log event
 * encoder; the encoded records are then appended to the engine. This harness repeats the
 * netprot_to_msgpack() call on the input as the datagram. The TypesDB is a fixed one holding the
 * definitions collectd ships for the common types (load, cpu, memory, if_octets, ...), built with
 * the TypesDB module's own typesdb_add_node()/typesdb_add_field(). The plugin is not built into the
 * library: typesdb.c and typesdb_parser.c are compiled into this binary, and netprot.c is included
 * unchanged because its helpers are static.
 */
#include "../plugins/in_collectd/netprot.c"

#include "fault_injection.h"

static struct mk_list *type_db;

static const char *const type_definitions[][5] = {
    { "gauge",      "value:GAUGE:U:U" },
    { "derive",     "value:DERIVE:0:U" },
    { "counter",    "value:COUNTER:U:U" },
    { "absolute",   "value:ABSOLUTE:0:U" },
    { "load",       "shortterm:GAUGE:0:5000", "midterm:GAUGE:0:5000", "longterm:GAUGE:0:5000" },
    { "cpu",        "value:DERIVE:0:U" },
    { "memory",     "value:GAUGE:0:281474976710656" },
    { "if_octets",  "rx:DERIVE:0:U", "tx:DERIVE:0:U" },
    { "if_packets", "rx:DERIVE:0:U", "tx:DERIVE:0:U" },
    { "df_complex", "value:GAUGE:0:U" },
    { "disk_octets", "read:DERIVE:0:U", "write:DERIVE:0:U" },
    { "temperature", "value:GAUGE:-273.15:U" },
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    struct typesdb_node *node;
    size_t               i;
    size_t               j;

    /* flb_malloc_mod is 0 until set: the fault injection divides by it */
    mayhem_set_fault_selector(0);

    type_db = flb_malloc(sizeof(struct mk_list));
    if (type_db == NULL) {
        return 0;
    }
    mk_list_init(type_db);

    for (i = 0; i < sizeof(type_definitions) / sizeof(type_definitions[0]); i++) {
        if (typesdb_add_node(type_db, type_definitions[i][0]) != 0) {
            continue;
        }
        node = typesdb_last_node(type_db);
        for (j = 1; j < 5 && type_definitions[i][j] != NULL; j++) {
            typesdb_add_field(node, type_definitions[i][j]);
        }
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct flb_log_event_encoder encoder;
    char                        *packet;

    if (size < 1 || type_db == NULL) {
        return 0;
    }

    /* First byte: allocation-failure selector (mayhem/fault_injection.h). */
    mayhem_set_fault_selector(data[0]);
    data++;
    size--;

    packet = flb_malloc(size + 1);
    if (packet == NULL) {
        return 0;
    }
    memcpy(packet, data, size);
    packet[size] = '\0';

    if (flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT) ==
        FLB_EVENT_ENCODER_SUCCESS) {
        netprot_to_msgpack(packet, (int) size, type_db, &encoder);
        flb_log_event_encoder_destroy(&encoder);
    }

    flb_free(packet);
    return 0;
}
