# CMake hook for the sanitized fuzz build (mayhem/build.sh passes it as -DCMAKE_PROJECT_INCLUDE).
# CMake includes it after every project() call, so it can adjust the build from mayhem/ without
# editing an upstream file.
get_filename_component(MAYHEM_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)

# Bundled msgpack-c: compile zone.c with the 10 MB allocation cap OSS-Fuzz applies to it by sed.
if(PROJECT_NAME STREQUAL "msgpack-c")
  set_source_files_properties(src/zone.c PROPERTIES
    COMPILE_OPTIONS "-include;${MAYHEM_DIR}/msgpack_zone_cap.h")
endif()

# Harnesses built from a wrapper in mayhem/ instead of upstream's file (the wrapper #includes the
# upstream file unchanged and makes each input independent of the earlier ones).
function(mayhem_wrap_fuzzer target wrapper)
  if(TARGET ${target})
    set_property(TARGET ${target} PROPERTY SOURCES "${MAYHEM_DIR}/${wrapper}")
  endif()
endfunction()

# Fuzzers that are not in upstream's tests/internal/fuzzers/: one source file in mayhem/ each,
# linked the way upstream links its OSS-Fuzz targets. Extra arguments are further source files
# (paths from the repository root) compiled into the fuzzer.
function(mayhem_add_fuzzer name source)
  set(extra_sources "")
  foreach(extra ${ARGN})
    list(APPEND extra_sources "${CMAKE_SOURCE_DIR}/${extra}")
  endforeach()
  add_executable(${name} "${MAYHEM_DIR}/${source}" ${extra_sources})
  target_link_libraries(${name} ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(${name} PROPERTIES LINK_FLAGS "$ENV{LIB_FUZZING_ENGINE}")
  target_link_libraries(${name} fluent-bit-static)
endfunction()

# Buffer-in decoders and parsers that read bytes from the network and need no socket.
function(mayhem_extra_fuzzers)
  mayhem_add_fuzzer(mayhem-fuzz-decompress_snappy_zstd decompress_snappy_zstd_fuzzer.c)
  mayhem_add_fuzzer(mayhem-fuzz-decompress_gzip gzip_decompress_fuzzer.c)
  mayhem_add_fuzzer(mayhem-fuzz-http1_server_session http1_server_session_fuzzer.c)
  mayhem_add_fuzzer(mayhem-fuzz-statsd_line statsd_line_fuzzer.c)
  mayhem_add_fuzzer(mayhem-fuzz-prom_remote_write prom_remote_write_fuzzer.c)
  mayhem_add_fuzzer(mayhem-fuzz-otlp_json otlp_json_fuzzer.c)
  # in_collectd is not built into the library: its type database sources go into the harness.
  mayhem_add_fuzzer(mayhem-fuzz-collectd_packet collectd_packet_fuzzer.c
    plugins/in_collectd/typesdb.c plugins/in_collectd/typesdb_parser.c)
  mayhem_add_fuzzer(mayhem-fuzz-http2_server_session http2_server_session_fuzzer.c)
endfunction()

# src/flb_snappy.c compiles with the same 10 MB allocation cap as msgpack's zone.c: its raw decoder
# sizes the output buffer from the length the stream declares, so a few bytes can ask for gigabytes.
# The callers that have a budget pass it (flb_snappy_uncompress_bounded); flb_snappy_uncompress has
# none. (flb_zstd_uncompress carries its own 100 MB limit, so zstd needs no cap.)
function(mayhem_cap_decoder_allocations)
  set_source_files_properties("${CMAKE_SOURCE_DIR}/src/flb_snappy.c"
    DIRECTORY "${CMAKE_SOURCE_DIR}/src"
    PROPERTIES COMPILE_OPTIONS "-include;${MAYHEM_DIR}/msgpack_zone_cap.h")
endfunction()

# lib/monkey/mk_server/mk_http.c is compiled without UBSan's pointer-overflow check. Every request
# the HTTP/1 server session starts goes through mk_http_request_init(), which takes
# mk_list_entry_first() of the session's dummy mk_server.hosts list; that list is never initialised
# (src/http_server/flb_http_server_http1.c), so the entry is NULL minus a field offset. The result
# is never dereferenced, but the check would abort the http1_server_session harness on its first
# input. ASan and every other UBSan check stay on for this file.
function(mayhem_relax_monkey_http)
  set_source_files_properties("${CMAKE_SOURCE_DIR}/lib/monkey/mk_server/mk_http.c"
    DIRECTORY "${CMAKE_SOURCE_DIR}/lib/monkey/mk_server"
    PROPERTIES COMPILE_OPTIONS "-fno-sanitize=pointer-overflow")
endfunction()

# The bundled protobuf-c is compiled without UBSan's shift-base check. Its tag decoder
# (parse_tag_and_wiretype, protobuf-c.c:2085) shifts a 7-bit group left into an int, so any message
# whose field tag spans five bytes reports "left shift of 127 by 25 places". The result is only
# stored in an unsigned tag; every OTLP and Prometheus remote-write decode goes through it, so the
# check would abort those harnesses on the first mutated tag. ASan and every other UBSan check stay on.
function(mayhem_relax_protobuf_c)
  set_source_files_properties(
    "${CMAKE_SOURCE_DIR}/lib/fluent-otel-proto/proto_c/protobuf-c/protobuf-c.c"
    DIRECTORY "${CMAKE_SOURCE_DIR}/lib/fluent-otel-proto/src"
    PROPERTIES COMPILE_OPTIONS "-fno-sanitize=shift-base")
endfunction()

if(PROJECT_NAME STREQUAL "fluent-bit")
  cmake_language(DEFER CALL mayhem_wrap_fuzzer
    flb-it-fuzz-input_fuzzer_OSSFUZZ input_fuzzer_isolated.c)
  cmake_language(DEFER CALL mayhem_wrap_fuzzer
    flb-it-fuzz-engine_fuzzer_OSSFUZZ engine_fuzzer_isolated.c)
  cmake_language(DEFER CALL mayhem_wrap_fuzzer
    flb-it-fuzz-signv4_fuzzer_OSSFUZZ signv4_fuzzer_isolated.c)
  cmake_language(DEFER CALL mayhem_extra_fuzzers)
  cmake_language(DEFER CALL mayhem_cap_decoder_allocations)
  cmake_language(DEFER CALL mayhem_relax_monkey_http)
  cmake_language(DEFER CALL mayhem_relax_protobuf_c)
endif()
