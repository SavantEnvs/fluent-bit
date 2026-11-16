#!/usr/bin/env bash
#
# mayhem/build.sh — build fluent-bit's fuzz harnesses and its internal unit-test suite.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image exports the
# build contract (CC, CXX, LIB_FUZZING_ENGINE, SANITIZER_FLAGS, STANDALONE_FUZZ_MAIN, SRC).
#
# What it builds (everything stays ADDITIVE — no upstream file is edited):
#   1. build/fuzz   upstream's own OSS-Fuzz configuration (-DFLB_TESTS_OSSFUZZ=ON, the plugin set
#                   OSS-Fuzz's projects/fluent-bit/build.sh selects), compiled with
#                   $SANITIZER_FLAGS + SanitizerCoverage + DWARF-3. Every harness in
#                   tests/internal/fuzzers/ becomes /mayhem/flb-it-fuzz-<name>_OSSFUZZ (libFuzzer)
#                   and /mayhem/flb-it-fuzz-<name>_OSSFUZZ-standalone (run-once reproducer).
#      Eight more harnesses in mayhem/ (mayhem-fuzz-<name>, added by the same hook) cover the
#      buffer-in decoders upstream has none for: snappy/zstd, gzip (multi-member and streaming),
#      the HTTP/1 and HTTP/2 server sessions, in_statsd's line parser, the Prometheus remote-write
#      body, OTLP JSON metrics and traces, and in_collectd's packet parser.
#   2. build/tests  the project's internal unit tests (tests/internal, acutest) with the project's
#                   NORMAL flags — the functional oracle mayhem/test.sh runs.
# Both build trees live under build/, which upstream's .gitignore already ignores (`build/*`), so a
# `git clean -ffdX` removes them and a re-run reconfigures from scratch.
#
# Differences from OSS-Fuzz's build.sh, on purpose:
#   * OSS-Fuzz sed-patches lib/msgpack-c/src/zone.c to cap allocations at 10 MB. That edits an
#     upstream file, so instead mayhem/fuzz_build_hooks.cmake compiles zone.c with a force-included
#     header (mayhem/msgpack_zone_cap.h) that applies the same cap, so a huge msgpack length header
#     is rejected rather than reported as an excessive-allocation defect.
#   * input_fuzzer.c keeps chunk files under a fixed /tmp/input-chunk-test/ across inputs. The same
#     hook builds that one harness from mayhem/input_fuzzer_isolated.c, which includes the upstream
#     file unchanged but gives every process its own storage directory, emptied around each input.
#   * engine_fuzzer.c builds a fluent-bit context once in LLVMFuzzerInitialize and reuses it for
#     every input, so engine state carries over between inputs. The hook builds it from
#     mayhem/engine_fuzzer_isolated.c, which includes the upstream file unchanged and runs it on a
#     fresh context per input. signv4_fuzzer.c leaves two setenv()ed credentials set;
#     mayhem/signv4_fuzzer_isolated.c unsets them after each input.
#   * OSS-Fuzz swaps lib/cmetrics and lib/ctraces for their upstream HEADs at image-build time
#     (an unpinned network fetch). The copies bundled in this tree are used instead.
#   * OSS-Fuzz deletes the system libyaml shared objects to force a static link; here libyaml is an
#     ordinary apt dependency and is linked however CMake finds it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# SANITIZER_FLAGS uses `=` (no colon): an explicit EMPTY value builds with no sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export CC CXX

cd "$SRC"

# The plugin selection OSS-Fuzz builds its fuzzers with (projects/fluent-bit/build.sh). Used for the
# fuzz build only, so the harnesses reach exactly the surface OSS-Fuzz fuzzes.
PLUGIN_FLAGS=(
  -DFLB_IN_COLLECTD=OFF -DFLB_IN_CPU=OFF -DFLB_IN_DISK=OFF -DFLB_IN_DOCKER=OFF -DFLB_IN_EXEC=OFF
  -DFLB_IN_FORWARD=OFF -DFLB_IN_HEAD=OFF -DFLB_IN_HEALTH=OFF -DFLB_IN_KMSG=OFF -DFLB_IN_MEM=OFF
  -DFLB_IN_MQTT=OFF -DFLB_IN_NETIF=OFF -DFLB_IN_PROC=OFF -DFLB_IN_RANDOM=OFF -DFLB_IN_SERIAL=OFF
  -DFLB_IN_STDIN=OFF -DFLB_IN_SYSLOG=OFF -DFLB_IN_SYSTEMD=OFF -DFLB_IN_TAIL=OFF -DFLB_IN_TCP=OFF
  -DFLB_IN_THERMAL=OFF -DFLB_IN_WINLOG=OFF
  -DFLB_OUT_AZURE=OFF -DFLB_OUT_BIGQUERY=OFF -DFLB_OUT_COUNTER=OFF -DFLB_OUT_DATADOG=OFF
  -DFLB_OUT_ES=OFF -DFLB_OUT_FILE=OFF -DFLB_OUT_FLOWCOUNTER=OFF -DFLB_OUT_FORWARD=OFF
  -DFLB_OUT_GELF=OFF -DFLB_OUT_HTTP=ON -DFLB_OUT_INFLUXDB=OFF -DFLB_OUT_KAFKA=OFF
  -DFLB_OUT_KAFKA_REST=OFF -DFLB_OUT_LOKI=OFF -DFLB_OUT_NATS=OFF -DFLB_OUT_NRLOGS=OFF
  -DFLB_OUT_NULL=OFF -DFLB_OUT_PGSQL=OFF -DFLB_OUT_PLOT=OFF -DFLB_OUT_SLACK=OFF
  -DFLB_OUT_SPLUNK=OFF -DFLB_OUT_STACKDRIVER=OFF -DFLB_OUT_STDOUT=ON -DFLB_OUT_SYSLOG=OFF
  -DFLB_OUT_TCP=OFF
  -DFLB_LUAJIT=OFF -DFLB_STREAM_PROCESSOR=OFF
  -DFLB_FILTER_ALTER_SIZE=ON -DFLB_FILTER_AWS=ON -DFLB_FILTER_GREP=ON -DFLB_FILTER_KUBERNETES=ON
  -DFLB_FILTER_MODIFY=ON -DFLB_FILTER_NEST=ON -DFLB_FILTER_PARSER=ON
  -DFLB_FILTER_RECORD_MODIFIER=ON -DFLB_FILTER_REWRITE_TAG=ON -DFLB_FILTER_THROTTLE=ON
  -DFLB_BINARY=OFF -DFLB_EXAMPLES=OFF -DFLB_METRICS=ON -DFLB_DEBUG=ON
  -DMBEDTLS_FATAL_WARNINGS=OFF -DFLB_CONFIG_YAML=ON
)

# ── 1) Sanitized fuzz build ─────────────────────────────────────────────────────────────────────
FUZZ_DIR="$SRC/build/fuzz"
mkdir -p "$FUZZ_DIR/mayhem-objs"

# Build-time LeakSanitizer off-switch (mayhem/lsan_off.c) and the run-once standalone driver, both
# compiled with the same flags as the harnesses.
LSAN_OFF_O="$FUZZ_DIR/mayhem-objs/lsan_off.o"
STANDALONE_O="$FUZZ_DIR/mayhem-objs/standalone_main.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$LSAN_OFF_O"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$STANDALONE_O"

# -fsanitize=fuzzer-no-link puts SanitizerCoverage into the project itself, so the fuzzer gets edge
# feedback from fluent-bit and not only from the harness. $DEBUG_FLAGS goes last so its -gdwarf-3
# wins over any -g carried by $SANITIZER_FLAGS. -fcommon and -DFLB_TESTS_OSSFUZZ=ON are what
# OSS-Fuzz passes.
#
# Two UBSan checks are relaxed for the fuzz build; ASan and every other UBSan check stay on and
# halting:
#   alignment  the upstream harnesses themselves read ints straight out of the fuzz buffer
#              (engine_fuzzer.c:32, http_fuzzer.c:70), as do onigmo's regex bytecode interpreter
#              (lib/onigmo/regexec.c) and flb_config_map.c — the target aborts on the first input,
#              before any fluent-bit code of interest runs. Harmless on x86-64, and not in the
#              UBSan check set OSS-Fuzz builds this project with.
#   function   the bundled protobuf-c (lib/fluent-otel-proto/.../protobuf-c.c:3416) calls each
#              generated message_init through a generic function-pointer type, so every OTLP /
#              cmetrics / ctraces decode trips it on the first message.
UBSAN_RELAX="-fno-sanitize=alignment,function"
FUZZ_CFLAGS="$SANITIZER_FLAGS $UBSAN_RELAX -fsanitize=fuzzer-no-link -fcommon -DFLB_TESTS_OSSFUZZ=ON $DEBUG_FLAGS"

# tests/internal/fuzzers/CMakeLists.txt links each *_OSSFUZZ target with $ENV{LIB_FUZZING_ENGINE}
# (read at configure time). Appending the lsan_off object there links it into every fuzzer.
# No -DCMAKE_C_COMPILER: CMake takes $CC/$CXX, and the -D form wipes the cache on a re-run.
LIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE $LSAN_OFF_O" \
cmake -S "$SRC" -B "$FUZZ_DIR" \
  -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_CFLAGS" \
  -DFLB_TESTS_INTERNAL=ON -DFLB_TESTS_INTERNAL_FUZZ=ON -DFLB_TESTS_OSSFUZZ=ON \
  -DCMAKE_PROJECT_INCLUDE="$SRC/mayhem/fuzz_build_hooks.cmake" \
  "${PLUGIN_FLAGS[@]}"

# Every harness upstream's CMake declares, discovered from the generated build (so a harness added
# upstream is built without touching this script; it still needs its own mayhem/Mayhemfile_*).
mapfile -t FUZZERS < <(cmake --build "$FUZZ_DIR" --target help \
  | sed -n -e 's/^\.\.\. \(flb-it-fuzz-[A-Za-z0-9_]*_OSSFUZZ\)$/\1/p' \
           -e 's/^\.\.\. \(mayhem-fuzz-[A-Za-z0-9_]*\)$/\1/p' | sort)
[ "${#FUZZERS[@]}" -gt 0 ] || { echo "build.sh: no *_OSSFUZZ targets in the generated build" >&2; exit 1; }

cmake --build "$FUZZ_DIR" -j"$MAYHEM_JOBS" --target "${FUZZERS[@]}"

for f in "${FUZZERS[@]}"; do
  # Hard link rather than copy: the harnesses that link all of fluent-bit are ~250 MB each.
  [ "$FUZZ_DIR/bin/$f" -ef "$SRC/$f" ] || ln -f "$FUZZ_DIR/bin/$f" "$SRC/$f" 2>/dev/null \
    || cp -f "$FUZZ_DIR/bin/$f" "$SRC/$f"

  # Standalone reproducer: re-run CMake's own link line for the harness with the libFuzzer runtime
  # swapped for the run-once driver ($STANDALONE_FUZZ_MAIN). Same objects, same libraries, same flags.
  link_txt="$(find "$FUZZ_DIR" -path "*/CMakeFiles/$f.dir/link.txt" | head -1)"
  [ -f "$link_txt" ] || { echo "build.sh: missing link.txt for $f" >&2; exit 1; }
  link_dir="${link_txt%/CMakeFiles/*}"
  link_cmd="$(sed -e "s# -fsanitize=fuzzer # $STANDALONE_O #" \
                  -e "s# -o [^ ]*# -o $SRC/$f-standalone#" "$link_txt")"
  case "$link_cmd" in
    *" -fsanitize=fuzzer "*|*"-o ../"*) echo "build.sh: could not rewrite the link line for $f" >&2; exit 1 ;;
  esac
  case "$link_cmd" in
    *"$STANDALONE_O"*"$SRC/$f-standalone"*|*"$SRC/$f-standalone"*"$STANDALONE_O"*) ;;
    *) echo "build.sh: could not rewrite the link line for $f" >&2; exit 1 ;;
  esac
  ( cd "$link_dir" && bash -c "$link_cmd" )
done

# JSON dictionary for the JSON-parsing harnesses (flb_json / parse_json / pack_json_state): upstream
# ships one with its bundled yyjson (lib/yyjson-<ver>/fuzz/fuzzer.dict). Copied to a version-free
# path so the Mayhemfiles' `dictionary:` survives a yyjson bump; a missing dictionary fails the build.
JSON_DICT=( "$SRC"/lib/yyjson-*/fuzz/fuzzer.dict )
[ -f "${JSON_DICT[0]}" ] || { echo "build.sh: yyjson fuzzer.dict not found under lib/yyjson-*/fuzz" >&2; exit 1; }
cp -f "${JSON_DICT[0]}" "$SRC/flb-json.dict"

# Every Mayhemfile must point at a binary this build produced.
for mf in "$SRC"/mayhem/Mayhemfile_*; do
  [ -f "$mf" ] || continue
  bin="$(sed -n 's/^[[:space:]]*-[[:space:]]*cmd:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$mf" | head -1)"
  [ -x "$bin" ] || { echo "build.sh: $mf points at $bin, which was not built" >&2; exit 1; }
done

# ── 2) Test suite (normal flags) ────────────────────────────────────────────────────────────────
# The project's unit tests, both suites upstream CI builds (.github/scripts/run-unit-tests.sh:
# -DFLB_TESTS_INTERNAL=On -DFLB_TESTS_RUNTIME=On): the internal acutest suite (flb-it-*) and the
# runtime plugin suite (flb-rt-*, tests/runtime — the in_statsd / in_http / in_opentelemetry /
# in_splunk tests cover the plugin code several fuzz targets drive). Built the way upstream builds
# them: no sanitizers, no fuzz instrumentation, upstream's DEFAULT plugin set. Upstream's own skip
# list is passed the same way upstream passes it (-DFLB_WITHOUT_<test>=1): flb-rt-out_elasticsearch,
# out_td, out_forward, in_disk, in_proc and flb-it-fstore, plus flb-it-network when the host has no
# IPv6 loopback. Left out to keep the rebuild short: the fluent-bit binary, the shared library,
# and examples. The bundled WASM runtime (WAMR), LuaJIT and librdkafka stay at upstream's default
# (ON): without them filter_wasm / filter_lua / kafka do not register and their runtime tests
# (filter_wasm, filter_lua, out_kafka) are not built or fail.
# mayhem/test.sh only RUNS build/tests/bin/flb-it-* and flb-rt-*.
TEST_DIR="$SRC/build/tests"
TEST_SKIPS=(-DFLB_WITHOUT_flb-it-fstore=1)
for t in out_elasticsearch out_td out_forward in_disk in_proc; do
  TEST_SKIPS+=("-DFLB_WITHOUT_flb-rt-$t=1")
done
if ! grep -qs '^00000000000000000000000000000001 ' /proc/net/if_inet6; then
  TEST_SKIPS+=(-DFLB_WITHOUT_flb-it-network=1)
fi
cmake -S "$SRC" -B "$TEST_DIR" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DFLB_TESTS_INTERNAL=ON -DFLB_TESTS_RUNTIME=ON -DFLB_TESTS_INTERNAL_FUZZ=OFF -DFLB_TESTS_OSSFUZZ=OFF \
  "${TEST_SKIPS[@]}" \
  -DFLB_BINARY=OFF -DFLB_SHARED_LIB=OFF -DFLB_EXAMPLES=OFF
cmake --build "$TEST_DIR" -j"$MAYHEM_JOBS"

echo "build.sh: built ${#FUZZERS[@]} fuzzers (+ standalone reproducers) and the internal + runtime test suites"
