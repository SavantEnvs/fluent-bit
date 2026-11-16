#!/usr/bin/env bash
#
# mayhem/test.sh — RUN fluent-bit's own unit-test suites, the two upstream CI runs: the internal
# suite (tests/internal, flb-it-*) and the runtime plugin suite (tests/runtime, flb-rt-*), both
# acutest, which mayhem/build.sh already built with the project's normal flags into build/tests
# (upstream's skip list applied there, at configure time). Never compiles.
#
# The oracle is behavioral: every flb-it-* / flb-rt-* binary is an acutest runner whose test cases assert
# values (TEST_CHECK). A binary counts only if it prints acutest's own verdict line
# ("SUCCESS: All unit tests have passed."), so a program neutered to exit(0) FAILS here. Counts are
# per acutest test case ("Test <name>... [ OK ]" / "[ FAILED ]"); binaries are run directly.
#
# Output: a CTRF report at ${CTRF_REPORT:-$SRC/ctrf-report.json} plus a `CTRF {...}` line on stdout;
# exit non-zero iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TEST_BIN="$SRC/build/tests/bin"
shopt -s nullglob
IT_BINS=("$TEST_BIN"/flb-it-*)
RT_BINS=("$TEST_BIN"/flb-rt-*)
if [ "${#IT_BINS[@]}" -eq 0 ] || [ "${#RT_BINS[@]}" -eq 0 ]; then
  echo "test.sh: missing flb-it-* or flb-rt-* test binaries in $TEST_BIN (mayhem/build.sh must run first)" >&2
  emit_ctrf "acutest" 0 1 0
  exit 1
fi
BINS=("${IT_BINS[@]}" "${RT_BINS[@]}")

# Cases that cannot pass in this image for a reason unrelated to the code under test. Format:
# "<binary>:<acutest case>". Each one is passed to acutest's --skip and reported as skipped.
#   flb-it-utils:test_flb_utils_get_machine_id — asserts two calls return the SAME machine id; the
#     image has no /etc/machine-id or /var/lib/dbus/machine-id (no systemd/dbus), so fluent-bit
#     falls back to a fresh random UUID on every call.
SKIP_CASES=(
  "flb-it-utils:test_flb_utils_get_machine_id"
)

# flb-rt-in_http:failure_response_code_400_bad_disk_write renames its storage.path
# (/tmp/http-input-test-404-bad-write -> .fail) with rename(2) to make the next chunk write fail.
# The build-time run of this suite (Dockerfile) leaves that dir behind in an image layer, and on
# overlayfs rename(2) of a directory from a lower layer fails with EXDEV, so the write succeeds and
# the case gets 201. Remove the leftover so every run starts from the fresh /tmp the test expects.
rm -rf /tmp/http-input-test-404-bad-write /tmp/http-input-test-404-bad-write.fail

passed=0; failed=0; skipped=0
logdir="$(mktemp -d "${TMPDIR:-/tmp}/flb-test.XXXXXX")"
trap 'rm -rf "$logdir"' EXIT
# upstream registers every test with WORKING_DIRECTORY <source>/build.
cd "$SRC/build"

# run_one <bin> <log>: one acutest binary, with its --skip list; prints its exit code.
run_one() {
  local bin="$1" log="$2" t args=() sc rc=0
  t="$(basename "$bin")"
  for sc in "${SKIP_CASES[@]}"; do
    [ "${sc%%:*}" = "$t" ] || continue
    [ "${#args[@]}" -gt 0 ] || args=(--skip)
    args+=("${sc#*:}")
  done
  timeout 600 "$bin" "${args[@]}" >"$log" 2>&1 </dev/null || rc=$?
  echo "$rc" > "$log.rc"
}
verdict_ok() { [ "$(cat "$1.rc")" -eq 0 ] && grep -aq '^SUCCESS: All unit tests have passed' "$1"; }

# The suite is ~1.2k cases and many runtime cases sleep for seconds, so binaries run in parallel,
# as upstream's `ctest --parallel` does. Runtime plugin tests listen on fixed ports (in_http 9880,
# in_splunk 8088, ...), so two binaries running at once can collide on a port; a binary that fails
# in the parallel pass is re-run ALONE once, and that solo run is its verdict (a real failure fails
# both times).
export -f run_one
export SKIP_CASES_STR="${SKIP_CASES[*]}"
printf '%s\n' "${BINS[@]}" | xargs -P "$MAYHEM_JOBS" -I{} bash -c \
  'SKIP_CASES=($SKIP_CASES_STR); run_one "$1" "$2/$(basename "$1").log"' _ {} "$logdir"

for bin in "${BINS[@]}"; do
  t="$(basename "$bin")"; log="$logdir/$t.log"
  if ! verdict_ok "$log"; then
    echo "retry    $t alone (parallel run: rc=$(cat "$log.rc"))"
    run_one "$bin" "$log"
  fi
  nskip=0
  for sc in "${SKIP_CASES[@]}"; do [ "${sc%%:*}" = "$t" ] && nskip=$(( nskip + 1 )); done
  rc="$(cat "$log.rc")"
  ok=$(grep -acE '\[ OK \][[:space:]]*$' "$log" || true)
  bad=$(grep -acE '\[ FAILED \][[:space:]]*$' "$log" || true)
  passed=$(( passed + ok ))
  failed=$(( failed + bad ))
  skipped=$(( skipped + nskip ))
  if verdict_ok "$log"; then
    echo "ok       $t ($ok cases)"
  else
    # Crashed, timed out, or exited without acutest's verdict: one failure even if no case said so.
    [ "$bad" -gt 0 ] || failed=$(( failed + 1 ))
    echo "FAILED   $t (rc=$rc, $ok ok, $bad failed)"
    grep -aE '\[ FAILED \]|Check .*failed|^FAILED:|interrupted' "$log" | head -20 | sed 's/^/    /'
  fi
done

emit_ctrf "acutest" "$passed" "$failed" "$skipped"
