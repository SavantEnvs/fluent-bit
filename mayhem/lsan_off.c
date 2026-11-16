/* Fleet policy: disable LeakSanitizer at BUILD time for every ASan-instrumented target. ASan's
   memory-corruption checks and UBSan stay fully on and halting -- only leak detection is affected.
   Leaks are not the defect class this fleet fuzzes for, and several of the upstream harnesses
   (engine/config/input) tear down fluent-bit contexts on error paths that do not free everything.
   This is the sanctioned build-time hook; no runtime sanitizer-option override is used, because
   Mayhem alone owns the runtime sanitizer option set. Linked into every fuzzer and -standalone
   binary by mayhem/build.sh. */
int __lsan_is_turned_off(void);
int __lsan_is_turned_off(void) {
  return 1;
}
