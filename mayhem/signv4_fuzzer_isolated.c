/* tests/internal/fuzzers/signv4_fuzzer.c with its credentials made per-input.
   Upstream setenv()s AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from the input and never removes
   them, so the environment the next input starts in depends on the previous one. Here both are
   unset after every input. The upstream file is included unchanged. */
#define LLVMFuzzerTestOneInput mayhem_upstream_signv4_test
#include "../tests/internal/fuzzers/signv4_fuzzer.c"
#undef LLVMFuzzerTestOneInput

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int ret;

    ret = mayhem_upstream_signv4_test(data, size);
    unsetenv(AWS_ACCESS_KEY_ID);
    unsetenv(AWS_SECRET_ACCESS_KEY);
    unsetenv(AWS_SESSION_TOKEN);
    return ret;
}
