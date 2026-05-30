/*
 * bbops worked example — a tiny libFuzzer harness with a PLANTED bug, so you can
 * confirm the whole fuzzing pipeline works end-to-end on the Air before pointing
 * it at a real target.
 *
 * Build (Apple clang ships with libFuzzer + ASan):
 *   clang -g -O1 -fsanitize=fuzzer,address parser_fuzz.c -o /tmp/parser_fuzz
 * Run via the throttled runner:
 *   ../run-fuzzer.sh /tmp/parser_fuzz
 *
 * Within seconds ASan should report a heap-buffer-overflow and drop a crash file
 * in ./crashes — that's your proof the loop works. Then replace LLVMFuzzerTestOneInput
 * with a harness that feeds `data` into the real library function you want to fuzz.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Pretend this is a parser in some library you're fuzzing. */
static void parse(const uint8_t *data, size_t size) {
    char buf[16];
    /* Planted bug: trusts attacker-controlled length. A real bug class. */
    if (size >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        memcpy(buf, data, size);   /* overflow when size > 16 */
        (void)buf;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse(data, size);
    return 0;
}
