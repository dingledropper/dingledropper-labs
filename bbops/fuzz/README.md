# bbops/fuzz — thermal-throttled fuzzing on the Air

Fuzzing is the one sustained-CPU workload here, so on a fanless M4 it's
deliberately throttled: half the cores by default, `nice`d, time-capped so it
duty-cycles instead of pinning all-core forever.

## Prove the loop works (2 minutes)

```sh
clang -g -O1 -fsanitize=fuzzer,address examples/parser_fuzz.c -o /tmp/parser_fuzz
./run-fuzzer.sh /tmp/parser_fuzz
```

`examples/parser_fuzz.c` has a planted heap overflow. Within seconds AddressSanitizer
should crash and write a repro into `./crashes/`. That confirms the toolchain end-to-end.

## Point it at a real target

1. Pick a library that eats untrusted bytes (parsers, codecs, image/font/media,
   compression, protocol decoders) — **and is in a paying program / OSS-Fuzz-adjacent**.
2. Write a harness: replace `LLVMFuzzerTestOneInput` so it feeds `data`/`size`
   into the real library function, then build it against that library with
   `-fsanitize=fuzzer,address`.
3. Seed `./corpus/` with valid sample inputs (real files of that format) — good
   seeds matter more than CPU.
4. Run it through `run-fuzzer.sh`. Triage anything in `./crashes/`.

## Thermal knobs (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `JOBS` | half the cores | parallel fuzzing workers |
| `MAX_TOTAL_TIME` | `3600` | seconds per run (duty-cycling; `0` = unlimited, not advised) |
| `RSS_LIMIT_MB` | `2048` | memory cap per worker |

Honest note: writing good harnesses is the skill that makes fuzzing pay. With
"not much coding," lean on me to write harnesses for specific targets you pick —
that's the right division of labour.
