# orchard-uc — Orchard Action circuit under-constrained-cell detector (Lane-1, full-circuit)

Extends the Lane-2 EC-base anchor sweep to the **whole** Orchard Action circuit.
Targets the surface the NU6.2 fix and Lane-2 did **not** cover: gadget-internal
canonicity / decomposition (`note_commit`/Sinsemilla, `commit_ivk`,
scalar-fixed-short, nullifier) — i.e. the "intricate special cases" the FV teams
are racing on.

## What it reports
1. **Gate inventory** — every custom gate and which advice columns it constrains.
2. **Candidates** — advice cells that are *assigned* + *referenced by a gate* +
   **not** transitively equality-bound to a trusted source (a `Fixed` constant or
   an `Instance` public input). That is the exact shape of the Hornby
   unanchored-base bug (`[a]base + [b]B'`), generalized. Candidates in
   canonicity/decomposition regions are marked `<<< HOT`.

A clean run prints `NONE` — a calibrated negative, same disposition as Lane-2.

## Run (M4 / clanker)
```bash
cargo run --release                      # fixed (post-NU6.2) circuit
cargo run --release --features insecure  # historical insecure circuit (sanity:
                                         # it SHOULD surface the known mul base cell)
```
Use `--features insecure` first as a **calibration**: the detector should flag the
known unanchored variable-base-mul cell. If it does, the fixed run's output is
trustworthy. (This is the Lane-1 "calibrate on the known bug first" discipline.)

## Version pinning
`orchard 0.14.0` → `halo2_proofs 0.3.x`, `pasta_curves 0.5.x`, `halo2_gadgets 0.5.x`.
If `cargo` resolves a mismatched `halo2_proofs`, force it to match orchard 0.14.0's
lockfile: `cargo update -p halo2_proofs --precise <ver>`.

## Three likely compile tweaks (marked `// TWEAK:` in src/main.rs)
1. `assign_advice` generic shape — newer halo2_proofs take `Value<VR>` directly
   instead of a closure `V: FnOnce() -> Value<VR>`.
2. `cs.constants()` vs the field `cs.constants` (older API).
3. Some versions require `fn get_challenge(&self, _: Challenge) -> Value<F>` on
   `Assignment` — add it returning `Value::unknown()` if the compiler asks.

## Confirming a candidate (two-witness MockProver — do this before believing it)
For a flagged cell, build a minimal circuit exercising that gadget and prove the
**soundness break** directly (per the Lane-1 RUNBOOK):
```text
1. honest witness w  -> MockProver::run(k, &c_honest, instances).verify() == Ok
2. forged  witness w' (the cell set to a value inconsistent with its supposed
   source, all OTHER constraints still satisfiable)
       fixed circuit  -> verify() == Err   (constraint catches it)
       if a candidate is real, the *current* circuit will verify() == Ok on w'
```
If the current circuit accepts `w'`, you have a soundness bug → responsible
disclosure to ZODL core (Daira-Emma Hopwood / Kris Nuttycombe / Jack Grigg),
same channel as Hornby. Do **not** post publicly.

## Complementary heavier pass
Point your already-built **Korrekt + cvc5** (Lane-1) at `note_commit.rs` and
`commit_ivk.rs` for SMT-level under-constraint detection. This structural detector
is the fast first filter; Korrekt is the deep confirm. Never treat a clean
structural run as proof of soundness — only the two-witness MockProver (or a full
FV) is.
