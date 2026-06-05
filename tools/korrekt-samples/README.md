# Korrekt samples — Orchard canonicity under-constraint hunt

Drop-in circuits for the Korrekt + cvc5 (finite-field) under-constrained
analyzer. They use the Analyzable-Halo2 fork dialect
(`zcash_halo2_proofs`, `Fr = pasta::Fp = pallas::Base`).

| file | what it is |
|---|---|
| `canonicity_decomp.rs` | **Calibration only.** Generic "dropped range gate -> free cell" toy. Confirms the pipeline flags a known-broken circuit. Cannot reproduce the real psi bug (see below). |
| `note_commit_psi.rs` | **Faithful, decisive.** Full 255-bit model of the `note_commit` psi canonicity property over the real Pallas modulus. |

## Why `note_commit_psi.rs` is full-width (not a toy)

`psi` is a field element, always in `[0, p)`. The real gate prevents a prover
committing to the non-canonical 255-bit string `bits(psi + p)` (which is
`< 2^255` and `≡ psi (mod p)`, so it satisfies `Σ b_k 2^k = psi` in the field)
instead of `bits(psi)`. That second witness only exists at the real `p` and
full width — a scaled-down model makes "secure" and "broken" identical. So this
is the smallest model that is actually decisive.

- `NoteCommitPsi<Secure>`: enforces final borrow of `V - p` == 1 (i.e. `V < p`,
  canonical) -> unique witness.
- `NoteCommitPsi<UnderConstrained>`: drops exactly that one constraint (the
  analog of the real gate's `h_1 · z13_g1_g2_prime` term) -> `bits(psi)` and
  `bits(psi+p)` both satisfy everything -> cvc5 should report UNDER-CONSTRAINED.

## Run (on the box where Korrekt + cvc5 live)

1. Calibrate first on the broken toy — pipeline MUST flag it:
   point `korrekt/src/main.rs::run_analysis` at `CanonicityDecompCircuitUnderConstrained`,
   then `bash run-korrekt.sh -t undcc -v r -l in -i 5`.
2. Then point `run_analysis` at `NoteCommitPsiCircuitUnderConstrained`
   (from `note_commit_psi.rs`) and run the same command.
   - `UnderConstrained` should report **under-constrained** (the `+p` witness).
   - As a control, `NoteCommitPsiCircuit` (Secure) should report **well-constrained**.

`note_commit_psi.rs` is iteration-1 and blind-authored (this container can't
compile the fork). Expect the same small dialect tweaks the other sample needed
(`assign_advice`/`assign_fixed` closure-vs-value shape, `Constraints::with_selector`
import path). cvc5 over 255 bit-rows is heavy — run on the strongest host.

## Disposition

A cvc5 hit here proves the dropped constraint is **load-bearing** for psi
canonicity. The real-circuit question it points at: does `note_commit` actually
bind `z13_g` / `z13_g1_g2_prime` to their lookup-region running sums, or is one
left unanchored (the Hornby class)? Confirm any real suspicion with a
two-witness `MockProver` on the full Orchard circuit before believing it, and
disclose privately to ZODL core — never publicly.
