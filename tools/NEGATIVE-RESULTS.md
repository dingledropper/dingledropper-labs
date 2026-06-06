# Negative results — ZK counterfeiting/soundness hunt

Record of surfaces audited and cleared, so a future pass starts from the
frontier instead of zero. Everything below is a **negative** (sound, or a
duplicate of public work, or not worth further tooling). Nothing here was
filed; nothing reached adversarial review because there was nothing to file.

## Cleared surfaces

| Surface | Verdict |
|---|---|
| Zcash consensus value-accounting (turnstile, binding sigs, per-pool conservation, VK routing) | Sound — no in-protocol counterfeit vector remains post-NU6.2 |
| ZSA per-asset value commitment (variable-base on AssetBase, QED-it zsa1) | **Duplicate** of public GHSA-jfw5-j458-pfv6 (Hornby unanchored-base) → DO NOT FILE |
| Polygon zkEVM input-binding (`_getInputSnarkBytes`, `_getInputPessimisticBytes`) | Sound — all fields fixed-length (no `abi.encodePacked` collision), full state-transition binding, `_checkStateRootInsidePrime` Goldilocks canonicity check |
| snarkjs verifier templates (Groth16 / PLONK / fflonk `.sol.ejs`) | Hardened — `checkField` / input range-checks / on-curve checks present |
| zkVerify `fflonk_verifier` core | Sound — point on-curve + field range checks; transcript binds raw public input, so non-canonical-pub divergence from the Solidity reference is not a counterfeiting vector |
| zkVerify statement hash (`compute_statement_hash`) | Sound — `keccak(keccak(ctx) ‖ vk_hash ‖ version ‖ keccak(pubs))`, all 4 parts fixed-32B, domain-separated by `ctx` |
| zkVerify aggregate Merkle tree (`compute_receipt`) | Sound — `H256` leaves length-separated from 64B nodes; explicit awareness in code |
| zkVerify verifier wrappers (sp1, risc0, groth16) | Sound — vkey/image-id + pubs bound; risc0 binds proof version; groth16 checks pub-count vs vk IC-length and curve coherence |
| zkVerify EVM attestation contracts (`Merkle.verifyProofKeccak`, leaf encoders, posting auth) | Sound — leaf/node length-separated; encoders match the pallet; root posting is `onlyRole(OPERATOR)` or ISMP `onlyHost` + exact source-id check |
| Orchard circuit-internal canonicity (`note_commit` psi/rho, `commit_ivk`) | **Not pursued** — see tooling notes below |

## Tooling notes (`tools/`)

- `korrekt-samples/` — calibrated Korrekt+cvc5 under-constrained detector.
  `canonicity_decomp.rs` calibrates the pipeline. `note_commit_psi.rs` documents
  why a *decisive* psi-canonicity model must be full-width over the real `p`
  (the bug is the `bits(psi+p)` non-canonical representation, a mod-p
  phenomenon that cannot be scaled down). Korrekt analyzes a small row-window,
  so multi-row models false-positive; a correct model would only re-prove the
  textbook fact that canonicity gates are necessary — calibration, not discovery.
- `orchard-uc-fork/` — structural copy-anchor detector for the **real** orchard
  circuit, built against the Analyzable-Halo2 fork (which un-seals
  `Column::index` / `cs.gates`). **Blocked:** the fork (commit `7fc5e14d`,
  nominal 0.3.0) is an older halo2 snapshot missing `Error::IllegalHashFromPrivatePoint`
  and the `AssignedCell<F,F> → AssignedCell<Assigned<F>,F>` conversions that
  `halo2_gadgets 0.5.0` requires, so orchard 0.14 won't compile against it.

## Meta-lesson

Across every funded, audited ZK target, the verifier-soundness / input-binding /
attestation / canonicity bug classes are **covered**. Bounty size tracks audit
coverage; a structural scanner or template sweep only has an edge in *un*-audited
code, which carries ~no bounty. Honest floor — no inflation.

## If resuming

The remaining differentiated edges, in rough EV order:
1. Deep *manual* cryptographic analysis of a specific gadget (how Hornby was
   actually found) — not a scanner.
2. The `orchard-uc-fork` detector IF the fork is updated to a halo2 commit
   compatible with halo2_gadgets 0.5.0, OR rewritten against stock halo2_proofs
   0.3 using `Debug`-string column identity (copy-anchor only, noisier).
3. Newer/less-audited ZK programs (the EVM-side of fresh rollups, custom
   aggchain/SP1 integrations) — better prior than the picked-over flagships.
