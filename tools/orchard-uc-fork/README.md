# orchard-uc-fork — real-circuit structural under-constrained detector

Analyzes the **real** `orchard::circuit::Circuit` (note_commit, commit_ivk,
nullifier, scalar-fixed-short, …) for the Hornby "unanchored cell" class:
advice cells that a gate constrains but that are **never equality-bound** to a
trusted source (a circuit constant `Fixed` or a public input `Instance`).

## Why it compiles now (it didn't before)

Stock `halo2_proofs 0.3` seals `Column::index`, `ConstraintSystem::gates`, and
query column indices, so a downstream crate can't read the constraint system —
that's why the earlier attempt failed. This crate's `Cargo.toml` does:

```toml
[patch.crates-io]
halo2_proofs = { git = "https://github.com/Analyzable-Halo2/zcash-halo2.git", package = "halo2_proofs" }
```

The Analyzable-Halo2 fork is the **same 0.3.0** with those marked `pub`
("Visibility changed for analyzer") — the very fork Korrekt uses. Verified
compatible: exact version `0.3.0`, has the `batch` +
`floor-planner-v1-legacy-pdqsort` features orchard needs, standard 0.3 `Circuit`
trait, clean `Assignment` trait (no `annotate_column`). So orchard + halo2_gadgets
build unchanged while this crate introspects them.

## Run (on a host that can build orchard — M2 / clanker)

```
cargo run --release
```

First build pulls orchard 0.14, halo2_gadgets 0.5, and the fork; expect a few
minutes. If `cargo` complains about a second halo2_proofs in the tree, add the
same `[patch.crates-io]` for any other halo2 crate it names.

## Reading the output

- **gate inventory** — every custom gate and the advice columns it constrains.
- **CANDIDATES** — gate-constrained advice cells not anchored to a constant/
  instance, grouped by region. `<<< HOT` marks canonicity/decomposition regions
  (`note_commit`, `commit_ivk`, `psi`, `rho`, `canon`, `sinsemilla`, …).

This is **triage**: there WILL be false positives — many legitimate advice cells
are constrained purely by gates + lookups and never copied to a constant. The
signal is *targeted*: in the psi/commit_ivk canonicity regions, check whether the
canonicity-input cells (`z13_g`, `z13_g1_g2_prime`, `*_prime`) sit in a copy
component with their decomposition source, as the soundness argument requires.

## Disposition

A genuinely unanchored canonicity cell would be a soundness bug → confirm with a
two-witness `MockProver` on the full circuit, then disclose **privately** to
ZODL core (Daira-Emma Hopwood / Kris Nuttycombe / Jack Grigg) — never publicly.
A clean `NONE` (or only explained false positives) is a calibrated negative.
