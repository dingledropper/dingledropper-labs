//! Canonicity-class model for the Orchard note_commit hunt.
//!
//! Models the *signature* we're chasing in `orchard::circuit::note_commit`:
//! a value `v` is split into limbs and reassembled, and a HIGH limb that must be
//! range/canonicity-bounded is (in the under-constrained variant) left unbound.
//! When a decomposition piece isn't range-bound, the prover can substitute a
//! non-canonical field element (e.g. the ½·p trick) that satisfies the linear
//! reassembly while differing from the honest witness -> two models, same public
//! input -> UNDER-CONSTRAINED.
//!
//! This is a CLASS model / porting template, NOT orchard's exact psi/rho
//! canonicity gates. A cvc5 hit here demonstrates the detector catches the
//! signature; the next step is porting the real limb structure from note_commit.rs.
//!
//! v = l0 + 2*l1 + 4*l2 ; public input i = v.
//!   constrained:        l0,l1,l2 all boolean (range-bound) + reassembly
//!   under-constrained:  l2's boolean (range) gate is DROPPED  <-- the bug class

use group::ff::PrimeField as Field;
use zcash_halo2_proofs::circuit::*;
use zcash_halo2_proofs::plonk::*;
use zcash_halo2_proofs::poly::Rotation;

#[derive(Clone)]
pub struct CanonicityDecompConfig {
    l0: Column<Advice>,
    l1: Column<Advice>,
    l2: Column<Advice>,
    v: Column<Advice>,
    i: Column<Instance>,
    s: Selector,
}

// ----------------------------------------------------------------------------
// Fully-constrained version (expected: NOT under-constrained)
// ----------------------------------------------------------------------------
pub struct CanonicityDecompCircuit<F: Field> {
    l0: F,
    l1: F,
    l2: F,
}

impl<F: Field> Default for CanonicityDecompCircuit<F> {
    fn default() -> Self {
        Self { l0: F::ONE, l1: F::ONE, l2: F::ONE }
    }
}

impl<F: Field> Circuit<F> for CanonicityDecompCircuit<F> {
    type Config = CanonicityDecompConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let l0 = meta.advice_column();
        let l1 = meta.advice_column();
        let l2 = meta.advice_column();
        let v = meta.advice_column();
        let i = meta.instance_column();
        let s = meta.selector();
        meta.enable_equality(v);
        meta.enable_equality(i);

        meta.create_gate("l0_range", |meta| {
            let a = meta.query_advice(l0, Rotation::cur());
            let dummy = meta.query_selector(s);
            vec![dummy * a.clone() * (Expression::Constant(F::from(1)) - a)]
        });
        meta.create_gate("l1_range", |meta| {
            let a = meta.query_advice(l1, Rotation::cur());
            let dummy = meta.query_selector(s);
            vec![dummy * a.clone() * (Expression::Constant(F::from(1)) - a)]
        });
        // The HIGH-limb canonicity/range gate. Present here, dropped below.
        meta.create_gate("l2_canonicity", |meta| {
            let a = meta.query_advice(l2, Rotation::cur());
            let dummy = meta.query_selector(s);
            vec![dummy * a.clone() * (Expression::Constant(F::from(1)) - a)]
        });
        meta.create_gate("reassembly", |meta| {
            let a = meta.query_advice(l0, Rotation::cur());
            let b = meta.query_advice(l1, Rotation::cur());
            let c = meta.query_advice(l2, Rotation::cur());
            let val = meta.query_advice(v, Rotation::cur());
            let dummy = meta.query_selector(s);
            // v = l0 + 2*l1 + 4*l2
            vec![dummy * (a + Expression::Constant(F::from(2)) * b
                + Expression::Constant(F::from(4)) * c - val)]
        });

        Self::Config { l0, l1, l2, v, i, s }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let out = layouter
            .assign_region(
                || "decomp",
                |mut region| {
                    config.s.enable(&mut region, 0)?;
                    region.assign_advice(|| "l0", config.l0, 0, || Value::known(self.l0))?;
                    region.assign_advice(|| "l1", config.l1, 0, || Value::known(self.l1))?;
                    region.assign_advice(|| "l2", config.l2, 0, || Value::known(self.l2))?;
                    let out = region.assign_advice(
                        || "v",
                        config.v,
                        0,
                        || Value::known(self.l0 + F::from(2) * self.l1 + F::from(4) * self.l2),
                    )?;
                    Ok(out)
                },
            )
            .unwrap();
        layouter.constrain_instance(out.cell(), config.i, 0)?;
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Under-constrained version: l2's canonicity/range gate is DROPPED.
// Expected: cvc5 reports UNDER-CONSTRAINED (l2 can take a non-canonical value).
// ----------------------------------------------------------------------------
pub struct CanonicityDecompCircuitUnderConstrained<F: Field> {
    l0: F,
    l1: F,
    l2: F,
}

impl<F: Field> Default for CanonicityDecompCircuitUnderConstrained<F> {
    fn default() -> Self {
        Self { l0: F::ONE, l1: F::ONE, l2: F::ONE }
    }
}

impl<F: Field> Circuit<F> for CanonicityDecompCircuitUnderConstrained<F> {
    type Config = CanonicityDecompConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let l0 = meta.advice_column();
        let l1 = meta.advice_column();
        let l2 = meta.advice_column();
        let v = meta.advice_column();
        let i = meta.instance_column();
        let s = meta.selector();
        meta.enable_equality(v);
        meta.enable_equality(i);

        meta.create_gate("l0_range", |meta| {
            let a = meta.query_advice(l0, Rotation::cur());
            let dummy = meta.query_selector(s);
            vec![dummy * a.clone() * (Expression::Constant(F::from(1)) - a)]
        });
        meta.create_gate("l1_range", |meta| {
            let a = meta.query_advice(l1, Rotation::cur());
            let dummy = meta.query_selector(s);
            vec![dummy * a.clone() * (Expression::Constant(F::from(1)) - a)]
        });
        // l2_canonicity gate intentionally OMITTED -> the bug class.
        meta.create_gate("reassembly", |meta| {
            let a = meta.query_advice(l0, Rotation::cur());
            let b = meta.query_advice(l1, Rotation::cur());
            let c = meta.query_advice(l2, Rotation::cur());
            let val = meta.query_advice(v, Rotation::cur());
            let dummy = meta.query_selector(s);
            vec![dummy * (a + Expression::Constant(F::from(2)) * b
                + Expression::Constant(F::from(4)) * c - val)]
        });

        Self::Config { l0, l1, l2, v, i, s }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let out = layouter
            .assign_region(
                || "decomp",
                |mut region| {
                    config.s.enable(&mut region, 0)?;
                    region.assign_advice(|| "l0", config.l0, 0, || Value::known(self.l0))?;
                    region.assign_advice(|| "l1", config.l1, 0, || Value::known(self.l1))?;
                    region.assign_advice(|| "l2", config.l2, 0, || Value::known(self.l2))?;
                    let out = region.assign_advice(
                        || "v",
                        config.v,
                        0,
                        || Value::known(self.l0 + F::from(2) * self.l1 + F::from(4) * self.l2),
                    )?;
                    Ok(out)
                },
            )
            .unwrap();
        layouter.constrain_instance(out.cell(), config.i, 0)?;
        Ok(())
    }
}
