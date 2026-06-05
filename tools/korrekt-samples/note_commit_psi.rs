//! Faithful full-width model of the Orchard `note_commit` **psi canonicity**
//! soundness property, for Korrekt + cvc5 (finite-field) under-constrained
//! detection.
//!
//! WHY FULL WIDTH (read this before "simplifying")
//! ------------------------------------------------
//! `psi` is a Pallas base-field element, so it is ALWAYS in `[0, p)`. The bug
//! the real gate prevents is NOT "psi out of range". It is a prover committing
//! to the **non-canonical 255-bit string** `bits(psi + p)` instead of
//! `bits(psi)`:
//!   * `psi + p < 2^255`  (since `psi < p` and `p < 2^254.01`), so it fits in
//!     255 bits, and
//!   * `Σ (bits(psi+p))_k · 2^k  ==  psi + p  ==  psi   (mod p)`,
//!     so it satisfies the field decomposition `Σ b_k 2^k = psi` just like the
//!     canonical string does.
//! The note_commit psi gate's canonicity terms (the `h_1`-gated `z13` checks /
//! the `t_P` borrow) exist precisely to forbid the `+p` representation, so that
//! the Sinsemilla hash binds the unique canonical bits.
//!
//! Therefore the soundness break is a **mod-p phenomenon**: it only exists at
//! the real field `p` and full bit width. A scaled-down toy (e.g. the earlier
//! `canonicity_decomp.rs`) CANNOT reproduce the second witness — the `+p`
//! string does not fit, so "secure" and "broken" look identical. This model is
//! the smallest one that is actually decisive.
//!
//! WHAT THIS MODELS
//! ----------------
//! value `V = Σ_{k=0}^{254} b_k · 2^k`, public instance `psi = V (mod p)`.
//!   * decomposition + per-bit booleanity pin the canonical bits, AND
//!   * an LSB-first borrow chain computes `V - p`; the final borrow-out is 1
//!     iff `V < p`. The **canonicity** constraint forces that final borrow = 1,
//!     i.e. the bit-string is the canonical one (`V = psi`, not `psi + p`).
//!
//! `NoteCommitPsi<Secure>`          : final-borrow == 1 enforced  -> unique witness.
//! `NoteCommitPsi<UnderConstrained>`: that one constraint dropped -> `bits(psi)`
//!     and `bits(psi+p)` both satisfy everything => cvc5 should report
//!     UNDER-CONSTRAINED. That single dropped constraint is the analog of the
//!     real gate's dropped `h_1 · z13_g1_g2_prime` canonicity term.
//!
//! This is still a triage model: a cvc5 hit says "this constraint is
//! load-bearing for psi canonicity". The real-circuit question it points at is
//! whether note_commit actually binds `z13_g1_g2_prime` / `z13_g` to their
//! lookup-region running sums (the Hornby "unanchored cell" class). Confirm any
//! real suspicion with a two-witness MockProver on the full circuit.

use group::ff::PrimeField as Field;
use zcash_halo2_proofs::circuit::*;
use zcash_halo2_proofs::plonk::*;
use zcash_halo2_proofs::poly::Rotation;

/// Number of value bits (k = 0..=254). 255 bits covers `[0, 2^255)`, which
/// contains both `psi` and `psi + p`.
const N_BITS: usize = 255;

/// Pallas base field modulus p, little-endian u64 limbs.
/// p = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
const P_LIMBS: [u64; 4] = [
    0x8c46eb2100000001,
    0x224698fc0994a8dd,
    0x0000000000000000,
    0x4000000000000000,
];

#[inline]
fn p_bit(k: usize) -> u64 {
    (P_LIMBS[k / 64] >> (k % 64)) & 1
}

/// Compile-time selection of which variant we build.
pub trait Mode {
    /// If true, enforce the final-borrow canonicity constraint.
    const SECURE: bool;
}
pub struct Secure;
pub struct UnderConstrained;
impl Mode for Secure {
    const SECURE: bool = true;
}
impl Mode for UnderConstrained {
    const SECURE: bool = false;
}

#[derive(Clone)]
pub struct PsiConfig {
    b: Column<Advice>,   // value bit b_k
    acc: Column<Advice>, // running value Σ_{j<=k} b_j 2^j
    brw: Column<Advice>, // borrow-out of (V - p) at bit k
    res: Column<Advice>, // result bit of (V - p) at bit k
    pw: Column<Fixed>,   // 2^k
    pb: Column<Fixed>,   // bit k of p
    inst: Column<Instance>,
    q_init: Selector, // row 0 (acc = 0, brw = 0)
    q_step: Selector, // rows 1..=N_BITS (one per value bit)
    q_last: Selector, // last step only; canonicity (final borrow == 1)
}

pub struct NoteCommitPsi<M: Mode> {
    /// The canonical value bits of the honest witness (b_0 .. b_254), LSB first.
    bits: [bool; N_BITS],
    _mode: core::marker::PhantomData<M>,
}

impl<M: Mode> Default for NoteCommitPsi<M> {
    fn default() -> Self {
        // Honest witness: psi = 1 -> bits = 000...0001 (canonical, < p).
        let mut bits = [false; N_BITS];
        bits[0] = true;
        Self {
            bits,
            _mode: core::marker::PhantomData,
        }
    }
}

impl<F: Field, M: Mode> Circuit<F> for NoteCommitPsi<M> {
    type Config = PsiConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let b = meta.advice_column();
        let acc = meta.advice_column();
        let brw = meta.advice_column();
        let res = meta.advice_column();
        let pw = meta.fixed_column();
        let pb = meta.fixed_column();
        let inst = meta.instance_column();
        meta.enable_equality(acc);
        meta.enable_equality(inst);

        let q_init = meta.selector();
        let q_step = meta.selector();
        let q_last = meta.selector();

        let one = Expression::Constant(F::ONE);
        let two = Expression::Constant(F::ONE + F::ONE);

        // Row 0 init: acc = 0 and borrow_in = 0.
        meta.create_gate("init", |meta| {
            let q = meta.query_selector(q_init);
            let acc0 = meta.query_advice(acc, Rotation::cur());
            let brw0 = meta.query_advice(brw, Rotation::cur());
            vec![q.clone() * acc0, q * brw0]
        });

        // Per value bit k (rows 1..=N_BITS). `prev` row is k-1 (row 0 = init).
        meta.create_gate("step", |meta| {
            let q = meta.query_selector(q_step);

            let bk = meta.query_advice(b, Rotation::cur());
            let resk = meta.query_advice(res, Rotation::cur());
            let brwk = meta.query_advice(brw, Rotation::cur());

            let acc_cur = meta.query_advice(acc, Rotation::cur());
            let acc_prev = meta.query_advice(acc, Rotation::prev());
            let brw_prev = meta.query_advice(brw, Rotation::prev());

            let pw_k = meta.query_fixed(pw, Rotation::cur());
            let pb_k = meta.query_fixed(pb, Rotation::cur());

            // booleanity of the three bit cells
            let bool_b = bk.clone() * (one.clone() - bk.clone());
            let bool_res = resk.clone() * (one.clone() - resk.clone());
            let bool_brw = brwk.clone() * (one.clone() - brwk.clone());

            // running value: acc_cur = acc_prev + b_k * 2^k
            let acc_step = acc_cur - acc_prev - bk.clone() * pw_k;

            // LSB-first subtraction (V - p) at bit k:
            //   b_k - p_k - borrow_in = res_k - 2*borrow_out
            // => b_k - p_k - brw_prev - res_k + 2*brw_cur = 0
            let borrow = bk - pb_k - brw_prev - resk + two.clone() * brwk;

            Constraints::with_selector(q, vec![bool_b, bool_res, bool_brw, acc_step, borrow])
        });

        // Canonicity: final borrow-out == 1  <=>  V < p  <=>  canonical bits.
        // Present only in the Secure variant. Dropping it is the analog of the
        // real gate's dropped `h_1 * z13_g1_g2_prime` term.
        if M::SECURE {
            meta.create_gate("canonicity_final_borrow", |meta| {
                let q = meta.query_selector(q_last);
                let brw_last = meta.query_advice(brw, Rotation::cur());
                vec![q * (brw_last - one.clone())]
            });
        }

        PsiConfig {
            b,
            acc,
            brw,
            res,
            pw,
            pb,
            inst,
            q_init,
            q_step,
            q_last,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let acc_last = layouter.assign_region(
            || "psi decomposition + canonicity",
            |mut region| {
                // Row 0: init (acc = 0, borrow_in = 0).
                config.q_init.enable(&mut region, 0)?;
                region.assign_advice(|| "b0", config.b, 0, || Value::known(F::ZERO))?;
                region.assign_advice(|| "res0", config.res, 0, || Value::known(F::ZERO))?;
                region.assign_advice(|| "acc0", config.acc, 0, || Value::known(F::ZERO))?;
                region.assign_advice(|| "brw0", config.brw, 0, || Value::known(F::ZERO))?;
                // Fixed cells on the init row are unused by gates; set to 0.
                region.assign_fixed(|| "pw0", config.pw, 0, || Value::known(F::ZERO))?;
                region.assign_fixed(|| "pb0", config.pb, 0, || Value::known(F::ZERO))?;

                let mut acc_val = F::ZERO; // running field value
                let mut pow = F::ONE; // 2^k
                let mut borrow_in: u64 = 0; // borrow into bit k (LSB-first)
                let mut last_cell = None;

                for k in 0..N_BITS {
                    let row = k + 1;
                    config.q_step.enable(&mut region, row)?;

                    let bk = self.bits[k] as u64;
                    let pk = p_bit(k);

                    // honest subtraction (V - p) borrow chain, LSB first
                    let diff = bk as i64 - pk as i64 - borrow_in as i64; // in {-2,-1,0,1}
                    let (res_k, borrow_out) = if diff < 0 {
                        ((diff + 2) as u64, 1u64)
                    } else {
                        (diff as u64, 0u64)
                    };

                    region.assign_advice(
                        || "b",
                        config.b,
                        row,
                        || Value::known(if bk == 1 { F::ONE } else { F::ZERO }),
                    )?;
                    region.assign_advice(
                        || "res",
                        config.res,
                        row,
                        || Value::known(if res_k == 1 { F::ONE } else { F::ZERO }),
                    )?;
                    region.assign_advice(
                        || "brw",
                        config.brw,
                        row,
                        || Value::known(if borrow_out == 1 { F::ONE } else { F::ZERO }),
                    )?;
                    region.assign_fixed(|| "pw", config.pw, row, || Value::known(pow))?;
                    region.assign_fixed(
                        || "pb",
                        config.pb,
                        row,
                        || Value::known(if pk == 1 { F::ONE } else { F::ZERO }),
                    )?;

                    if bk == 1 {
                        acc_val += pow;
                    }
                    let cell = region.assign_advice(|| "acc", config.acc, row, || Value::known(acc_val))?;

                    if k == N_BITS - 1 {
                        // enable the canonicity selector on the final step
                        config.q_last.enable(&mut region, row)?;
                        last_cell = Some(cell);
                    }

                    pow = pow + pow; // 2^(k+1)
                    borrow_in = borrow_out;
                }

                Ok(last_cell.unwrap())
            },
        )?;

        // Public input: psi = V (mod p) = final accumulator.
        layouter.constrain_instance(acc_last.cell(), config.inst, 0)?;
        Ok(())
    }
}

/// Convenience aliases matching the Korrekt `run_analysis` hardcoding style.
pub type NoteCommitPsiCircuit = NoteCommitPsi<Secure>;
pub type NoteCommitPsiCircuitUnderConstrained = NoteCommitPsi<UnderConstrained>;
