//! Orchard Action circuit — structural under-constrained-cell detector
//! (full real circuit), built against the **Analyzable-Halo2 fork**.
//!
//! WHY THIS, NOT A KORREKT MODEL
//! -----------------------------
//! Hand-built Korrekt samples can only re-demonstrate textbook facts (e.g. "a
//! decomposition without its range/canonicity gate is under-constrained").
//! DISCOVERY requires analyzing the *real* `orchard::circuit::Circuit`. Stock
//! halo2_proofs 0.3 seals exactly the introspection needed (`Column::index`,
//! `ConstraintSystem::gates`, query column indices), which is why the earlier
//! external-crate attempt did not compile. The Analyzable-Halo2 fork is the
//! same 0.3.0 with those marked `pub`; a `[patch.crates-io]` swaps it in, so
//! orchard + halo2_gadgets compile unchanged and we can read the constraint
//! system.
//!
//! WHAT IT DOES
//! ------------
//! Drives the real circuit through `configure` + `FloorPlanner::synthesize`
//! with a recording `Assignment`, then:
//!   1. union-finds the copy (equality) graph;
//!   2. marks every component touching a Fixed or Instance cell as ANCHORED
//!      (a trusted source: circuit constant or public input);
//!   3. walks every custom gate's polynomials to learn which advice COLUMNS each
//!      gate constrains;
//!   4. flags advice cells that are assigned + referenced by a gate + NOT in an
//!      anchored component -- the generalized shape of the Hornby unanchored-
//!      base bug. Candidates in canonicity/decomposition regions are `<<< HOT`.
//!
//! This is TRIAGE: it produces candidates (it will have false positives for
//! cells that are legitimately constrained only by gates+lookups and never
//! copied to a constant/instance). The point is to scan the note_commit /
//! commit_ivk canonicity regions and check whether the canonicity-input cells
//! (z13_g, z13_g1_g2_prime, *_prime, ...) are anchored as expected. Confirm any
//! real suspicion with a two-witness MockProver on the full circuit before
//! believing it, and disclose privately to ZODL core -- never publicly.
//!
//! RUN (on a host that can build orchard, e.g. M2/clanker):
//!   cargo run --release

use std::collections::{BTreeMap, BTreeSet, HashMap};

use orchard::circuit::Circuit;
use pasta_curves::pallas;

use halo2_proofs::{
    circuit::Value,
    plonk::{
        Advice, Any, Assigned, Assignment, Circuit as PlonkCircuit, Column, ConstraintSystem,
        Error, Expression, Fixed, FloorPlanner, Instance, Selector,
    },
};

type F = pallas::Base;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Kind {
    Advice,
    Fixed,
    Instance,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct Cell {
    kind: Kind,
    col: usize,
    row: usize,
}

fn kind_of(c: &Column<Any>) -> Kind {
    match c.column_type() {
        Any::Advice => Kind::Advice,
        Any::Fixed => Kind::Fixed,
        Any::Instance => Kind::Instance,
    }
}

#[derive(Default)]
struct Recorder {
    ns: Vec<String>,
    region: Vec<String>,
    advice_region: HashMap<Cell, String>,
    advice_cells: BTreeSet<Cell>,
    copies: Vec<(Cell, Cell)>,
    fixed_cells: BTreeSet<Cell>,
    instance_cells: BTreeSet<Cell>,
}

impl Recorder {
    fn path(&self) -> String {
        let mut p = self.ns.clone();
        p.extend(self.region.clone());
        if p.is_empty() {
            "<root>".into()
        } else {
            p.join(" / ")
        }
    }
}

impl Assignment<F> for Recorder {
    fn enter_region<NR, N>(&mut self, name: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.region.push(name().into());
    }

    fn exit_region(&mut self) {
        self.region.pop();
    }

    fn enable_selector<A, AR>(&mut self, _: A, _: &Selector, _: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        Ok(())
    }

    fn query_instance(&self, _: Column<Instance>, _: usize) -> Result<Value<F>, Error> {
        Ok(Value::unknown())
    }

    fn assign_advice<V, VR, A, AR>(
        &mut self,
        _: A,
        column: Column<Advice>,
        row: usize,
        _to: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let cell = Cell {
            kind: Kind::Advice,
            col: column.index(),
            row,
        };
        self.advice_cells.insert(cell);
        self.advice_region.entry(cell).or_insert_with(|| self.path());
        Ok(())
    }

    fn assign_fixed<V, VR, A, AR>(
        &mut self,
        _: A,
        column: Column<Fixed>,
        row: usize,
        _to: V,
    ) -> Result<(), Error>
    where
        V: FnOnce() -> Value<VR>,
        VR: Into<Assigned<F>>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        self.fixed_cells.insert(Cell {
            kind: Kind::Fixed,
            col: column.index(),
            row,
        });
        Ok(())
    }

    fn copy(
        &mut self,
        l: Column<Any>,
        l_row: usize,
        r: Column<Any>,
        r_row: usize,
    ) -> Result<(), Error> {
        let lc = Cell {
            kind: kind_of(&l),
            col: l.index(),
            row: l_row,
        };
        let rc = Cell {
            kind: kind_of(&r),
            col: r.index(),
            row: r_row,
        };
        if lc.kind == Kind::Fixed {
            self.fixed_cells.insert(lc);
        }
        if rc.kind == Kind::Fixed {
            self.fixed_cells.insert(rc);
        }
        if lc.kind == Kind::Instance {
            self.instance_cells.insert(lc);
        }
        if rc.kind == Kind::Instance {
            self.instance_cells.insert(rc);
        }
        self.copies.push((lc, rc));
        Ok(())
    }

    fn fill_from_row(
        &mut self,
        _: Column<Fixed>,
        _: usize,
        _: Value<Assigned<F>>,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn push_namespace<NR, N>(&mut self, name_fn: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.ns.push(name_fn().into());
    }

    fn pop_namespace(&mut self, _: Option<String>) {
        self.ns.pop();
    }
}

// ---- union-find over copied cells -------------------------------------------

struct Uf {
    parent: HashMap<Cell, Cell>,
}
impl Uf {
    fn new() -> Self {
        Self {
            parent: HashMap::new(),
        }
    }
    fn find(&mut self, x: Cell) -> Cell {
        let p = *self.parent.entry(x).or_insert(x);
        if p == x {
            x
        } else {
            let r = self.find(p);
            self.parent.insert(x, r);
            r
        }
    }
    fn union(&mut self, a: Cell, b: Cell) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }
}

// ---- gate polynomial walk: which advice columns does each gate constrain -----

fn collect_advice_cols(e: &Expression<F>, out: &mut BTreeSet<usize>) {
    match e {
        Expression::Advice(q) => {
            out.insert(q.column_index);
        }
        Expression::Negated(a) | Expression::Scaled(a, _) => collect_advice_cols(a, out),
        Expression::Sum(a, b) | Expression::Product(a, b) => {
            collect_advice_cols(a, out);
            collect_advice_cols(b, out);
        }
        _ => {}
    }
}

fn main() {
    let circuit = Circuit::default();

    // 1. configure -> ConstraintSystem (gates, columns)
    let mut cs = ConstraintSystem::<F>::default();
    let config = <Circuit as PlonkCircuit<F>>::configure(&mut cs);

    // 2. synthesize through the recorder
    let mut rec = Recorder::default();
    <Circuit as PlonkCircuit<F>>::FloorPlanner::synthesize(
        &mut rec,
        &circuit,
        config,
        cs.constants.clone(),
    )
    .expect("synthesize");

    // 3. anchor analysis: a component is ANCHORED if it touches a Fixed/Instance cell
    let mut uf = Uf::new();
    for (a, b) in &rec.copies {
        uf.union(*a, *b);
    }
    let mut anchored_roots: BTreeSet<Cell> = BTreeSet::new();
    for c in rec.fixed_cells.iter().chain(rec.instance_cells.iter()) {
        let r = uf.find(*c);
        anchored_roots.insert(r);
    }

    // advice columns constrained by at least one custom gate
    let mut gate_cols: BTreeSet<usize> = BTreeSet::new();
    let mut gate_report: Vec<(String, BTreeSet<usize>)> = Vec::new();
    for gate in cs.gates.iter() {
        let mut cols = BTreeSet::new();
        for poly in gate.polynomials() {
            collect_advice_cols(poly, &mut cols);
        }
        gate_cols.extend(cols.iter().copied());
        gate_report.push((gate.name().to_string(), cols));
    }

    // 4. flag: assigned advice cell, in a gate-constrained column, NOT anchored
    let mut free_by_region: BTreeMap<String, Vec<Cell>> = BTreeMap::new();
    let mut total_free = 0usize;
    let cells: Vec<Cell> = rec.advice_cells.iter().copied().collect();
    for c in cells {
        if !gate_cols.contains(&c.col) {
            continue;
        }
        let root = uf.find(c);
        if !anchored_roots.contains(&root) {
            let region = rec.advice_region.get(&c).cloned().unwrap_or_else(|| "?".into());
            free_by_region.entry(region).or_default().push(c);
            total_free += 1;
        }
    }

    // ---- report ----
    println!("== Orchard Action circuit structural under-constrained scan (fork build) ==");
    println!("advice cells     : {}", rec.advice_cells.len());
    println!("copy constraints : {}", rec.copies.len());
    println!("fixed cells      : {}", rec.fixed_cells.len());
    println!("instance cells   : {}", rec.instance_cells.len());
    println!("custom gates     : {}", gate_report.len());
    println!();

    println!("-- gate inventory (name -> advice columns constrained) --");
    for (name, cols) in &gate_report {
        println!("  [{}]  cols={:?}", name, cols);
    }
    println!();

    println!("-- CANDIDATES: assigned + gate-constrained + NOT anchored to fixed/instance --");
    println!("   (triage; expect false positives for gate/lookup-only cells.");
    println!("    focus on the HOT canonicity/decomposition regions, then confirm");
    println!("    a real suspect with a two-witness MockProver before believing it.)");
    if total_free == 0 {
        println!("   NONE.");
    } else {
        for (region, cells) in &free_by_region {
            let hot = [
                "note_commit",
                "commit",
                "ivk",
                "short",
                "canon",
                "decompos",
                "sinsemilla",
                "nullifier",
                "psi",
                "rho",
            ]
            .iter()
            .any(|k| region.to_lowercase().contains(k));
            let mark = if hot { "  <<< HOT" } else { "" };
            println!("  region: {region}  ({} cells){mark}", cells.len());
            for c in cells.iter().take(16) {
                println!("      advice col {} row {}", c.col, c.row);
            }
            if cells.len() > 16 {
                println!("      ... (+{} more)", cells.len() - 16);
            }
        }
        println!();
        println!("total candidate cells: {total_free}");
    }
}
