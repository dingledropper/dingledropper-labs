//! Orchard Action circuit — full-circuit under-constrained-cell detector (Lane-1).
//!
//! WHAT IT DOES
//!   Drives the real `orchard::circuit::Circuit` through `Circuit::configure` +
//!   `FloorPlanner::synthesize` with a custom `Assignment` that records EVERY
//!   advice assignment, copy (equality) constraint, fixed assignment, and
//!   selector enable — tagged by region/namespace. Then:
//!     1. union-finds the copy graph,
//!     2. marks every component that touches a Fixed or Instance cell as ANCHORED
//!        (a "trusted source": circuit constant or public input),
//!     3. walks every custom gate's polynomial to learn which advice COLUMNS each
//!        gate constrains,
//!     4. flags advice cells that are assigned + referenced by a gate + NOT in an
//!        anchored component (i.e. never equality-bound, directly or transitively,
//!        to a constant/instance) — the exact shape of the Hornby unanchored-base
//!        bug, generalized to the whole circuit.
//!   Output is grouped by region so you can zoom to note_commit / commit_ivk /
//!   scalar-fixed-short (the canonicity/decomposition surface Lane-2 didn't cover).
//!
//!   This is a TRIAGE tool: it produces candidates. Confirm any candidate with a
//!   two-witness MockProver (see CONFIRM section in README) before believing it.
//!
//! RUN (on M4):  cargo run --release
//!   audit the historical insecure circuit instead:  cargo run --release --features insecure
//!
//! NOTE: pinned to halo2_proofs 0.3 (zcash). The 3 spots most likely to need a
//! one-line tweak for your exact lockfile are marked `// TWEAK:`.

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

/// A cell identity: which kind of column, its index, and the row.
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
    // namespace / region stack -> human-readable path for tagging cells
    ns: Vec<String>,
    region: Vec<String>,
    // advice cell -> region path where it was assigned
    advice_region: HashMap<Cell, String>,
    // all advice cells assigned
    advice_cells: BTreeSet<Cell>,
    // copy (equality) constraints
    copies: Vec<(Cell, Cell)>,
    // fixed / instance cells that ever appear (trusted sources)
    fixed_cells: BTreeSet<Cell>,
    instance_cells: BTreeSet<Cell>,
    // selector enables: (debug(selector), row)
    selector_rows: Vec<(String, usize)>,
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

    fn enable_selector<A, AR>(&mut self, annotation: A, selector: &Selector, row: usize) -> Result<(), Error>
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        let _ = annotation;
        self.selector_rows.push((format!("{:?}", selector), row));
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
        // TWEAK: if your halo2_proofs assign_advice has a different generic shape
        // (newer versions take `Value<VR>` directly, not a closure), adjust here.
        let cell = Cell { kind: Kind::Advice, col: column.index(), row };
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
        self.fixed_cells.insert(Cell { kind: Kind::Fixed, col: column.index(), row });
        Ok(())
    }

    fn copy(
        &mut self,
        l: Column<Any>,
        l_row: usize,
        r: Column<Any>,
        r_row: usize,
    ) -> Result<(), Error> {
        let lc = Cell { kind: kind_of(&l), col: l.index(), row: l_row };
        let rc = Cell { kind: kind_of(&r), col: r.index(), row: r_row };
        if lc.kind == Kind::Fixed { self.fixed_cells.insert(lc); }
        if rc.kind == Kind::Fixed { self.fixed_cells.insert(rc); }
        if lc.kind == Kind::Instance { self.instance_cells.insert(lc); }
        if rc.kind == Kind::Instance { self.instance_cells.insert(rc); }
        self.copies.push((lc, rc));
        Ok(())
    }

    fn fill_from_row(&mut self, _: Column<Fixed>, _: usize, _: Value<Assigned<F>>) -> Result<(), Error> {
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

    fn annotate_column<A, AR>(&mut self, _: A, _: Column<Any>)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
    }
    // TWEAK: some halo2_proofs versions also require `fn get_challenge(&self, _) -> Value<F>`.
}

// ---- union-find over copied cells -------------------------------------------

struct Uf {
    parent: HashMap<Cell, Cell>,
}
impl Uf {
    fn new() -> Self { Self { parent: HashMap::new() } }
    fn find(&mut self, x: Cell) -> Cell {
        let p = *self.parent.entry(x).or_insert(x);
        if p == x { x } else { let r = self.find(p); self.parent.insert(x, r); r }
    }
    fn union(&mut self, a: Cell, b: Cell) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb { self.parent.insert(ra, rb); }
    }
}

// ---- gate polynomial walk: which advice columns does each gate constrain -----

fn collect_advice_cols(e: &Expression<F>, out: &mut BTreeSet<usize>) {
    match e {
        Expression::Advice(q) => { out.insert(q.column_index()); }
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
        cs.constants().clone(), // TWEAK: older API: `cs.constants.clone()`
    )
    .expect("synthesize");

    // 3. anchor analysis
    let mut uf = Uf::new();
    for (a, b) in &rec.copies {
        uf.union(*a, *b);
    }
    // a component is ANCHORED if any of its members is a Fixed or Instance cell
    let mut anchored_roots: BTreeSet<Cell> = BTreeSet::new();
    for c in rec.fixed_cells.iter().chain(rec.instance_cells.iter()) {
        let r = uf.find(*c);
        anchored_roots.insert(r);
    }
    let is_anchored = |uf: &mut Uf, c: Cell| anchored_roots.contains(&uf.find(c));

    // advice columns constrained by at least one custom gate
    let mut gate_cols: BTreeSet<usize> = BTreeSet::new();
    let mut gate_report: Vec<(String, BTreeSet<usize>)> = Vec::new();
    for gate in cs.gates() {
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
    let mut uf2 = uf; // move
    for c in cells {
        if !gate_cols.contains(&c.col) {
            continue; // column never appears in any custom gate -> not a constraint cell
        }
        if !is_anchored(&mut uf2, c) {
            let region = rec.advice_region.get(&c).cloned().unwrap_or_else(|| "?".into());
            free_by_region.entry(region).or_default().push(c);
            total_free += 1;
        }
    }

    // ---- report ----
    let variant = if cfg!(feature = "insecure") { "InsecurePreNu6_2" } else { "FixedPostNu6_2 (default)" };
    println!("== Orchard Action circuit under-constrained scan ==");
    println!("circuit variant : {variant}");
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
    println!("   (review these; confirm with a two-witness MockProver before believing)");
    if total_free == 0 {
        println!("   NONE. Every gate-constrained advice cell is transitively bound to a");
        println!("   trusted source. (Clean negative for this bug class — same disposition");
        println!("   as Lane-2, now extended to the full circuit.)");
    } else {
        for (region, cells) in &free_by_region {
            // prioritise the canonicity/decomposition regions
            let hot = ["note_commit", "commit", "ivk", "short", "canon", "decompos", "sinsemilla", "nullifier"]
                .iter()
                .any(|k| region.to_lowercase().contains(k));
            let mark = if hot { "  <<< HOT" } else { "" };
            println!("  region: {region}  ({} cells){mark}", cells.len());
            for c in cells.iter().take(12) {
                println!("      advice col {} row {}", c.col, c.row);
            }
            if cells.len() > 12 {
                println!("      ... (+{} more)", cells.len() - 12);
            }
        }
        println!();
        println!("total candidate cells: {total_free}");
    }
}
