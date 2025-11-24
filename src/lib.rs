use blake3::Hasher;
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;

/// 128-bit symmetric key for a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Label(pub [u8; 16]);

impl Label {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        Label(b)
    }
}

/// KDF from single label + tag
fn kdf1(label: &Label, tag: u64) -> [u8; 16] {
    let mut hasher = Hasher::new();
    hasher.update(&label.0);
    hasher.update(&tag.to_le_bytes());
    let hash = hasher.finalize();
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash.as_bytes()[0..16]);
    result
}

/// KDF from one or two labels + domain separator
fn kdf2(a: &Label, b: &Label, tag: u64) -> [u8;16] {
    use blake3::Hasher;
    let mut h = Hasher::new();
    h.update(&a.0);
    h.update(&b.0);
    h.update(&tag.to_le_bytes()); // domain separation
    let out = h.finalize();
    let mut r = [0u8;16];
    r.copy_from_slice(&out.as_bytes()[0..16]);
    r
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Garbled wire: two labels
#[derive(Clone, Debug)]
pub struct GarbledWire {
    pub l0: Label,
    pub l1: Label,
}

impl GarbledWire {
    pub fn new() -> Self { GarbledWire { l0: Label::random(), l1: Label::random() } }
}

/// 4-row AND garbled table (rows in canonical order (00,01,10,11))
#[derive(Clone, Debug)]
pub struct AndTable {
    pub gid: u64,
    pub rows: [[u8;16]; 4],
}

impl AndTable {
    pub fn new(gid: u64, a: &GarbledWire, b: &GarbledWire, out: &GarbledWire) -> Self {
        let mut rows = [[0u8;16];4];
        // row 00 -> out.l0
        let m00 = kdf2(&a.l0, &b.l0, gid);
        rows[0] = xor16(&out.l0.0, &m00);
        // row 01 -> out.l0
        let m01 = kdf2(&a.l0, &b.l1, gid);
        rows[1] = xor16(&out.l0.0, &m01);
        // row 10 -> out.l0
        let m10 = kdf2(&a.l1, &b.l0, gid);
        rows[2] = xor16(&out.l0.0, &m10);
        // row 11 -> out.l1
        let m11 = kdf2(&a.l1, &b.l1, gid);
        rows[3] = xor16(&out.l1.0, &m11);

        Self { gid, rows }
    }

    /// evaluator chooses row index via known bits (alpha,beta)
    pub fn eval_with_index(&self, a_lbl: &Label, b_lbl: &Label, alpha: u8, beta: u8) -> Label {
        let idx = (alpha as usize) * 2 + (beta as usize);
        let mask = kdf2(a_lbl, b_lbl, self.gid);
        let mut out = [0u8;16];
        for i in 0..16 { out[i] = self.rows[idx][i] ^ mask[i]; }
        Label(out)
    }

    /// evaluator doesn't want to use index (try all rows)
    pub fn eval_without_index(&self, a_lbl: &Label, b_lbl: &Label) -> Vec<Label> {
        let mut res = Vec::with_capacity(4);
        let mask = kdf2(a_lbl, b_lbl, self.gid);
        for idx in 0..4 {
            let mut out = [0u8;16];
            for i in 0..16 { out[i] = self.rows[idx][i] ^ mask[i]; }
            res.push(Label(out));
        }
        res
    }
}

/// Simple single-gate identity output circuits (e.g., output = 4)
#[derive(Clone, Debug)]
pub struct IdentityTable {
    pub gid: u64,
    pub ct0: [u8;16],
    pub ct1: [u8;16],
}

impl IdentityTable {
    pub fn new(gid: u64, inp: &GarbledWire, out: &GarbledWire) -> Self {
        let pad0 = kdf1(&inp.l0, gid);
        let pad1 = kdf1(&inp.l1, gid);
        let ct0 = xor16(&out.l0.0, &pad0);
        let ct1 = xor16(&out.l1.0, &pad1);
        Self { gid, ct0, ct1 }
    }

    pub fn eval(&self, in_lbl: &Label) -> GarbledWire {
        let pad = kdf1(in_lbl, self.gid);

        let mut cand0 = [0u8;16];
        for i in 0..16 { cand0[i] = self.ct0[i] ^ pad[i]; }
        
        let mut cand1 = [0u8;16];
        for i in 0..16 { cand1[i] = self.ct1[i] ^ pad[i]; }
        
        GarbledWire{l0: Label(cand0), l1:Label(cand1)}
    }
}

/// Encoded garbled circuit (simple list of wires, one AND table)
#[derive(Clone, Debug)]
pub struct GarbledCircuit {
    pub wires: Vec<GarbledWire>,          // all wires
    pub and_tables: Vec<(usize, usize, usize, AndTable)>, // (a_idx,b_idx,out_idx, table)
    //pub id_tables: Vec<(usize, usize, IdentityTable)>, // input->output identity tables
    pub output_map: HashMap<Label,bool>,  // mapping of output label -> bit
}

impl GarbledCircuit {
    pub fn new_empty() -> Self {
        Self { wires: Vec::new(), and_tables: Vec::new(), output_map: HashMap::new() }
    }
}

/// Garbler: constructs garbled circuit
pub struct Garbler {}

impl Garbler {
    pub fn garble_and_build_example() -> (GarbledCircuit, usize, usize, usize) {
        // Build small circuit: O = A AND B
        // wires[0] = A, wires[1] = B, wires[2] = O
        let mut gc = GarbledCircuit::new_empty();
        let wa = GarbledWire::new();
        let wb = GarbledWire::new();
        let wo = GarbledWire::new();

        let a_idx = gc.wires.len(); gc.wires.push(wa);
        let b_idx = gc.wires.len(); gc.wires.push(wb);
        let o_idx = gc.wires.len(); gc.wires.push(wo);

        let gid = 1u64;
        let at = AndTable::new(gid, &gc.wires[a_idx], &gc.wires[b_idx], &gc.wires[o_idx]);
        gc.and_tables.push((a_idx,b_idx,o_idx,at));

        // register output map for decoder
        gc.output_map.insert(gc.wires[o_idx].l0, false);
        gc.output_map.insert(gc.wires[o_idx].l1, true);

        (gc, a_idx, b_idx, o_idx)
    }
}

/// Evaluator: receives garbled circuit and input labels, evaluates
pub struct Evaluator {}

impl Evaluator {
    /// Evaluate the single AND circuit, given labels for input wires and their clear bits.
    pub fn eval_and(gc: &GarbledCircuit, a_lbl: Label, b_lbl: Label, a_bit: u8, b_bit: u8) -> bool {
        // find the single and table
        assert_eq!(gc.and_tables.len(), 1, "example expects one AND");
        let (_a_idx, _b_idx, _out_idx, table) = &gc.and_tables[0];

        // compute output label
        let out_lbl = table.eval_with_index(&a_lbl, &b_lbl, a_bit, b_bit);

        // decode via output_map
        if let Some(v) = gc.output_map.get(&out_lbl) {
            *v
        } else {
            panic!("output label not recognized");
        }
    }
}