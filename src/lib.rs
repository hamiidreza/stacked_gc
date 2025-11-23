use blake3::Hasher;
use rand::RngCore;
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct Label(pub [u8; 16]);

pub fn random_label() -> Label {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    Label(bytes)
}

fn kdf(label: &Label) -> [u8; 16] {
    let mut hasher = Hasher::new();
    hasher.update(&label.0);
    let hash = hasher.finalize();
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash.as_bytes()[0..16]);
    result
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

pub struct GarbledWire {
    pub label0: Label,
    pub label1: Label,
}

pub struct IdentityGateGarbled {
    pub ct0: [u8; 16],
    pub ct1: [u8; 16],
    pub output_wire: GarbledWire,
}

pub struct GarbledCircuitSingleIdentity {
    pub input_wire: GarbledWire,
    pub gate: IdentityGateGarbled,
}

impl GarbledWire {
    pub fn new_random() -> Self {
        Self {
            label0: random_label(),
            label1: random_label(),
        }
    }
}

impl GarbledCircuitSingleIdentity {
    pub fn new() -> Self {
        let input_wire = GarbledWire::new_random();
        let output_wire = GarbledWire::new_random();

        let pad0 = kdf(&input_wire.label0);
        let pad1 = kdf(&input_wire.label1);

        let ct0 = xor16(&pad0, &output_wire.label0.0);
        let ct1 = xor16(&pad1, &output_wire.label1.0);

        Self {
            input_wire: input_wire,
            gate: IdentityGateGarbled {
                ct0,
                ct1,
                output_wire,
            },
        }
    }
}
