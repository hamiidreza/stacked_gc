use rand::RngCore;
use rand::rngs::OsRng;

pub struct Label(pub [u8; 16]);

pub fn random_label() -> Label {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    Label(bytes)
}

