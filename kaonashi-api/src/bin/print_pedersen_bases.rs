use curve25519_dalek::scalar::Scalar;

use solana_zk_sdk::encryption::{elgamal::ElGamalKeypair, pedersen::PedersenOpening};

fn main() {
    // A chave concreta não altera G nem H.
    let keypair = ElGamalKeypair::new_rand();
    let public_key = keypair.pubkey();

    let zero_opening = PedersenOpening::new(Scalar::ZERO);
    let one_opening = PedersenOpening::new(Scalar::ONE);

    // E(1, 0):
    // commitment = G
    let encrypted_one_zero = public_key.encrypt_with_u64(1, &zero_opening).to_bytes();

    // E(0, 1):
    // commitment = H
    // handle = public key point
    let encrypted_zero_one = public_key.encrypt_with_u64(0, &one_opening).to_bytes();

    let mut g = [0u8; 32];
    g.copy_from_slice(&encrypted_one_zero[0..32]);

    let mut h = [0u8; 32];
    h.copy_from_slice(&encrypted_zero_one[0..32]);

    println!("G_BYTES: {:?}", g);
    println!("H_BYTES: {:?}", h);

    println!("G_HEX: {}", to_hex(&g));
    println!("H_HEX: {}", to_hex(&h));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
