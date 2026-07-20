use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use solana_zk_sdk::encryption::{elgamal::ElGamalPubkey, pedersen::PedersenOpening};

use crate::models::{RistrettoVoteProof, RistrettoVoteSumProof};

// Helpers

fn point_from_bytes(bytes: &[u8], name: &str) -> Result<RistrettoPoint, String> {
    if bytes.len() != 32 {
        return Err(format!("{name} must have 32 bytes"));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);

    CompressedRistretto(array)
        .decompress()
        .ok_or_else(|| format!("{name} is not a valid Ristretto point"))
}

fn scalar_from_bytes(bytes: &[u8], name: &str) -> Result<Scalar, String> {
    if bytes.len() != 32 {
        return Err(format!("{name} must have 32 bytes"));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);

    let scalar = Scalar::from_canonical_bytes(array);

    if bool::from(scalar.is_some()) {
        Ok(scalar.unwrap())
    } else {
        Err(format!("{name} is not a canonical scalar"))
    }
}

fn split_ciphertext(ciphertext: &[u8; 64]) -> Result<(RistrettoPoint, RistrettoPoint), String> {
    let commitment = point_from_bytes(&ciphertext[0..32], "ciphertext commitment")?;
    let handle = point_from_bytes(&ciphertext[32..64], "ciphertext handle")?;

    Ok((commitment, handle))
}

fn derive_bases(
    public_key: &ElGamalPubkey,
) -> Result<(RistrettoPoint, RistrettoPoint, RistrettoPoint), String> {
    let zero_opening = PedersenOpening::new(Scalar::ZERO);
    let one_opening = PedersenOpening::new(Scalar::ONE);

    let enc_one_zero = public_key.encrypt_with_u64(1, &zero_opening).to_bytes();

    let enc_zero_one = public_key.encrypt_with_u64(0, &one_opening).to_bytes();

    let (g_base, _) = split_ciphertext(&enc_one_zero)?;
    let (h_base, public_key_point) = split_ciphertext(&enc_zero_one)?;

    Ok((g_base, h_base, public_key_point))
}

fn challenge_vote_proof(
    public_key: &ElGamalPubkey,
    ciphertext: &[u8; 64],
    a0: &RistrettoPoint,
    b0: &RistrettoPoint,
    a1: &RistrettoPoint,
    b1: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();

    hasher.update(b"kaonashi-vote-proof");
    hasher.update(public_key.to_bytes());
    hasher.update(ciphertext);
    hasher.update(a0.compress().as_bytes());
    hasher.update(b0.compress().as_bytes());
    hasher.update(a1.compress().as_bytes());
    hasher.update(b1.compress().as_bytes());

    let hash = hasher.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);

    Scalar::from_bytes_mod_order_wide(&wide)
}

fn challenge_sum_proof(
    public_key: &ElGamalPubkey,
    aggregate_commitment: &RistrettoPoint,
    aggregate_handle: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();

    hasher.update(b"kaonashi-vote-sum-proof");
    hasher.update(public_key.to_bytes());
    hasher.update(aggregate_commitment.compress().as_bytes());
    hasher.update(aggregate_handle.compress().as_bytes());
    hasher.update(a.compress().as_bytes());
    hasher.update(b.compress().as_bytes());

    let hash = hasher.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);

    Scalar::from_bytes_mod_order_wide(&wide)
}

// Verify one VoteProof

pub fn verify_vote_proof(
    public_key: &ElGamalPubkey,
    ciphertext: &[u8; 64],
    proof: &RistrettoVoteProof,
) -> Result<(), String> {
    let (g_base, h_base, public_key_point) = derive_bases(public_key)?;
    let (commitment, handle) = split_ciphertext(ciphertext)?;

    let a0 = point_from_bytes(&proof.a0, "a0")?;
    let b0 = point_from_bytes(&proof.b0, "b0")?;
    let c0 = scalar_from_bytes(&proof.c0, "c0")?;
    let s0 = scalar_from_bytes(&proof.s0, "s0")?;

    let a1 = point_from_bytes(&proof.a1, "a1")?;
    let b1 = point_from_bytes(&proof.b1, "b1")?;
    let c1 = scalar_from_bytes(&proof.c1, "c1")?;
    let s1 = scalar_from_bytes(&proof.s1, "s1")?;

    let challenge = challenge_vote_proof(public_key, ciphertext, &a0, &b0, &a1, &b1);

    if c0 + c1 != challenge {
        return Err("VoteProof challenge check failed".to_string());
    }

    let commitment_minus_0 = commitment;
    let commitment_minus_1 = commitment - g_base;

    let check_0_a = h_base * s0 == a0 + commitment_minus_0 * c0;
    let check_0_b = public_key_point * s0 == b0 + handle * c0;

    let check_1_a = h_base * s1 == a1 + commitment_minus_1 * c1;
    let check_1_b = public_key_point * s1 == b1 + handle * c1;

    if !check_0_a || !check_0_b || !check_1_a || !check_1_b {
        return Err("VoteProof equation check failed".to_string());
    }

    Ok(())
}

// Verify VoteSumProof

pub fn verify_vote_sum_proof(
    public_key: &ElGamalPubkey,
    encrypted_vote: &[[u8; 64]],
    proof: &RistrettoVoteSumProof,
) -> Result<(), String> {
    if encrypted_vote.is_empty() {
        return Err("Cannot verify VoteSumProof for empty encrypted vote".to_string());
    }

    let (g_base, h_base, public_key_point) = derive_bases(public_key)?;

    let mut aggregate_commitment: Option<RistrettoPoint> = None;
    let mut aggregate_handle: Option<RistrettoPoint> = None;

    for ciphertext in encrypted_vote {
        let (commitment, handle) = split_ciphertext(ciphertext)?;

        aggregate_commitment = Some(match aggregate_commitment {
            Some(current) => current + commitment,
            None => commitment,
        });

        aggregate_handle = Some(match aggregate_handle {
            Some(current) => current + handle,
            None => handle,
        });
    }

    let aggregate_commitment =
        aggregate_commitment.ok_or_else(|| "Missing aggregate commitment".to_string())?;

    let aggregate_handle =
        aggregate_handle.ok_or_else(|| "Missing aggregate handle".to_string())?;

    let a = point_from_bytes(&proof.a, "sum proof a")?;
    let b = point_from_bytes(&proof.b, "sum proof b")?;
    let c = scalar_from_bytes(&proof.c, "sum proof c")?;
    let s = scalar_from_bytes(&proof.s, "sum proof s")?;

    let expected_c =
        challenge_sum_proof(public_key, &aggregate_commitment, &aggregate_handle, &a, &b);

    if c != expected_c {
        return Err("VoteSumProof challenge check failed".to_string());
    }

    let commitment_minus_one = aggregate_commitment - g_base;

    let check_a = h_base * s == a + commitment_minus_one * c;
    let check_b = public_key_point * s == b + aggregate_handle * c;

    if !check_a || !check_b {
        return Err("VoteSumProof equation check failed".to_string());
    }

    Ok(())
}

// Verify full encrypted vote

pub fn verify_encrypted_vote_proofs(
    public_key: &ElGamalPubkey,
    encrypted_vote: &[[u8; 64]],
    vote_proofs: &[RistrettoVoteProof],
    vote_sum_proof: &RistrettoVoteSumProof,
) -> Result<(), String> {
    if encrypted_vote.len() != vote_proofs.len() {
        return Err(format!(
            "Expected {} vote proofs, got {}",
            encrypted_vote.len(),
            vote_proofs.len()
        ));
    }

    for (index, (ciphertext, proof)) in encrypted_vote.iter().zip(vote_proofs.iter()).enumerate() {
        verify_vote_proof(public_key, ciphertext, proof)
            .map_err(|error| format!("VoteProof failed at index {index}: {error}"))?;
    }

    verify_vote_sum_proof(public_key, encrypted_vote, vote_sum_proof)?;

    Ok(())
}
