use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

use sha2::{Digest, Sha512};

use crate::{VoteProof, VoteSumProof};

type ProofResult<T> = core::result::Result<T, String>;

// ============================================================================
// Solana ZK SDK Pedersen generators
// ============================================================================

const G_BYTES: [u8; 32] = [
    226, 242, 174, 10, 106, 188, 78, 113, 168, 132, 169, 97, 197, 0, 81, 95, 88, 227, 11, 106, 165,
    130, 221, 141, 182, 166, 89, 69, 224, 141, 45, 118,
];

const H_BYTES: [u8; 32] = [
    140, 146, 64, 180, 86, 169, 230, 220, 101, 195, 119, 161, 4, 141, 116, 95, 148, 160, 140, 219,
    127, 68, 203, 205, 123, 70, 243, 64, 72, 135, 17, 52,
];
// ============================================================================
// Helpers
// ============================================================================

fn point_from_array(bytes: &[u8; 32], name: &str) -> ProofResult<RistrettoPoint> {
    CompressedRistretto(*bytes)
        .decompress()
        .ok_or_else(|| format!("{name} is not a valid Ristretto point"))
}

fn point_from_slice(bytes: &[u8], name: &str) -> ProofResult<RistrettoPoint> {
    if bytes.len() != 32 {
        return Err(format!("{name} must have 32 bytes, got {}", bytes.len()));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);

    point_from_array(&array, name)
}

fn scalar_from_array(bytes: &[u8; 32], name: &str) -> ProofResult<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or_else(|| format!("{name} is not a canonical scalar"))
}

fn split_ciphertext(ciphertext: &[u8; 64]) -> ProofResult<(RistrettoPoint, RistrettoPoint)> {
    let commitment = point_from_slice(&ciphertext[0..32], "ciphertext commitment")?;

    let handle = point_from_slice(&ciphertext[32..64], "ciphertext handle")?;

    Ok((commitment, handle))
}

fn derive_bases(
    public_key: &[u8; 32],
) -> ProofResult<(RistrettoPoint, RistrettoPoint, RistrettoPoint)> {
    if G_BYTES == [0u8; 32] {
        return Err("G_BYTES has not been configured with the Solana SDK generator".to_string());
    }

    if H_BYTES == [0u8; 32] {
        return Err("H_BYTES has not been configured with the Solana SDK generator".to_string());
    }

    let g_base = CompressedRistretto(G_BYTES)
        .decompress()
        .ok_or_else(|| "The configured G_BYTES value is not a valid Ristretto point".to_string())?;

    let h_base = CompressedRistretto(H_BYTES)
        .decompress()
        .ok_or_else(|| "The configured H_BYTES value is not a valid Ristretto point".to_string())?;

    let public_key_point = point_from_array(public_key, "ElGamal public key")?;

    Ok((g_base, h_base, public_key_point))
}

// ============================================================================
// Fiat–Shamir challenges
// ============================================================================

fn challenge_vote_proof(
    public_key: &[u8; 32],
    ciphertext: &[u8; 64],
    a0: &RistrettoPoint,
    b0: &RistrettoPoint,
    a1: &RistrettoPoint,
    b1: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();

    hasher.update(b"kaonashi-vote-proof");
    hasher.update(public_key);
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
    public_key: &[u8; 32],
    aggregate_commitment: &RistrettoPoint,
    aggregate_handle: &RistrettoPoint,
    a: &RistrettoPoint,
    b: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();

    hasher.update(b"kaonashi-vote-sum-proof");
    hasher.update(public_key);

    hasher.update(aggregate_commitment.compress().as_bytes());

    hasher.update(aggregate_handle.compress().as_bytes());

    hasher.update(a.compress().as_bytes());
    hasher.update(b.compress().as_bytes());

    let hash = hasher.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);

    Scalar::from_bytes_mod_order_wide(&wide)
}

// ============================================================================
// VoteProof verification
// ============================================================================

pub fn verify_vote_proof(
    public_key: &[u8; 32],
    ciphertext: &[u8; 64],
    proof: &VoteProof,
) -> ProofResult<()> {
    let (g_base, h_base, public_key_point) = derive_bases(public_key)?;

    let (commitment, handle) = split_ciphertext(ciphertext)?;

    let a0 = point_from_array(&proof.a0, "VoteProof a0")?;

    let b0 = point_from_array(&proof.b0, "VoteProof b0")?;

    let c0 = scalar_from_array(&proof.c0, "VoteProof c0")?;

    let s0 = scalar_from_array(&proof.s0, "VoteProof s0")?;

    let a1 = point_from_array(&proof.a1, "VoteProof a1")?;

    let b1 = point_from_array(&proof.b1, "VoteProof b1")?;

    let c1 = scalar_from_array(&proof.c1, "VoteProof c1")?;

    let s1 = scalar_from_array(&proof.s1, "VoteProof s1")?;

    let expected_challenge = challenge_vote_proof(public_key, ciphertext, &a0, &b0, &a1, &b1);

    if c0 + c1 != expected_challenge {
        return Err("VoteProof challenge check failed".to_string());
    }

    // Branch 0:
    //
    // commitment = 0G + rH
    // handle = rP

    let check_zero_commitment = h_base * s0 == a0 + commitment * c0;

    let check_zero_handle = public_key_point * s0 == b0 + handle * c0;

    // Branch 1:
    //
    // commitment = G + rH
    // handle = rP

    let commitment_minus_one = commitment - g_base;

    let check_one_commitment = h_base * s1 == a1 + commitment_minus_one * c1;

    let check_one_handle = public_key_point * s1 == b1 + handle * c1;

    if !check_zero_commitment {
        return Err("VoteProof branch 0 commitment equation failed".to_string());
    }

    if !check_zero_handle {
        return Err("VoteProof branch 0 handle equation failed".to_string());
    }

    if !check_one_commitment {
        return Err("VoteProof branch 1 commitment equation failed".to_string());
    }

    if !check_one_handle {
        return Err("VoteProof branch 1 handle equation failed".to_string());
    }

    Ok(())
}

// ============================================================================
// VoteSumProof verification
// ============================================================================

pub fn verify_vote_sum_proof(
    public_key: &[u8; 32],
    encrypted_vote: &[[u8; 64]],
    proof: &VoteSumProof,
) -> ProofResult<()> {
    if encrypted_vote.is_empty() {
        return Err("Cannot verify VoteSumProof for an empty encrypted vote".to_string());
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

    let a = point_from_array(&proof.a, "VoteSumProof a")?;

    let b = point_from_array(&proof.b, "VoteSumProof b")?;

    let c = scalar_from_array(&proof.c, "VoteSumProof c")?;

    let s = scalar_from_array(&proof.s, "VoteSumProof s")?;

    let expected_challenge =
        challenge_sum_proof(public_key, &aggregate_commitment, &aggregate_handle, &a, &b);

    if c != expected_challenge {
        return Err("VoteSumProof challenge check failed".to_string());
    }

    // A soma dos ciphertexts deve cifrar exatamente 1:
    //
    // aggregate_commitment = G + r_total H
    // aggregate_handle = r_total P

    let commitment_minus_one = aggregate_commitment - g_base;

    let check_commitment = h_base * s == a + commitment_minus_one * c;

    let check_handle = public_key_point * s == b + aggregate_handle * c;

    if !check_commitment {
        return Err("VoteSumProof commitment equation failed".to_string());
    }

    if !check_handle {
        return Err("VoteSumProof handle equation failed".to_string());
    }

    Ok(())
}

// ============================================================================
// Full encrypted vote verification
// ============================================================================

pub fn verify_encrypted_vote_proofs(
    public_key: &[u8; 32],
    encrypted_vote: &[[u8; 64]],
    vote_proofs: &[VoteProof],
    vote_sum_proof: &VoteSumProof,
) -> ProofResult<()> {
    if encrypted_vote.is_empty() {
        return Err("Encrypted vote cannot be empty".to_string());
    }

    if encrypted_vote.len() != vote_proofs.len() {
        return Err(format!(
            "Expected {} vote proofs, got {}",
            encrypted_vote.len(),
            vote_proofs.len(),
        ));
    }

    for (index, (ciphertext, proof)) in encrypted_vote.iter().zip(vote_proofs.iter()).enumerate() {
        verify_vote_proof(public_key, ciphertext, proof).map_err(|verification_error| {
            format!(
                "VoteProof failed at index {index}: \
                 {verification_error}"
            )
        })?;
    }

    verify_vote_sum_proof(public_key, encrypted_vote, vote_sum_proof)
        .map_err(|verification_error| format!("VoteSumProof failed: {verification_error}"))?;

    Ok(())
}
