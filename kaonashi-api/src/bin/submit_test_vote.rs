use anyhow::{Context, Result};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use solana_sdk::signature::{Keypair, Signer};
use solana_zk_sdk::encryption::{elgamal::ElGamalPubkey, pedersen::PedersenOpening};
use std::{env, fs};

const API_BASE_URL: &str = "http://127.0.0.1:3000";
const WALLETS_FILE: &str = "test-wallets/wallets.json";

#[derive(Debug, Deserialize)]
struct WalletRecord {
    wallet_id: String,
    public_key: String,
    keypair_64_file: String,
}

#[derive(Debug, Deserialize)]
struct ElGamalPublicKeyResponse {
    public_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RistrettoVoteProof {
    a0: Vec<u8>,
    b0: Vec<u8>,
    c0: Vec<u8>,
    s0: Vec<u8>,
    a1: Vec<u8>,
    b1: Vec<u8>,
    c1: Vec<u8>,
    s1: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RistrettoVoteSumProof {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    s: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct SubmitVoteRequest {
    wallet_id: String,
    public_key: String,
    decade_id: u8,
    encrypted_vote: Vec<Vec<u8>>,
    encrypted_vote_hash: String,
    vote_proofs: Vec<RistrettoVoteProof>,
    vote_sum_proof: RistrettoVoteSumProof,
    message: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct SubmitVoteResponse {
    accepted: bool,
    pending_votes: usize,
    batch_submitted: bool,
    status: String,
}

#[derive(Debug, Serialize)]
struct AdminActionRequest {
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct ResolveTieRequest {
    public_key: String,
    message: String,
    signature: String,
    decade_id: u8,
    winner_index: usize,
}

fn main() -> Result<()> {
    let decade_id = env::args()
        .nth(1)
        .unwrap_or_else(|| "2".to_string())
        .parse::<u8>()
        .context("Usage: cargo run --bin submit_test_vote -- <decade_id>")?;

    let chairperson_secret_key =
        env::var("CHAIRPERSON_SECRET_KEY").context("Missing CHAIRPERSON_SECRET_KEY")?;

    let chairperson_public_key = env::var("CHAIRPERSON_PUBLIC_KEY").unwrap_or_else(|_| {
        keypair_from_secret(&chairperson_secret_key)
            .expect("Invalid chairperson secret key")
            .pubkey()
            .to_string()
    });

    let client = Client::new();

    println!("Starting Kaonashi Scales Up test");
    println!("Decade id: {decade_id}");
    println!("Chairperson: {chairperson_public_key}");

    create_ballots(&client, &chairperson_public_key, &chairperson_secret_key)?;

    let wallets_json = fs::read_to_string(WALLETS_FILE)
        .with_context(|| format!("Failed to read {WALLETS_FILE}"))?;

    let wallets: Vec<WalletRecord> = serde_json::from_str(&wallets_json)?;

    if wallets.len() < 10 {
        anyhow::bail!("This test needs at least 10 wallets");
    }

    let public_key = get_elgamal_public_key(&client, decade_id)?;

    // 10 votes with a tie:
    // movie 0 -> 3 votes
    // movie 1 -> 3 votes
    // movie 2 -> 2 votes
    // movie 3 -> 2 votes
    let planned_votes = [0usize, 1, 0, 1, 2, 3, 0, 1, 2, 3];

    println!("\nSubmitting 10 encrypted votes");
    println!("Expected tie: movie 0 = 3 votes, movie 1 = 3 votes");

    for (index, movie_index) in planned_votes.iter().enumerate() {
        let wallet = &wallets[index];

        let response = submit_one_vote(&client, wallet, &public_key, decade_id, *movie_index)?;

        println!(
            "Vote {} -> {} voted for movie {} | accepted={}, pending_votes={}, batch_submitted={}, status={}",
            index + 1,
            wallet.wallet_id,
            movie_index,
            response.accepted,
            response.pending_votes,
            response.batch_submitted,
            response.status
        );
    }

    println!("\nExpected result before tie resolution:");
    println!("movie 0 -> 3 votes");
    println!("movie 1 -> 3 votes");
    println!("movie 2 -> 2 votes");
    println!("movie 3 -> 2 votes");

    close_election(&client, &chairperson_public_key, &chairperson_secret_key)?;

    flush_batch(
        &client,
        &chairperson_public_key,
        &chairperson_secret_key,
        decade_id,
    )?;

    finalize_election(&client, &chairperson_public_key, &chairperson_secret_key)?;

    get_results(&client, decade_id)?;

    // Tie resolution: chairperson chooses movie 1.
    resolve_tie(
        &client,
        &chairperson_public_key,
        &chairperson_secret_key,
        decade_id,
        1,
    )?;

    finalize_election(&client, &chairperson_public_key, &chairperson_secret_key)?;

    get_results(&client, decade_id)?;

    println!("\nKaonashi Scales Up test completed");
    println!("Final winner selected by chairperson: movie 1");

    Ok(())
}

fn keypair_from_secret(secret_key: &str) -> Result<Keypair> {
    let keypair_bytes = bs58::decode(secret_key.trim()).into_vec()?;

    Keypair::try_from(keypair_bytes.as_slice())
        .map_err(|error| anyhow::anyhow!("Invalid chairperson keypair: {error}"))
}

fn create_admin_message(public_key: &str, action: &str, decade_id: Option<u8>) -> String {
    match decade_id {
        Some(decade_id) => format!(
            "Kaonashi admin action\npublic_key: {}\naction: {}\ndecade_id: {}",
            public_key, action, decade_id
        ),
        None => format!(
            "Kaonashi admin action\npublic_key: {}\naction: {}",
            public_key, action
        ),
    }
}

fn create_signed_admin_request(
    public_key: &str,
    secret_key: &str,
    action: &str,
    decade_id: Option<u8>,
) -> Result<AdminActionRequest> {
    let message = create_admin_message(public_key, action, decade_id);

    let keypair = keypair_from_secret(secret_key)?;
    let signature = keypair.sign_message(message.as_bytes()).to_string();

    Ok(AdminActionRequest {
        public_key: public_key.to_string(),
        message,
        signature,
    })
}

fn post_admin(
    client: &Client,
    endpoint: &str,
    body: &AdminActionRequest,
    label: &str,
) -> Result<()> {
    let response = client
        .post(format!("{API_BASE_URL}{endpoint}"))
        .json(body)
        .send()?
        .error_for_status()?;

    let text = response.text().unwrap_or_default();

    println!("\n{label} completed");

    if !text.trim().is_empty() {
        println!("{text}");
    }

    Ok(())
}

fn get_api(client: &Client, endpoint: &str, label: &str) -> Result<()> {
    let response = client
        .get(format!("{API_BASE_URL}{endpoint}"))
        .send()?
        .error_for_status()?;

    let text = response.text().unwrap_or_default();

    println!("\n{label}:");

    if !text.trim().is_empty() {
        println!("{text}");
    }

    Ok(())
}

fn create_ballots(
    client: &Client,
    chairperson_public_key: &str,
    chairperson_secret_key: &str,
) -> Result<()> {
    let body = create_signed_admin_request(
        chairperson_public_key,
        chairperson_secret_key,
        "create_ballots",
        None,
    )?;

    post_admin(client, "/api/admin/create-ballots", &body, "Create ballots")
}

fn close_election(
    client: &Client,
    chairperson_public_key: &str,
    chairperson_secret_key: &str,
) -> Result<()> {
    let body = create_signed_admin_request(
        chairperson_public_key,
        chairperson_secret_key,
        "close_election",
        None,
    )?;

    post_admin(client, "/api/admin/close-election", &body, "Close election")
}

fn flush_batch(
    client: &Client,
    chairperson_public_key: &str,
    chairperson_secret_key: &str,
    decade_id: u8,
) -> Result<()> {
    let body = create_signed_admin_request(
        chairperson_public_key,
        chairperson_secret_key,
        "flush_batch",
        Some(decade_id),
    )?;

    post_admin(
        client,
        &format!("/api/admin/flush-batch/{decade_id}"),
        &body,
        "Flush batch",
    )
}

fn finalize_election(
    client: &Client,
    chairperson_public_key: &str,
    chairperson_secret_key: &str,
) -> Result<()> {
    let body = create_signed_admin_request(
        chairperson_public_key,
        chairperson_secret_key,
        "finalize_election",
        None,
    )?;

    post_admin(
        client,
        "/api/admin/finalize-election",
        &body,
        "Finalize election",
    )
}

fn resolve_tie(
    client: &Client,
    chairperson_public_key: &str,
    chairperson_secret_key: &str,
    decade_id: u8,
    winner_index: usize,
) -> Result<()> {
    let admin_request = create_signed_admin_request(
        chairperson_public_key,
        chairperson_secret_key,
        "resolve_tie",
        Some(decade_id),
    )?;

    let body = ResolveTieRequest {
        public_key: admin_request.public_key,
        message: admin_request.message,
        signature: admin_request.signature,
        decade_id,
        winner_index,
    };

    let response = client
        .post(format!("{API_BASE_URL}/api/admin/resolve-tie"))
        .json(&body)
        .send()?
        .error_for_status()?;

    let text = response.text().unwrap_or_default();

    println!("\nResolve tie completed");

    if !text.trim().is_empty() {
        println!("{text}");
    }

    Ok(())
}

fn get_results(client: &Client, decade_id: u8) -> Result<()> {
    get_api(
        client,
        &format!("/api/results/{decade_id}"),
        "Election results",
    )
}

fn get_elgamal_public_key(client: &Client, decade_id: u8) -> Result<ElGamalPubkey> {
    let response: ElGamalPublicKeyResponse = client
        .get(format!(
            "{API_BASE_URL}/api/election/{decade_id}/elgamal-public-key"
        ))
        .send()?
        .error_for_status()?
        .json()?;

    ElGamalPubkey::try_from(response.public_key.as_slice())
        .map_err(|_| anyhow::anyhow!("Invalid ElGamal public key"))
}

fn submit_one_vote(
    client: &Client,
    wallet: &WalletRecord,
    elgamal_public_key: &ElGamalPubkey,
    decade_id: u8,
    movie_index: usize,
) -> Result<SubmitVoteResponse> {
    let keypair_base58: String = serde_json::from_str(
        &fs::read_to_string(&wallet.keypair_64_file)
            .with_context(|| format!("Failed to read {}", wallet.keypair_64_file))?,
    )?;

    let keypair_bytes = bs58::decode(keypair_base58.trim()).into_vec()?;

    let keypair = Keypair::try_from(keypair_bytes.as_slice())
        .map_err(|error| anyhow::anyhow!("Invalid keypair: {error}"))?;

    let vote_vector = create_vote_vector(movie_index, 8)?;

    let witness = encrypt_vote_with_witness(&vote_vector, elgamal_public_key)?;

    let vote_proofs = generate_vote_proofs(
        elgamal_public_key,
        &vote_vector,
        &witness.encrypted_vote,
        &witness.opening_scalars,
    )?;

    let vote_sum_proof = generate_vote_sum_proof(
        elgamal_public_key,
        &witness.encrypted_vote,
        &witness.opening_scalars,
    )?;

    let encrypted_vote_hash = hash_encrypted_vote(&witness.encrypted_vote);

    let message = format!(
        "Kaonashi encrypted vote\nwallet_id: {}\npublic_key: {}\ndecade_id: {}\nencrypted_vote_hash: {}",
        wallet.wallet_id,
        wallet.public_key,
        decade_id,
        encrypted_vote_hash
    );

    let signature = keypair.sign_message(message.as_bytes()).to_string();

    let encrypted_vote_json = witness
        .encrypted_vote
        .iter()
        .map(|ciphertext| ciphertext.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let request = SubmitVoteRequest {
        wallet_id: wallet.wallet_id.clone(),
        public_key: wallet.public_key.clone(),
        decade_id,
        encrypted_vote: encrypted_vote_json,
        encrypted_vote_hash,
        vote_proofs,
        vote_sum_proof,
        message,
        signature,
    };

    let response = client
        .post(format!("{API_BASE_URL}/api/vote"))
        .json(&request)
        .send()?
        .error_for_status()?
        .json::<SubmitVoteResponse>()?;

    Ok(response)
}

struct EncryptedVoteWitness {
    encrypted_vote: Vec<[u8; 64]>,
    opening_scalars: Vec<Scalar>,
}

fn create_vote_vector(selected_index: usize, proposal_count: usize) -> Result<Vec<u64>> {
    let mut vote = vec![0u64; proposal_count];
    vote[selected_index] = 1;
    Ok(vote)
}

fn encrypt_vote_with_witness(
    vote: &[u64],
    public_key: &ElGamalPubkey,
) -> Result<EncryptedVoteWitness> {
    let mut encrypted_vote = Vec::new();
    let mut opening_scalars = Vec::new();

    for value in vote {
        let r = Scalar::random(&mut OsRng);
        let opening = PedersenOpening::new(r);

        encrypted_vote.push(public_key.encrypt_with_u64(*value, &opening).to_bytes());
        opening_scalars.push(r);
    }

    Ok(EncryptedVoteWitness {
        encrypted_vote,
        opening_scalars,
    })
}

fn hash_encrypted_vote(encrypted_vote: &[[u8; 64]]) -> String {
    let mut hasher = Sha256::new();

    for ciphertext in encrypted_vote {
        hasher.update(ciphertext);
    }

    hex::encode(hasher.finalize())
}

fn vec_from_point(point: &RistrettoPoint) -> Vec<u8> {
    point.compress().to_bytes().to_vec()
}

fn vec_from_scalar(scalar: &Scalar) -> Vec<u8> {
    scalar.to_bytes().to_vec()
}

fn split_ciphertext(ciphertext: &[u8; 64]) -> Result<(RistrettoPoint, RistrettoPoint)> {
    let mut commitment_bytes = [0u8; 32];
    let mut handle_bytes = [0u8; 32];

    commitment_bytes.copy_from_slice(&ciphertext[0..32]);
    handle_bytes.copy_from_slice(&ciphertext[32..64]);

    let commitment = CompressedRistretto(commitment_bytes)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid ciphertext commitment"))?;

    let handle = CompressedRistretto(handle_bytes)
        .decompress()
        .ok_or_else(|| anyhow::anyhow!("Invalid ciphertext handle"))?;

    Ok((commitment, handle))
}

fn derive_bases(
    public_key: &ElGamalPubkey,
) -> Result<(RistrettoPoint, RistrettoPoint, RistrettoPoint)> {
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

fn generate_vote_proof(
    public_key: &ElGamalPubkey,
    ciphertext: &[u8; 64],
    vote_value: u64,
    opening: &Scalar,
) -> Result<RistrettoVoteProof> {
    let (g_base, h_base, public_key_point) = derive_bases(public_key)?;
    let (commitment, handle) = split_ciphertext(ciphertext)?;

    let commitment_minus_0 = commitment;
    let commitment_minus_1 = commitment - g_base;

    let w = Scalar::random(&mut OsRng);
    let simulated_c = Scalar::random(&mut OsRng);
    let simulated_s = Scalar::random(&mut OsRng);

    if vote_value == 0 {
        let a0 = h_base * w;
        let b0 = public_key_point * w;

        let c1 = simulated_c;
        let s1 = simulated_s;

        let a1 = h_base * s1 - commitment_minus_1 * c1;
        let b1 = public_key_point * s1 - handle * c1;

        let challenge = challenge_vote_proof(public_key, ciphertext, &a0, &b0, &a1, &b1);

        let c0 = challenge - c1;
        let s0 = w + c0 * opening;

        Ok(RistrettoVoteProof {
            a0: vec_from_point(&a0),
            b0: vec_from_point(&b0),
            c0: vec_from_scalar(&c0),
            s0: vec_from_scalar(&s0),
            a1: vec_from_point(&a1),
            b1: vec_from_point(&b1),
            c1: vec_from_scalar(&c1),
            s1: vec_from_scalar(&s1),
        })
    } else {
        let c0 = simulated_c;
        let s0 = simulated_s;

        let a0 = h_base * s0 - commitment_minus_0 * c0;
        let b0 = public_key_point * s0 - handle * c0;

        let a1 = h_base * w;
        let b1 = public_key_point * w;

        let challenge = challenge_vote_proof(public_key, ciphertext, &a0, &b0, &a1, &b1);

        let c1 = challenge - c0;
        let s1 = w + c1 * opening;

        Ok(RistrettoVoteProof {
            a0: vec_from_point(&a0),
            b0: vec_from_point(&b0),
            c0: vec_from_scalar(&c0),
            s0: vec_from_scalar(&s0),
            a1: vec_from_point(&a1),
            b1: vec_from_point(&b1),
            c1: vec_from_scalar(&c1),
            s1: vec_from_scalar(&s1),
        })
    }
}

fn generate_vote_proofs(
    public_key: &ElGamalPubkey,
    vote_vector: &[u64],
    encrypted_vote: &[[u8; 64]],
    openings: &[Scalar],
) -> Result<Vec<RistrettoVoteProof>> {
    vote_vector
        .iter()
        .zip(encrypted_vote.iter())
        .zip(openings.iter())
        .map(|((value, ciphertext), opening)| {
            generate_vote_proof(public_key, ciphertext, *value, opening)
        })
        .collect()
}

fn generate_vote_sum_proof(
    public_key: &ElGamalPubkey,
    encrypted_vote: &[[u8; 64]],
    openings: &[Scalar],
) -> Result<RistrettoVoteSumProof> {
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
        aggregate_commitment.ok_or_else(|| anyhow::anyhow!("Missing aggregate commitment"))?;

    let aggregate_handle =
        aggregate_handle.ok_or_else(|| anyhow::anyhow!("Missing aggregate handle"))?;

    let total_opening = openings
        .iter()
        .fold(Scalar::ZERO, |acc, opening| acc + opening);

    let w = Scalar::random(&mut OsRng);

    let a = h_base * w;
    let b = public_key_point * w;

    let c = challenge_sum_proof(public_key, &aggregate_commitment, &aggregate_handle, &a, &b);

    let s = w + c * total_opening;

    let _commitment_minus_one = aggregate_commitment - g_base;

    Ok(RistrettoVoteSumProof {
        a: vec_from_point(&a),
        b: vec_from_point(&b),
        c: vec_from_scalar(&c),
        s: vec_from_scalar(&s),
    })
}
