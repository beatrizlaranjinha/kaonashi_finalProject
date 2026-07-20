use crate::crypto::vote_crypto::{
    create_vote_vector, encrypt_vote_with_witness, hash_encrypted_vote,
};
use crate::crypto::wallet_signature::sign_message;
use crate::crypto::zk_vote::{generate_vote_proofs, generate_vote_sum_proof};

use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::SigningKey;
use gloo_net::http::Request;
use serde::{Deserialize, Serialize};
use solana_zk_sdk::encryption::elgamal::ElGamalPubkey;

const API_BASE_URL: &str = "http://127.0.0.1:3000";

// API errors

#[derive(Debug, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
}

// Wallet authentication types

#[derive(Debug, Serialize)]
pub struct ChallengeRequest {
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeResponse {
    pub message: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct WalletLoginRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct WalletLoginResponse {
    pub authenticated: bool,
    pub public_key: String,

    // Some backend responses may not include a token.
    #[serde(default)]
    pub token: String,
}

// Wallet authentication functions

// Requests a challenge from the backend and signs it with the wallet private key.
pub async fn login_wallet(
    public_key: String,
    secret_key: String,
) -> Result<WalletLoginResponse, String> {
    let response = Request::post(&format!("{API_BASE_URL}/api/auth/challenge"))
        .header("Content-Type", "application/json")
        .json(&ChallengeRequest {
            public_key: public_key.clone(),
        })
        .map_err(|error| format!("Failed to create challenge request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    let challenge = if response.ok() {
        response
            .json::<ChallengeResponse>()
            .await
            .map_err(|error| format!("Invalid challenge response: {error}"))?
    } else {
        let status = response.status();

        return match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to get challenge with status {status}")),
        };
    };

    let secret_key_bytes = bs58::decode(secret_key.trim())
        .into_vec()
        .map_err(|error| format!("Invalid base58 secret key: {error}"))?;

    if secret_key_bytes.len() != 32 {
        return Err(format!(
            "Secret key must have 32 bytes, but has {}",
            secret_key_bytes.len()
        ));
    }

    let mut secret_key_array = [0u8; 32];
    secret_key_array.copy_from_slice(&secret_key_bytes);

    let mut signing_key = SigningKey::from_bytes(&secret_key_array);
    let signature = signing_key.sign(challenge.message.as_bytes());
    let signature_base58 = bs58::encode(signature.to_bytes()).into_string();

    let response = Request::post(&format!("{API_BASE_URL}/api/auth/login"))
        .header("Content-Type", "application/json")
        .json(&WalletLoginRequest {
            public_key,
            message: challenge.message,
            signature: signature_base58,
        })
        .map_err(|error| format!("Failed to create login request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<WalletLoginResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Login failed with status {status}")),
        }
    }
}

// Chairperson status types

#[derive(Debug, Deserialize)]
pub struct ChairpersonStatusResponse {
    pub public_key: String,
    pub is_chairperson: bool,
}

// Chairperson status functions

// Checks if the connected wallet is the chairperson.
pub async fn get_chairperson_status(
    public_key: String,
) -> Result<ChairpersonStatusResponse, String> {
    let response = Request::get(&format!(
        "{API_BASE_URL}/api/chairperson/status/{public_key}"
    ))
    .send()
    .await
    .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<ChairpersonStatusResponse>()
            .await
            .map_err(|error| format!("Invalid chairperson status response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!(
                "Failed to check chairperson status with status {status}"
            )),
        }
    }
}

// Encrypted voting types

#[derive(Debug, Deserialize)]
pub struct ElGamalPublicKeyResponse {
    pub decade_id: u8,

    #[serde(default)]
    pub decade: String,

    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RistrettoVoteProof {
    pub a0: Vec<u8>,
    pub b0: Vec<u8>,
    pub c0: Vec<u8>,
    pub s0: Vec<u8>,

    pub a1: Vec<u8>,
    pub b1: Vec<u8>,
    pub c1: Vec<u8>,
    pub s1: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RistrettoVoteSumProof {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
    pub s: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SubmitVoteRequest {
    pub wallet_id: String,
    pub public_key: String,
    pub decade_id: u8,

    pub encrypted_vote: Vec<Vec<u8>>,
    pub encrypted_vote_hash: String,

    pub vote_proofs: Vec<RistrettoVoteProof>,
    pub vote_sum_proof: RistrettoVoteSumProof,

    pub message: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitVoteResponse {
    pub accepted: bool,

    #[serde(default)]
    pub wallet_id: String,

    pub decade_id: u8,

    #[serde(default)]
    pub encrypted_vote_hash: String,

    #[serde(default)]
    pub decade: String,

    #[serde(default)]
    pub movie_index: usize,

    #[serde(default)]
    pub movie: String,

    #[serde(default)]
    pub status: String,

    #[serde(default)]
    pub pending_votes: usize,

    #[serde(default)]
    pub batch_submitted: bool,
}

// Encrypted voting helpers

// Fetches the ElGamal public key for the selected decade.
async fn get_elgamal_public_key(decade_id: u8) -> Result<ElGamalPubkey, String> {
    let response = Request::get(&format!(
        "{API_BASE_URL}/api/election/{decade_id}/elgamal-public-key"
    ))
    .send()
    .await
    .map_err(|error| format!("Failed to contact the API: {error}"))?;

    let response = if response.ok() {
        response
            .json::<ElGamalPublicKeyResponse>()
            .await
            .map_err(|error| format!("Invalid ElGamal public key response: {error}"))?
    } else {
        let status = response.status();

        return match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!(
                "Failed to get ElGamal public key with status {status}"
            )),
        };
    };

    if response.public_key.len() != 32 {
        return Err(format!(
            "ElGamal public key must have 32 bytes, got {}",
            response.public_key.len()
        ));
    }

    ElGamalPubkey::try_from(response.public_key.as_slice())
        .map_err(|_| "Invalid ElGamal public key bytes".to_string())
}

// Encrypted voting functions

// Encrypts the vote, generates proofs, signs the hash and submits it.
pub async fn submit_vote(
    wallet_id: String,
    public_key: String,
    secret_key: String,
    decade_id: u8,
    movie_index: usize,
    movie_name: String,
) -> Result<SubmitVoteResponse, String> {
    let elgamal_public_key = get_elgamal_public_key(decade_id).await?;

    let vote_vector = create_vote_vector(movie_index, 8)?;

    let encrypted_witness = encrypt_vote_with_witness(&vote_vector, &elgamal_public_key)?;

    let encrypted_vote = encrypted_witness.encrypted_vote;
    let opening_scalars = encrypted_witness.opening_scalars;

    if opening_scalars.len() != encrypted_vote.len() {
        return Err("Missing openings for encrypted vote".to_string());
    }

    let vote_proofs = generate_vote_proofs(
        &elgamal_public_key,
        &vote_vector,
        &encrypted_vote,
        &opening_scalars,
    )?;

    let vote_sum_proof =
        generate_vote_sum_proof(&elgamal_public_key, &encrypted_vote, &opening_scalars)?;

    let encrypted_vote_hash = hash_encrypted_vote(&encrypted_vote);

    let message = format!(
        "Kaonashi encrypted vote\nwallet_id: {}\npublic_key: {}\ndecade_id: {}\nencrypted_vote_hash: {}",
        wallet_id, public_key, decade_id, encrypted_vote_hash
    );

    let signature_base58 = sign_message(&secret_key, &message)?;

    leptos::logging::log!("ENCRYPTED VOTE HASH: {}", encrypted_vote_hash);
    leptos::logging::log!("SIGNED MESSAGE: {}", message);
    leptos::logging::log!("VOTE SIGNATURE: {}", signature_base58);

    let encrypted_vote_json = encrypted_vote
        .iter()
        .map(|ciphertext| ciphertext.to_vec())
        .collect::<Vec<Vec<u8>>>();

    let response = Request::post(&format!("{API_BASE_URL}/api/vote"))
        .header("Content-Type", "application/json")
        .json(&SubmitVoteRequest {
            wallet_id,
            public_key,
            decade_id,
            encrypted_vote: encrypted_vote_json,
            encrypted_vote_hash: encrypted_vote_hash.clone(),
            vote_proofs,
            vote_sum_proof,
            message,
            signature: signature_base58,
        })
        .map_err(|error| format!("Failed to create vote request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        let mut vote_response = response
            .json::<SubmitVoteResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))?;

        // The frontend already knows the selected movie.
        if vote_response.movie.is_empty() {
            vote_response.movie = movie_name;
            vote_response.movie_index = movie_index;
        }

        // The frontend already computed the vote hash.
        if vote_response.encrypted_vote_hash.is_empty() {
            vote_response.encrypted_vote_hash = encrypted_vote_hash;
        }

        Ok(vote_response)
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("The API rejected the vote with status {status}")),
        }
    }
}

// Admin signed request types

#[derive(Debug, Serialize)]
pub struct AdminActionRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

// Admin signed request helpers

// Builds the exact admin message expected by the backend.
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

// Creates a signed admin request using the chairperson private key.
fn create_signed_admin_request(
    public_key: &str,
    secret_key: &str,
    action: &str,
    decade_id: Option<u8>,
) -> Result<AdminActionRequest, String> {
    let message = create_admin_message(public_key, action, decade_id);
    let signature = sign_message(secret_key, &message)?;

    Ok(AdminActionRequest {
        public_key: public_key.to_string(),
        message,
        signature,
    })
}

// Batch types

#[derive(Debug, Deserialize)]
pub struct VoteReceiptResponse {
    #[serde(default)]
    pub vote_hash: String,

    #[serde(default)]
    pub batch_id: String,

    #[serde(default)]
    pub merkle_root: String,
}

#[derive(Debug, Deserialize)]
pub struct FlushBatchResponse {
    #[serde(default)]
    pub success: bool,

    #[serde(default)]
    pub submitted: bool,

    pub decade_id: u8,

    #[serde(default)]
    pub decade: String,

    #[serde(default)]
    pub batch_id: String,

    #[serde(default)]
    pub merkle_root: String,

    #[serde(default)]
    pub vote_count: usize,

    #[serde(default)]
    pub batch_size: usize,

    #[serde(default)]
    pub pending_votes: usize,

    #[serde(default)]
    pub encrypted_batch_tally: Vec<Vec<u8>>,

    #[serde(default)]
    pub receipts: Vec<VoteReceiptResponse>,

    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct FlushBatchesResponse {
    pub success: bool,

    #[serde(default)]
    pub total_batches: usize,

    #[serde(default)]
    pub total_votes: usize,

    #[serde(default)]
    pub results: Vec<FlushBatchResponse>,

    #[serde(default)]
    pub status: String,
}

// Batch functions

// Submits the pending batch of one decade.
pub async fn flush_batch(
    _wallet_id: String,
    public_key: String,
    secret_key: String,
    decade_id: u8,
) -> Result<FlushBatchResponse, String> {
    let admin_request =
        create_signed_admin_request(&public_key, &secret_key, "flush_batch", Some(decade_id))?;

    let response = Request::post(&format!("{API_BASE_URL}/api/admin/flush-batch/{decade_id}"))
        .header("Content-Type", "application/json")
        .json(&admin_request)
        .map_err(|error| format!("Failed to create flush request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<FlushBatchResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to submit batch with status {status}")),
        }
    }
}

// Submits all pending batches from all decades.
pub async fn flush_batches(
    _wallet_id: String,
    public_key: String,
    secret_key: String,
) -> Result<FlushBatchesResponse, String> {
    let admin_request =
        create_signed_admin_request(&public_key, &secret_key, "flush_batches", None)?;

    let response = Request::post(&format!("{API_BASE_URL}/api/admin/flush-batches"))
        .header("Content-Type", "application/json")
        .json(&admin_request)
        .map_err(|error| format!("Failed to create flush batches request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<FlushBatchesResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to submit batches with status {status}")),
        }
    }
}

// Results types

#[derive(Debug, Deserialize, Clone)]
pub struct MovieResult {
    pub index: usize,
    pub title: String,
    pub votes: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ResultsResponse {
    pub decade_id: u8,

    #[serde(default)]
    pub decade: String,

    #[serde(default)]
    pub ballot_address: String,

    #[serde(default)]
    pub total_votes: usize,

    #[serde(default)]
    pub winner_index: Option<usize>,

    #[serde(default)]
    pub winner: Option<String>,

    #[serde(default)]
    pub tie_indices: Vec<usize>,

    #[serde(default)]
    pub final_winner_index: Option<usize>,

    #[serde(default)]
    pub final_winner: Option<String>,

    #[serde(default)]
    pub results: Vec<MovieResult>,
}

// Results functions

// Fetches the decrypted results for one decade.
pub async fn get_results(decade_id: u8) -> Result<ResultsResponse, String> {
    let response = Request::get(&format!("{API_BASE_URL}/api/results/{decade_id}"))
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<ResultsResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to load results with status {status}")),
        }
    }
}

// Tie resolution types

#[derive(Debug, Serialize)]
pub struct ResolveTieRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
    pub decade_id: u8,
    pub winner_index: usize,
}

#[derive(Debug, Deserialize)]
pub struct ResolveTieResponse {
    pub success: bool,
    pub decade_id: u8,
    pub winner_index: usize,

    #[serde(default)]
    pub status: String,
}

// Tie resolution functions

// Resolves a tie by signing the chairperson's chosen winner.
pub async fn resolve_tie(
    _wallet_id: String,
    public_key: String,
    secret_key: String,
    decade_id: u8,
    winner_index: usize,
) -> Result<ResolveTieResponse, String> {
    let admin_request =
        create_signed_admin_request(&public_key, &secret_key, "resolve_tie", Some(decade_id))?;

    let request = ResolveTieRequest {
        public_key: admin_request.public_key,
        message: admin_request.message,
        signature: admin_request.signature,
        decade_id,
        winner_index,
    };

    let response = Request::post(&format!("{API_BASE_URL}/api/admin/resolve-tie"))
        .header("Content-Type", "application/json")
        .json(&request)
        .map_err(|error| format!("Failed to create tie request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<ResolveTieResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to resolve tie with status {status}")),
        }
    }
}

// Receipt types

#[derive(Debug, Serialize)]
pub struct VerifyReceiptRequest {
    pub vote_hash: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StoredVoteReceiptResponse {
    #[serde(default)]
    pub vote_hash: String,

    #[serde(default)]
    pub batch_id: String,

    #[serde(default)]
    pub merkle_root: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VerifyReceiptResponse {
    #[serde(default)]
    pub vote_hash: String,

    #[serde(default)]
    pub verified: bool,

    #[serde(default)]
    pub batch_id: String,

    #[serde(default)]
    pub merkle_root: String,

    #[serde(default)]
    pub status: String,
}

// Receipt functions

// Fetches a stored receipt by vote hash.
pub async fn get_vote_receipt(
    vote_hash: String,
) -> Result<Option<StoredVoteReceiptResponse>, String> {
    let response = Request::get(&format!("{API_BASE_URL}/api/vote/receipt/{vote_hash}"))
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<Option<StoredVoteReceiptResponse>>()
            .await
            .map_err(|error| format!("Invalid receipt response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to load receipt with status {status}")),
        }
    }
}

// Verifies a receipt using its Merkle proof.
pub async fn verify_vote_receipt(vote_hash: String) -> Result<VerifyReceiptResponse, String> {
    let response = Request::post(&format!("{API_BASE_URL}/api/vote/verify-receipt"))
        .header("Content-Type", "application/json")
        .json(&VerifyReceiptRequest { vote_hash })
        .map_err(|error| format!("Failed to create receipt verification request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<VerifyReceiptResponse>()
            .await
            .map_err(|error| format!("Invalid receipt verification response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to verify receipt with status {status}")),
        }
    }
}

// Chairperson action types

#[derive(Debug, Deserialize, Clone)]
pub struct DecadeOperationResult {
    pub decade_id: u8,

    #[serde(default)]
    pub decade: String,

    pub success: bool,

    #[serde(default)]
    pub status: String,

    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CloseElectionResponse {
    pub success: bool,

    #[serde(default)]
    pub results: Vec<DecadeOperationResult>,

    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct FinalizeElectionResponse {
    pub success: bool,

    #[serde(default)]
    pub results: Vec<DecadeOperationResult>,

    #[serde(default)]
    pub status: String,
}

// Chairperson action functions

// Creates all on-chain ballots.
pub async fn create_ballots(public_key: String, secret_key: String) -> Result<String, String> {
    let admin_request =
        create_signed_admin_request(&public_key, &secret_key, "create_ballots", None)?;

    let response = Request::post(&format!("{API_BASE_URL}/api/admin/create-ballots"))
        .header("Content-Type", "application/json")
        .json(&admin_request)
        .map_err(|error| format!("Failed to create ballots request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .text()
            .await
            .map_err(|error| format!("Invalid create ballots response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to create ballots with status {status}")),
        }
    }
}

// Closes the election and rejects new votes.
pub async fn close_election(
    _wallet_id: String,
    public_key: String,
    secret_key: String,
) -> Result<CloseElectionResponse, String> {
    let admin_request =
        create_signed_admin_request(&public_key, &secret_key, "close_election", None)?;

    let response = Request::post(&format!("{API_BASE_URL}/api/admin/close-election"))
        .header("Content-Type", "application/json")
        .json(&admin_request)
        .map_err(|error| format!("Failed to create close election request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<CloseElectionResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to close election with status {status}")),
        }
    }
}

// Finalizes the election after batches and tie resolution.
pub async fn finalize_election(
    _wallet_id: String,
    public_key: String,
    secret_key: String,
) -> Result<FinalizeElectionResponse, String> {
    let admin_request =
        create_signed_admin_request(&public_key, &secret_key, "finalize_election", None)?;

    let response = Request::post(&format!("{API_BASE_URL}/api/admin/finalize-election"))
        .header("Content-Type", "application/json")
        .json(&admin_request)
        .map_err(|error| format!("Failed to create finalize request: {error}"))?
        .send()
        .await
        .map_err(|error| format!("Failed to contact the API: {error}"))?;

    if response.ok() {
        response
            .json::<FinalizeElectionResponse>()
            .await
            .map_err(|error| format!("Invalid API response: {error}"))
    } else {
        let status = response.status();

        match response.json::<ApiErrorResponse>().await {
            Ok(api_error) => Err(api_error.error),
            Err(_) => Err(format!("Failed to finalize election with status {status}")),
        }
    }
}
