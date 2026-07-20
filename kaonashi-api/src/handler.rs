use std::sync::{Arc, LazyLock, Mutex};

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_zk_sdk::encryption::elgamal::ElGamalPubkey;

use crate::auth::{create_login_message, verify_chairperson_action, verify_signature};
use crate::batches::{create_batch_for_decade, MAX_BATCH_SIZE};
use crate::blockchain::{
    close_ballot_on_chain, create_all_ballots_on_chain, finalize_election_from_blockchain,
    get_ballot_state_from_blockchain,
};
use crate::keeping_votes::KeepingVotes;
use crate::merkle::{verify_merkle_proof, MerkleProofNode};
use crate::models::{
    AdminActionRequest, BlockchainBallotResponse, ChairpersonStatusResponse, ChallengeRequest,
    ChallengeResponse, ElGamalPublicKeyResponse, ElectionCompletionResponse, FinalResultsResponse,
    FlushBatchResponse, LoginRequest, LoginResponse, PendingEncryptedVote, SubmitVoteResponse,
    SubmittedVote, VerifyReceiptRequest, VerifyReceiptResponse, VoteReceipt,
};
use crate::movies::movies_decades;
use crate::zk_verify::verify_encrypted_vote_proofs;

// Local API state

const DECADE_COUNT: usize = 6;

static ELECTION_CLOSED_BY_DECADE: LazyLock<Mutex<Vec<bool>>> =
    LazyLock::new(|| Mutex::new(vec![false; DECADE_COUNT]));

static RESOLVED_TIES_BY_DECADE: LazyLock<Mutex<Vec<Option<usize>>>> =
    LazyLock::new(|| Mutex::new(vec![None; DECADE_COUNT]));

// Local response types

#[derive(Debug, Serialize)]
pub struct DecadeOperationResult {
    pub decade_id: u8,
    pub success: bool,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct CloseElectionResponse {
    pub success: bool,
    pub results: Vec<DecadeOperationResult>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FlushBatchesResponse {
    pub success: bool,
    pub total_batches: usize,
    pub total_votes: usize,
    pub results: Vec<FlushBatchResponse>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct ResolveTieRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
    pub decade_id: u8,
    pub winner_index: usize,
}

#[derive(Debug, Serialize)]
pub struct ResolveTieResponse {
    pub success: bool,
    pub decade_id: u8,
    pub winner_index: usize,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct FinalizeElectionResponse {
    pub success: bool,
    pub results: Vec<DecadeOperationResult>,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct MovieResult {
    pub index: usize,
    pub title: String,
    pub votes: u64,
}

#[derive(Debug, Serialize)]
pub struct ResultsResponse {
    pub decade_id: u8,
    pub decade: String,
    pub ballot_address: String,
    pub total_votes: usize,
    pub winner_index: Option<usize>,
    pub winner: Option<String>,
    pub tie_indices: Vec<usize>,
    pub final_winner_index: Option<usize>,
    pub final_winner: Option<String>,
    pub results: Vec<MovieResult>,
}

// Basic API

// Confirms that the API server is running.
pub async fn is_running() -> &'static str {
    "api is indeed running"
}

// ElGamal public key

// Returns the ElGamal public key for a decade.
pub async fn get_elgamal_public_key(
    Path(decade_id): Path<u8>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
) -> Result<Json<ElGamalPublicKeyResponse>, String> {
    if movies_decades(decade_id).is_none() {
        return Err("Invalid decade".to_string());
    }

    let keypairs = keeping_votes.elgamal_keypairs_by_decade.lock().unwrap();

    let Some(keypair) = keypairs.get(decade_id as usize) else {
        return Err("No ElGamal keypair found for this decade".to_string());
    };

    Ok(Json(ElGamalPublicKeyResponse {
        decade_id,
        decade: format!("{}s", decade_label(decade_id)),
        public_key: keypair.pubkey().to_bytes().to_vec(),
    }))
}

// Vote submission

// Receives, validates and stores an encrypted vote.
pub async fn submit_vote(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(vote): Json<SubmittedVote>,
) -> Json<SubmitVoteResponse> {
    let Some(movies) = movies_decades(vote.decade_id) else {
        return Json(vote_response(
            false,
            vote.wallet_id,
            vote.decade_id,
            "invalid decade".to_string(),
            0,
            false,
            "Invalid decade".to_string(),
        ));
    };

    // The election must be created before users can vote.
    if !ballot_exists(keeping_votes.as_ref(), vote.decade_id) {
        return Json(vote_response(
            false,
            vote.wallet_id,
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            "Election is not ready yet. The chairperson must create the ballots first.".to_string(),
        ));
    }

    // Closed elections reject new votes.
    if is_decade_closed(vote.decade_id) {
        return Json(vote_response(
            false,
            vote.wallet_id,
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            "Election is closed".to_string(),
        ));
    }

    let proposal_count = movies.len();

    let encrypted_vote = match normalize_encrypted_vote(&vote.encrypted_vote, proposal_count) {
        Ok(encrypted_vote) => encrypted_vote,
        Err(error) => {
            println!("Invalid encrypted vote: {}", error);

            return Json(vote_response(
                false,
                vote.wallet_id,
                vote.decade_id,
                format!("{}s", decade_label(vote.decade_id)),
                0,
                false,
                "Invalid encrypted vote".to_string(),
            ));
        }
    };

    let expected_hash = hash_encrypted_vote(&encrypted_vote);

    if expected_hash != vote.encrypted_vote_hash {
        println!("Invalid encrypted vote hash");

        return Json(vote_response(
            false,
            vote.wallet_id,
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            "Invalid encrypted vote hash".to_string(),
        ));
    }

    let expected_message = format!(
        "Kaonashi encrypted vote\nwallet_id: {}\npublic_key: {}\ndecade_id: {}\nencrypted_vote_hash: {}",
        vote.wallet_id, vote.public_key, vote.decade_id, vote.encrypted_vote_hash
    );

    if vote.message != expected_message {
        println!("Vote message does not match encrypted vote");

        return Json(vote_response(
            false,
            vote.wallet_id,
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            "Vote message does not match".to_string(),
        ));
    }

    if let Err(error) = verify_signature(&vote.public_key, &vote.message, &vote.signature) {
        println!("Invalid vote signature: {}", error);

        return Json(vote_response(
            false,
            vote.wallet_id,
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            "Invalid vote signature".to_string(),
        ));
    }

    println!("Encrypted vote signature verified");
    println!("Encrypted vote hash: {}", vote.encrypted_vote_hash);
    println!("Received vote proofs: {}", vote.vote_proofs.len());

    let elgamal_public_key = {
        let keypairs = keeping_votes.elgamal_keypairs_by_decade.lock().unwrap();

        let Some(keypair) = keypairs.get(vote.decade_id as usize) else {
            return Json(vote_response(
                false,
                vote.wallet_id.clone(),
                vote.decade_id,
                format!("{}s", decade_label(vote.decade_id)),
                0,
                false,
                "Invalid decade keypair".to_string(),
            ));
        };

        let public_key_bytes = keypair.pubkey().to_bytes();

        ElGamalPubkey::try_from(public_key_bytes.as_slice())
            .map_err(|_| "Invalid ElGamal public key".to_string())
    };

    let Ok(elgamal_public_key) = elgamal_public_key else {
        return Json(vote_response(
            false,
            vote.wallet_id.clone(),
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            "Invalid ElGamal public key".to_string(),
        ));
    };

    if let Err(error) = verify_encrypted_vote_proofs(
        &elgamal_public_key,
        &encrypted_vote,
        &vote.vote_proofs,
        &vote.vote_sum_proof,
    ) {
        println!("Invalid vote proof: {}", error);

        return Json(vote_response(
            false,
            vote.wallet_id.clone(),
            vote.decade_id,
            format!("{}s", decade_label(vote.decade_id)),
            0,
            false,
            format!("Invalid vote proof: {}", error),
        ));
    }

    println!("Encrypted vote proofs verified");

    let mut pending_votes = keeping_votes.pending_encrypted_votes.lock().unwrap();

    pending_votes[vote.decade_id as usize].push(PendingEncryptedVote {
        wallet_id: vote.wallet_id.clone(),
        public_key: vote.public_key.clone(),
        decade_id: vote.decade_id,
        encrypted_vote_hash: vote.encrypted_vote_hash.clone(),
        encrypted_vote,
    });

    let pending_votes_count = pending_votes[vote.decade_id as usize].len();

    drop(pending_votes);

    // Automatically creates a batch when the batch size is reached.
    let batch_submitted = if pending_votes_count >= MAX_BATCH_SIZE {
        match create_batch_for_decade(keeping_votes.as_ref(), vote.decade_id) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(error) => {
                println!("Auto flush failed: {}", error);
                false
            }
        }
    } else {
        false
    };

    Json(vote_response(
        true,
        vote.wallet_id,
        vote.decade_id,
        format!("{}s", decade_label(vote.decade_id)),
        if batch_submitted {
            0
        } else {
            pending_votes_count
        },
        batch_submitted,
        "Encrypted vote accepted".to_string(),
    ))
}

// Creates the standard vote response.
fn vote_response(
    accepted: bool,
    wallet_id: String,
    decade_id: u8,
    decade: String,
    pending_votes: usize,
    batch_submitted: bool,
    status: String,
) -> SubmitVoteResponse {
    SubmitVoteResponse {
        accepted,
        wallet_id,
        decade_id,
        decade,
        movie_index: 0,
        movie: String::new(),
        status,
        pending_votes,
        batch_submitted,
    }
}

// Converts JSON ciphertexts into the internal encrypted vote format.
fn normalize_encrypted_vote(
    encrypted_vote: &[Vec<u8>],
    proposal_count: usize,
) -> Result<Vec<[u8; 64]>, String> {
    if encrypted_vote.len() != proposal_count {
        return Err(format!(
            "Expected {} ciphertexts, got {}",
            proposal_count,
            encrypted_vote.len()
        ));
    }

    encrypted_vote
        .iter()
        .map(|ciphertext| {
            if ciphertext.len() != 64 {
                return Err(format!(
                    "Each ciphertext must have 64 bytes, got {}",
                    ciphertext.len()
                ));
            }

            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(ciphertext);

            Ok(bytes)
        })
        .collect()
}

// Computes the hash that the voter signs.
fn hash_encrypted_vote(encrypted_vote: &[[u8; 64]]) -> String {
    let mut hasher = Sha256::new();

    for ciphertext in encrypted_vote {
        hasher.update(ciphertext);
    }

    hex::encode(hasher.finalize())
}

// Batches

// Creates a batch for one decade.
pub async fn flush_batch(
    Path(decade_id): Path<u8>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(admin): Json<AdminActionRequest>,
) -> Json<FlushBatchResponse> {
    if let Err(error) = verify_chairperson_action(
        &admin.public_key,
        &admin.message,
        &admin.signature,
        "flush_batch",
        Some(decade_id),
    ) {
        return Json(empty_flush_response(
            false,
            decade_id,
            format!("Unauthorized admin action: {}", error),
        ));
    }

    if movies_decades(decade_id).is_none() {
        return Json(empty_flush_response(
            false,
            decade_id,
            "Invalid decade".to_string(),
        ));
    }

    if !ballot_exists(keeping_votes.as_ref(), decade_id) {
        return Json(empty_flush_response(
            false,
            decade_id,
            "No on-chain ballot found. Create ballots first.".to_string(),
        ));
    }

    match create_batch_for_decade(keeping_votes.as_ref(), decade_id) {
        Ok(Some(response)) => Json(response),

        Ok(None) => Json(empty_flush_response(
            false,
            decade_id,
            "No pending encrypted votes".to_string(),
        )),

        Err(error) => Json(empty_flush_response(false, decade_id, error)),
    }
}

// Creates pending batches for all decades.
pub async fn flush_batches(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(admin): Json<AdminActionRequest>,
) -> Json<FlushBatchesResponse> {
    if let Err(error) = verify_chairperson_action(
        &admin.public_key,
        &admin.message,
        &admin.signature,
        "flush_batches",
        None,
    ) {
        return Json(FlushBatchesResponse {
            success: false,
            total_batches: 0,
            total_votes: 0,
            results: Vec::new(),
            status: format!("Unauthorized admin action: {}", error),
        });
    }

    let mut results = Vec::new();
    let mut total_batches = 0;
    let mut total_votes = 0;

    for decade_id in 0..DECADE_COUNT as u8 {
        if movies_decades(decade_id).is_none() {
            continue;
        }

        if !ballot_exists(keeping_votes.as_ref(), decade_id) {
            results.push(empty_flush_response(
                false,
                decade_id,
                "No on-chain ballot found. Create ballots first.".to_string(),
            ));
            continue;
        }

        match create_batch_for_decade(keeping_votes.as_ref(), decade_id) {
            Ok(Some(response)) => {
                if response.success {
                    total_batches += 1;
                    total_votes += response.vote_count;
                }

                results.push(response);
            }

            Ok(None) => {
                results.push(empty_flush_response(
                    false,
                    decade_id,
                    "No pending encrypted votes".to_string(),
                ));
            }

            Err(error) => {
                results.push(empty_flush_response(false, decade_id, error));
            }
        }
    }

    Json(FlushBatchesResponse {
        success: true,
        total_batches,
        total_votes,
        results,
        status: format!(
            "{} batch(es) submitted with {} pending vote(s).",
            total_batches, total_votes
        ),
    })
}

// Creates an empty batch response for errors or no pending votes.
fn empty_flush_response(success: bool, decade_id: u8, status: String) -> FlushBatchResponse {
    FlushBatchResponse {
        success,
        decade_id,
        batch_id: String::new(),
        merkle_root: String::new(),
        vote_count: 0,
        encrypted_batch_tally: Vec::new(),
        receipts: Vec::new(),
        status,
    }
}

// Vote receipts

// Returns the receipt of a vote using its hash.
pub async fn get_vote_receipt(
    Path(vote_hash): Path<String>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
) -> Json<Option<VoteReceipt>> {
    let receipts = keeping_votes.vote_receipts_by_hash.lock().unwrap();

    Json(receipts.get(&vote_hash).cloned())
}

// Verifies that a vote receipt matches its Merkle root.
pub async fn verify_vote_receipt(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(payload): Json<VerifyReceiptRequest>,
) -> Json<VerifyReceiptResponse> {
    let receipts = keeping_votes.vote_receipts_by_hash.lock().unwrap();

    let Some(receipt) = receipts.get(&payload.vote_hash) else {
        return Json(VerifyReceiptResponse {
            vote_hash: payload.vote_hash,
            verified: false,
            batch_id: String::new(),
            merkle_root: String::new(),
            status: "Receipt not found".to_string(),
        });
    };

    let proof = receipt
        .merkle_proof
        .iter()
        .map(|node| MerkleProofNode {
            hash: node.hash.clone(),
            is_left: node.is_left,
        })
        .collect::<Vec<MerkleProofNode>>();

    let verified = verify_merkle_proof(&receipt.leaf_hash, &proof, &receipt.merkle_root);

    Json(VerifyReceiptResponse {
        vote_hash: receipt.vote_hash.clone(),
        verified,
        batch_id: receipt.batch_id.clone(),
        merkle_root: receipt.merkle_root.clone(),
        status: if verified {
            "Receipt verified".to_string()
        } else {
            "Receipt verification failed".to_string()
        },
    })
}

// Results

// Returns the current vote counts for one decade.
pub async fn get_results(
    Path(decade_id): Path<u8>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
) -> Json<ResultsResponse> {
    let Some(movies) = movies_decades(decade_id) else {
        return Json(ResultsResponse {
            decade_id,
            decade: "invalid".to_string(),
            ballot_address: String::new(),
            total_votes: 0,
            winner_index: None,
            winner: None,
            tie_indices: Vec::new(),
            final_winner_index: None,
            final_winner: None,
            results: Vec::new(),
        });
    };

    let selected_votes = {
        let votes = keeping_votes.votes_by_decade.lock().unwrap();

        votes[decade_id as usize].clone()
    };

    let ballot_address = {
        let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

        ballots
            .get(decade_id as usize)
            .and_then(|ballot| ballot.as_ref())
            .cloned()
            .unwrap_or_default()
    };

    let results = movies
        .iter()
        .enumerate()
        .map(|(index, title)| MovieResult {
            index,
            title: title.clone(),
            votes: selected_votes[index] as u64,
        })
        .collect::<Vec<MovieResult>>();

    let total_votes = results.iter().map(|result| result.votes as usize).sum();

    let max_votes = results.iter().map(|result| result.votes).max().unwrap_or(0);

    let tie_indices = if max_votes == 0 {
        Vec::new()
    } else {
        results
            .iter()
            .filter_map(|result| {
                if result.votes == max_votes {
                    Some(result.index)
                } else {
                    None
                }
            })
            .collect::<Vec<usize>>()
    };

    let winner_index = if tie_indices.len() == 1 {
        Some(tie_indices[0])
    } else {
        None
    };

    let winner = winner_index.map(|index| movies[index].clone());

    let final_winner_index = get_resolved_tie(decade_id);
    let final_winner = final_winner_index.map(|index| movies[index].clone());

    Json(ResultsResponse {
        decade_id,
        decade: format!("{}s", decade_label(decade_id)),
        ballot_address: ballot_address.to_string(),
        total_votes,
        winner_index,
        winner,
        tie_indices,
        final_winner_index,
        final_winner,
        results,
    })
}

// Returns the winner text for one decade.
pub async fn get_winner(
    Path(decade_id): Path<u8>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
) -> String {
    let Some(movies) = movies_decades(decade_id) else {
        return "invalid decade".to_string();
    };

    let votes = keeping_votes.votes_by_decade.lock().unwrap();

    let selected_decade_votes = &votes[decade_id as usize];

    let Some((winner_index, winner_votes)) = selected_decade_votes
        .iter()
        .enumerate()
        .max_by_key(|(_, vote_count)| *vote_count)
    else {
        return "no votes found".to_string();
    };

    if *winner_votes == 0 {
        return "No votes yet".to_string();
    }

    let tied_movies = selected_decade_votes
        .iter()
        .enumerate()
        .filter_map(|(index, vote_count)| {
            if vote_count == winner_votes {
                Some(movies[index].clone())
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    if tied_movies.len() > 1 {
        return format!(
            "tie between: {} with {} votes",
            tied_movies.join(", "),
            winner_votes
        );
    }

    format!(
        "Winner: {} with {} votes",
        movies[winner_index], winner_votes
    )
}

// Returns the movie list for one decade.
pub async fn get_movies(Path(decade_id): Path<u8>) -> Json<Option<Vec<String>>> {
    let movies = movies_decades(decade_id)
        .map(|movies| movies.iter().map(|movie| movie.to_string()).collect());

    Json(movies)
}

// Chairperson actions

// Creates all on-chain ballots.
pub async fn create_ballots(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(admin): Json<AdminActionRequest>,
) -> String {
    if let Err(error) = verify_chairperson_action(
        &admin.public_key,
        &admin.message,
        &admin.signature,
        "create_ballots",
        None,
    ) {
        return format!("Unauthorized admin action: {}", error);
    }

    if all_ballots_exist(keeping_votes.as_ref()) {
        return "Ballots already exist. The election is already ready.".to_string();
    }

    let elgamal_public_keys_by_decade = {
        let keypairs = keeping_votes.elgamal_keypairs_by_decade.lock().unwrap();

        keypairs
            .iter()
            .map(|keypair| keypair.pubkey().to_bytes())
            .collect::<Vec<[u8; 32]>>()
    };

    let result = tokio::task::spawn_blocking(move || {
        create_all_ballots_on_chain(elgamal_public_keys_by_decade)
    })
    .await;

    match result {
        Ok(Ok(created_ballots)) => {
            let lines = created_ballots
                .iter()
                .map(|(decade_id, ballot)| format!("decade {} -> ballot {}", decade_id, ballot))
                .collect::<Vec<String>>();

            {
                let mut ballots = keeping_votes.ballots_by_decade.lock().unwrap();

                for (decade_id, ballot) in created_ballots {
                    ballots[decade_id as usize] = Some(ballot);
                }
            }

            // Creating ballots opens the election.
            {
                let mut closed = ELECTION_CLOSED_BY_DECADE.lock().unwrap();

                for value in closed.iter_mut() {
                    *value = false;
                }
            }

            // A new election starts without resolved ties.
            {
                let mut resolved_ties = RESOLVED_TIES_BY_DECADE.lock().unwrap();

                for value in resolved_ties.iter_mut() {
                    *value = None;
                }
            }

            lines.join("\n")
        }

        Ok(Err(error)) => format!("Blockchain error: {}", error),

        Err(error) => format!("Blockchain task failed: {}", error),
    }
}

// Closes the election for all decades.
pub async fn close_election(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(admin): Json<AdminActionRequest>,
) -> Json<CloseElectionResponse> {
    if let Err(error) = verify_chairperson_action(
        &admin.public_key,
        &admin.message,
        &admin.signature,
        "close_election",
        None,
    ) {
        return Json(CloseElectionResponse {
            success: false,
            results: Vec::new(),
            status: format!("Unauthorized admin action: {}", error),
        });
    }

    let mut results = Vec::new();

    for decade_id in 0..DECADE_COUNT as u8 {
        let ballot = {
            let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

            ballots
                .get(decade_id as usize)
                .and_then(|ballot| ballot.as_ref())
                .cloned()
        };

        let Some(ballot) = ballot else {
            results.push(DecadeOperationResult {
                decade_id,
                success: false,
                status: "No ballot found. Create ballots first.".to_string(),
            });

            continue;
        };

        let close_result =
            tokio::task::spawn_blocking(move || close_ballot_on_chain(ballot, decade_id)).await;

        match close_result {
            Ok(Ok(())) => {
                {
                    let mut closed = ELECTION_CLOSED_BY_DECADE.lock().unwrap();

                    closed[decade_id as usize] = true;
                }

                results.push(DecadeOperationResult {
                    decade_id,
                    success: true,
                    status: "Closed".to_string(),
                });
            }

            Ok(Err(error)) => {
                results.push(DecadeOperationResult {
                    decade_id,
                    success: false,
                    status: error,
                });
            }

            Err(error) => {
                results.push(DecadeOperationResult {
                    decade_id,
                    success: false,
                    status: format!("Close task failed: {}", error),
                });
            }
        }
    }

    let closed_count = results.iter().filter(|result| result.success).count();

    Json(CloseElectionResponse {
        success: closed_count > 0,
        results,
        status: format!("Election closed across {} decade ballot(s).", closed_count),
    })
}

// Stores the chairperson decision for a tied decade.
pub async fn resolve_tie(Json(payload): Json<ResolveTieRequest>) -> Json<ResolveTieResponse> {
    if let Err(error) = verify_chairperson_action(
        &payload.public_key,
        &payload.message,
        &payload.signature,
        "resolve_tie",
        Some(payload.decade_id),
    ) {
        return Json(ResolveTieResponse {
            success: false,
            decade_id: payload.decade_id,
            winner_index: payload.winner_index,
            status: format!("Unauthorized admin action: {}", error),
        });
    }

    let Some(movies) = movies_decades(payload.decade_id) else {
        return Json(ResolveTieResponse {
            success: false,
            decade_id: payload.decade_id,
            winner_index: payload.winner_index,
            status: "Invalid decade".to_string(),
        });
    };

    if payload.winner_index >= movies.len() {
        return Json(ResolveTieResponse {
            success: false,
            decade_id: payload.decade_id,
            winner_index: payload.winner_index,
            status: "Invalid winner index".to_string(),
        });
    }

    {
        let mut resolved_ties = RESOLVED_TIES_BY_DECADE.lock().unwrap();

        resolved_ties[payload.decade_id as usize] = Some(payload.winner_index);
    }

    Json(ResolveTieResponse {
        success: true,
        decade_id: payload.decade_id,
        winner_index: payload.winner_index,
        status: format!(
            "Tie resolved for decade {} with winner index {}.",
            payload.decade_id, payload.winner_index
        ),
    })
}

// Finalizes all decade elections.
pub async fn finalize_election(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(admin): Json<AdminActionRequest>,
) -> Json<FinalizeElectionResponse> {
    if let Err(error) = verify_chairperson_action(
        &admin.public_key,
        &admin.message,
        &admin.signature,
        "finalize_election",
        None,
    ) {
        return Json(FinalizeElectionResponse {
            success: false,
            results: Vec::new(),
            status: format!("Unauthorized admin action: {}", error),
        });
    }

    let mut results = Vec::new();

    for decade_id in 0..DECADE_COUNT as u8 {
        if !ballot_exists(keeping_votes.as_ref(), decade_id) {
            results.push(DecadeOperationResult {
                decade_id,
                success: false,
                status: "No ballot found. Create ballots first.".to_string(),
            });

            continue;
        }

        if !is_decade_closed(decade_id) {
            results.push(DecadeOperationResult {
                decade_id,
                success: false,
                status: "Election must be closed before finalization.".to_string(),
            });

            continue;
        }

        let response = finalize_decade_from_state(keeping_votes.clone(), decade_id).await;

        // Saves decrypted results so the results page can read them.
        if !response.results.is_empty() {
            let mut votes = keeping_votes.votes_by_decade.lock().unwrap();

            if let Some(decade_votes) = votes.get_mut(decade_id as usize) {
                *decade_votes = response.results.iter().map(|votes| *votes as u64).collect();
            }
        }

        results.push(DecadeOperationResult {
            decade_id,
            success: response.success,
            status: response.status,
        });
    }

    let finalized_count = results
        .iter()
        .filter(|result| result.status == "Finalized")
        .count();

    let tie_count = results
        .iter()
        .filter(|result| result.status == "Tie")
        .count();

    let no_votes_count = results
        .iter()
        .filter(|result| result.status == "NoVotes")
        .count();

    let error_count = results
        .iter()
        .filter(|result| !result.success && result.status != "Tie" && result.status != "NoVotes")
        .count();

    Json(FinalizeElectionResponse {
        success: tie_count == 0 && error_count == 0 && finalized_count > 0,
        results,
        status: format!(
            "{} decade ballot(s) finalized. {} tie(s) require resolution. {} decade ballot(s) had no votes. {} error(s).",
            finalized_count, tie_count, no_votes_count, error_count
        ),
    })
}

// Finalizes only one decade.
// This keeps the old finalize-by-decade route available.
pub async fn finalize_election_for_decade(
    Path(decade_id): Path<u8>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(admin): Json<AdminActionRequest>,
) -> Json<FinalResultsResponse> {
    if let Err(error) = verify_chairperson_action(
        &admin.public_key,
        &admin.message,
        &admin.signature,
        "finalize_election",
        Some(decade_id),
    ) {
        return Json(FinalResultsResponse {
            success: false,
            decade_id,
            results: Vec::new(),
            winner_index: 0,
            winner_movie: String::new(),
            total_votes: 0,
            batch_count: 0,
            status: format!("Unauthorized admin action: {}", error),
        });
    }

    Json(finalize_decade_from_state(keeping_votes, decade_id).await)
}

// Reads and decrypts the on-chain encrypted tally for one decade.
async fn finalize_decade_from_state(
    keeping_votes: Arc<KeepingVotes>,
    decade_id: u8,
) -> FinalResultsResponse {
    let ballot = {
        let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

        let Some(ballot) = ballots
            .get(decade_id as usize)
            .and_then(|ballot| ballot.as_ref())
            .cloned()
        else {
            return FinalResultsResponse {
                success: false,
                decade_id,
                results: Vec::new(),
                winner_index: 0,
                winner_movie: String::new(),
                total_votes: 0,
                batch_count: 0,
                status: "No on-chain ballot found in API memory. Run /api/admin/create-ballots without restarting the API.".to_string(),
            };
        };

        ballot
    };

    let secret_key = {
        let keypairs = keeping_votes.elgamal_keypairs_by_decade.lock().unwrap();

        let Some(keypair) = keypairs.get(decade_id as usize) else {
            return FinalResultsResponse {
                success: false,
                decade_id,
                results: Vec::new(),
                winner_index: 0,
                winner_movie: String::new(),
                total_votes: 0,
                batch_count: 0,
                status: "No ElGamal keypair found for this decade".to_string(),
            };
        };

        keypair.secret().clone()
    };

    let resolved_winner_index = get_resolved_tie(decade_id);

    let result = tokio::task::spawn_blocking(move || {
        finalize_election_from_blockchain(ballot, decade_id, secret_key, resolved_winner_index)
    })
    .await;

    match result {
        Ok(Ok(response)) => response,

        Ok(Err(error)) => FinalResultsResponse {
            success: false,
            decade_id,
            results: Vec::new(),
            winner_index: 0,
            winner_movie: String::new(),
            total_votes: 0,
            batch_count: 0,
            status: error,
        },

        Err(error) => FinalResultsResponse {
            success: false,
            decade_id,
            results: Vec::new(),
            winner_index: 0,
            winner_movie: String::new(),
            total_votes: 0,
            batch_count: 0,
            status: format!("Finalize task failed: {}", error),
        },
    }
}

// Authentication

// Creates a login challenge message for a wallet.
pub async fn create_auth_challenge(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(payload): Json<ChallengeRequest>,
) -> Json<ChallengeResponse> {
    let message = create_login_message(&payload.public_key);

    {
        let mut challenges = keeping_votes.login_challenges.lock().unwrap();

        challenges.insert(payload.public_key.clone(), message.clone());
    }

    Json(ChallengeResponse {
        public_key: payload.public_key,
        message,
    })
}

// Verifies the wallet login signature.
pub async fn login_with_signature(
    State(keeping_votes): State<Arc<KeepingVotes>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, String> {
    {
        let mut challenges = keeping_votes.login_challenges.lock().unwrap();

        let Some(expected_message) = challenges.get(&payload.public_key) else {
            return Err("No login challenge found for this public key".to_string());
        };

        if expected_message != &payload.message {
            return Err("Login message does not match the current challenge".to_string());
        }

        verify_signature(&payload.public_key, &payload.message, &payload.signature)?;

        challenges.remove(&payload.public_key);
    }

    Ok(Json(LoginResponse {
        authenticated: true,
        public_key: payload.public_key,
    }))
}

// Blockchain state

// Reads the on-chain ballot state for one decade.
pub async fn get_blockchain_ballot(
    Path(decade_id): Path<u8>,
    State(keeping_votes): State<Arc<KeepingVotes>>,
) -> Json<BlockchainBallotResponse> {
    let ballot = {
        let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

        let Some(ballot) = ballots
            .get(decade_id as usize)
            .and_then(|ballot| ballot.as_ref())
            .cloned()
        else {
            return Json(BlockchainBallotResponse {
                success: false,
                decade_id,
                ballot: String::new(),
                merkle_root: String::new(),
                total_votes: 0,
                batch_count: 0,
                encrypted_tally: Vec::new(),
                status: "No on-chain ballot found in API memory. Run /api/admin/create-ballots without restarting the API.".to_string(),
            });
        };

        ballot
    };

    let result =
        tokio::task::spawn_blocking(move || get_ballot_state_from_blockchain(ballot, decade_id))
            .await;

    match result {
        Ok(Ok(response)) => Json(response),

        Ok(Err(error)) => Json(BlockchainBallotResponse {
            success: false,
            decade_id,
            ballot: String::new(),
            merkle_root: String::new(),
            total_votes: 0,
            batch_count: 0,
            encrypted_tally: Vec::new(),
            status: error,
        }),

        Err(_) => Json(BlockchainBallotResponse {
            success: false,
            decade_id,
            ballot: String::new(),
            merkle_root: String::new(),
            total_votes: 0,
            batch_count: 0,
            encrypted_tally: Vec::new(),
            status: "Failed to run blockchain fetch task".to_string(),
        }),
    }
}

// Chairperson status

// Checks whether a public key is the configured chairperson.
pub async fn get_chairperson_status(
    Path(public_key): Path<String>,
) -> Json<ChairpersonStatusResponse> {
    let chairperson_public_key = std::env::var("CHAIRPERSON_PUBLIC_KEY").unwrap_or_default();

    let is_chairperson = !chairperson_public_key.is_empty() && public_key == chairperson_public_key;

    Json(ChairpersonStatusResponse {
        public_key,
        is_chairperson,
    })
}

// Election completion

// Keeps the old election completion endpoint available.
pub async fn get_election_completion() -> Json<ElectionCompletionResponse> {
    Json(ElectionCompletionResponse {
        complete: true,
        eligible_voters: 0,
        completed_voters: 0,
        incomplete_voters: Vec::new(),
    })
}

// Internal helpers

// Checks if a decade already has an on-chain ballot.
fn ballot_exists(keeping_votes: &KeepingVotes, decade_id: u8) -> bool {
    let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

    ballots
        .get(decade_id as usize)
        .and_then(|ballot| ballot.as_ref())
        .is_some()
}

// Checks if all decade ballots exist.
fn all_ballots_exist(keeping_votes: &KeepingVotes) -> bool {
    let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

    ballots.iter().all(|ballot| ballot.is_some())
}

// Checks if a decade is closed.
fn is_decade_closed(decade_id: u8) -> bool {
    let closed = ELECTION_CLOSED_BY_DECADE.lock().unwrap();

    closed.get(decade_id as usize).copied().unwrap_or(false)
}

// Returns the resolved winner for a tied decade.
fn get_resolved_tie(decade_id: u8) -> Option<usize> {
    let resolved_ties = RESOLVED_TIES_BY_DECADE.lock().unwrap();

    resolved_ties.get(decade_id as usize).copied().flatten()
}

// Converts a decade id into a readable label.
fn decade_label(decade_id: u8) -> &'static str {
    match decade_id {
        0 => "1970",
        1 => "1980",
        2 => "1990",
        3 => "2000",
        4 => "2010",
        _ => "2020",
    }
}
