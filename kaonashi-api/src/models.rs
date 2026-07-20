use serde::{Deserialize, Serialize};

//votos

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

#[derive(Debug, Deserialize)]
pub struct SubmittedVote {
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
// Resposta enviada ao frontend após submissão do voto.
//
// O backend já não sabe qual foi o filme escolhido,
// por isso movie/movie_index vão vazios/default.
// O frontend preenche esses campos localmente para a UI.
#[derive(Debug, Serialize)]
pub struct SubmitVoteResponse {
    pub accepted: bool,

    pub wallet_id: String,

    pub decade_id: u8,
    pub decade: String,

    pub movie_index: usize,
    pub movie: String,

    pub status: String,

    pub pending_votes: usize,
    pub batch_submitted: bool,
}

// ELGAMAL KEY ENDPOINT

#[derive(Debug, Serialize)]
pub struct ElGamalPublicKeyResponse {
    pub decade_id: u8,
    pub decade: String,

    // Public key ElGamal da ballot/década.
    // O frontend usa isto para cifrar o voto.
    pub public_key: Vec<u8>,
}

// AUTENTICAÇÃO

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub authenticated: bool,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminActionRequest {
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

// BATCHES / MERKLE RECEIPTS

#[derive(Debug, Clone)]
pub struct PendingEncryptedVote {
    pub wallet_id: String,
    pub public_key: String,
    pub decade_id: u8,
    pub encrypted_vote_hash: String,
    pub encrypted_vote: Vec<[u8; 64]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofNodeResponse {
    pub hash: String,
    pub is_left: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VoteReceipt {
    pub vote_hash: String,
    pub leaf_hash: String,
    pub batch_id: String,
    pub decade_id: u8,
    pub leaf_index: usize,
    pub merkle_root: String,
    pub merkle_proof: Vec<MerkleProofNodeResponse>,
}

#[derive(Debug, Serialize)]
pub struct FlushBatchResponse {
    pub success: bool,
    pub decade_id: u8,
    pub batch_id: String,
    pub merkle_root: String,
    pub vote_count: usize,
    pub encrypted_batch_tally: Vec<Vec<u8>>,
    pub receipts: Vec<VoteReceipt>,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct EncryptedVoteBatch {
    pub batch_id: String,
    pub decade_id: u8,
    pub merkle_root: String,
    pub vote_count: usize,
    pub encrypted_batch_tally: Vec<[u8; 64]>,
    pub votes: Vec<PendingEncryptedVote>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyReceiptRequest {
    pub vote_hash: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyReceiptResponse {
    pub vote_hash: String,
    pub verified: bool,
    pub batch_id: String,
    pub merkle_root: String,
    pub status: String,
}

#[derive(Debug, serde::Serialize)]
pub struct BlockchainBallotResponse {
    pub success: bool,
    pub decade_id: u8,
    pub ballot: String,
    pub merkle_root: String,
    pub total_votes: u64,
    pub batch_count: u64,
    pub encrypted_tally: Vec<Vec<u8>>,
    pub status: String,
}
#[derive(Debug, serde::Serialize)]
pub struct FinalResultsResponse {
    pub success: bool,
    pub decade_id: u8,
    pub results: Vec<u32>,
    pub winner_index: usize,
    pub winner_movie: String,
    pub total_votes: u64,
    pub batch_count: u64,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ChairpersonStatusResponse {
    pub public_key: String,
    pub is_chairperson: bool,
}
#[derive(Debug, Serialize)]
pub struct IncompleteVoter {
    pub wallet_id: String,
    pub missing_decades: Vec<u8>,
    pub missing_decade_names: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ElectionCompletionResponse {
    pub complete: bool,
    pub eligible_voters: usize,
    pub completed_voters: usize,
    pub incomplete_voters: Vec<IncompleteVoter>,
}
