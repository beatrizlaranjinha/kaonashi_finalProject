use crate::blockchain::submit_rollup_batch_to_blockchain;
use crate::keeping_votes::KeepingVotes;
use crate::merkle::{hash_leaf, merkle_proof, merkle_root};
use crate::models::{
    EncryptedVoteBatch, FlushBatchResponse, MerkleProofNodeResponse, PendingEncryptedVote,
    VoteReceipt,
};
use solana_sdk::hash::hashv;
use solana_zk_sdk::encryption::elgamal::ElGamalCiphertext;
use std::time::{Duration, Instant};

pub const MAX_BATCH_SIZE: usize = 10;

// Cria um batch para uma década, se houver votos pendentes.
pub fn create_batch_for_decade(
    keeping_votes: &KeepingVotes,
    decade_id: u8,
) -> Result<Option<FlushBatchResponse>, String> {
    let mut pending_votes = keeping_votes.pending_encrypted_votes.lock().unwrap();

    if pending_votes[decade_id as usize].is_empty() {
        return Ok(None);
    }

    let vote_count = pending_votes[decade_id as usize].len().min(MAX_BATCH_SIZE);

    let votes = pending_votes[decade_id as usize]
        .drain(0..vote_count)
        .collect::<Vec<PendingEncryptedVote>>();

    drop(pending_votes);

    let leaves = votes.iter().map(batch_vote_leaf).collect::<Vec<String>>();

    let encrypted_batch_tally = create_encrypted_batch_tally(&votes)?;

    let tree_start = Instant::now();
    let merkle_root = merkle_root(&leaves)?;
    let tree_build_time = tree_start.elapsed();
    println!("Merkle tree build: {:?}", tree_build_time);

    let batch_index = {
        let batches = keeping_votes.encrypted_vote_batches.lock().unwrap();
        batches[decade_id as usize].len()
    };

    let decade_bytes = [decade_id];
    let batch_index_text = batch_index.to_string();
    let vote_count_text = votes.len().to_string();

    let batch_id = hashv(&[
        b"kaonashi-batch",
        &decade_bytes,
        batch_index_text.as_bytes(),
        merkle_root.as_bytes(),
        vote_count_text.as_bytes(),
    ])
    .to_string();

    let mut receipts = Vec::new();
    let mut total_proof_time = Duration::ZERO;

    for (index, vote) in votes.iter().enumerate() {
        let start = Instant::now();
        let proof = merkle_proof(&leaves, index)?;
        total_proof_time += start.elapsed();

        receipts.push(VoteReceipt {
            vote_hash: vote.encrypted_vote_hash.clone(),
            leaf_hash: leaves[index].clone(),
            batch_id: batch_id.clone(),
            decade_id,
            leaf_index: index,
            merkle_root: merkle_root.clone(),
            merkle_proof: proof
                .into_iter()
                .map(|node| MerkleProofNodeResponse {
                    hash: node.hash,
                    is_left: node.is_left,
                })
                .collect(),
        });
    }

    println!(
        "Average Merkle proof generation: {:?}",
        total_proof_time / receipts.len() as u32
    );

    let mut total_verification_time = Duration::ZERO;
    for receipt in &receipts {
        let proof = receipt
            .merkle_proof
            .iter()
            .map(|node| crate::merkle::MerkleProofNode {
                hash: node.hash.clone(),
                is_left: node.is_left,
            })
            .collect::<Vec<_>>();
        let start = Instant::now();
        let verified =
            crate::merkle::verify_merkle_proof(&receipt.leaf_hash, &proof, &receipt.merkle_root);
        total_verification_time += start.elapsed();
        assert!(verified);
    }
    println!(
        "Average Merkle proof verification: {:?}",
        total_verification_time / receipts.len() as u32
    );

    let batch = EncryptedVoteBatch {
        batch_id: batch_id.clone(),
        decade_id,
        merkle_root: merkle_root.clone(),
        vote_count: votes.len(),
        encrypted_batch_tally: encrypted_batch_tally.clone(),
        votes,
    };

    let mut batches = keeping_votes.encrypted_vote_batches.lock().unwrap();
    batches[decade_id as usize].push(batch);
    drop(batches);

    let mut stored_receipts = keeping_votes.vote_receipts_by_hash.lock().unwrap();

    for receipt in &receipts {
        stored_receipts.insert(receipt.vote_hash.clone(), receipt.clone());
    }

    drop(stored_receipts);

    let ballot_for_chain = {
        let ballots = keeping_votes.ballots_by_decade.lock().unwrap();

        ballots
            .get(decade_id as usize)
            .and_then(|ballot| ballot.as_ref())
            .cloned()
            .ok_or_else(|| {
                "No on-chain ballot found in API memory. Run /api/admin/create-ballots before submitting batches.".to_string()
            })?
    };

    let decade_id_for_chain = decade_id;
    let merkle_root_for_chain = merkle_root.clone();
    let encrypted_tally_for_chain = encrypted_batch_tally.clone();
    let batch_size_for_chain = receipts.len();

    let on_chain_status = match std::thread::spawn(move || {
        submit_rollup_batch_to_blockchain(
            ballot_for_chain,
            decade_id_for_chain,
            &merkle_root_for_chain,
            encrypted_tally_for_chain,
            batch_size_for_chain,
        )
    })
    .join()
    {
        Ok(Ok(_)) => "Encrypted vote batch created and submitted on-chain".to_string(),

        Ok(Err(error)) => format!(
            "Encrypted vote batch created off-chain, but on-chain submission failed: {}",
            error
        ),

        Err(_) => {
            "Encrypted vote batch created off-chain, but on-chain submission panicked".to_string()
        }
    };

    Ok(Some(FlushBatchResponse {
        success: true,
        decade_id,
        batch_id,
        merkle_root,
        vote_count: receipts.len(),
        encrypted_batch_tally: encrypted_batch_tally
            .iter()
            .map(|ciphertext| ciphertext.to_vec())
            .collect(),
        receipts,
        status: on_chain_status,
    }))
}

// Cria a leaf Merkle de um voto cifrado.
pub fn batch_vote_leaf(vote: &PendingEncryptedVote) -> String {
    let mut data = Vec::new();

    data.extend_from_slice(vote.wallet_id.as_bytes());
    data.extend_from_slice(vote.public_key.as_bytes());
    data.push(vote.decade_id);
    data.extend_from_slice(vote.encrypted_vote_hash.as_bytes());

    for ciphertext in &vote.encrypted_vote {
        data.extend_from_slice(ciphertext);
    }

    hash_leaf(&data)
}

fn create_encrypted_batch_tally(votes: &[PendingEncryptedVote]) -> Result<Vec<[u8; 64]>, String> {
    if votes.is_empty() {
        return Err("Cannot create encrypted tally from empty batch".to_string());
    }

    let proposal_count = votes[0].encrypted_vote.len();

    if proposal_count == 0 {
        return Err("Encrypted vote has no proposals".to_string());
    }

    let mut tally = votes[0]
        .encrypted_vote
        .iter()
        .enumerate()
        .map(|(index, ciphertext_bytes)| {
            ElGamalCiphertext::from_bytes(ciphertext_bytes)
                .ok_or_else(|| format!("Invalid ciphertext at vote 0, proposal {}", index))
        })
        .collect::<Result<Vec<ElGamalCiphertext>, String>>()?;

    for (vote_index, vote) in votes.iter().enumerate().skip(1) {
        if vote.encrypted_vote.len() != proposal_count {
            return Err(format!(
                "Vote {} has {} ciphertexts, expected {}",
                vote_index,
                vote.encrypted_vote.len(),
                proposal_count
            ));
        }

        for (proposal_index, ciphertext_bytes) in vote.encrypted_vote.iter().enumerate() {
            let ciphertext = ElGamalCiphertext::from_bytes(ciphertext_bytes).ok_or_else(|| {
                format!(
                    "Invalid ciphertext at vote {}, proposal {}",
                    vote_index, proposal_index
                )
            })?;

            let current = tally[proposal_index];
            tally[proposal_index] = current + ciphertext;
        }
    }

    Ok(tally
        .into_iter()
        .map(|ciphertext| ciphertext.to_bytes())
        .collect())
}
