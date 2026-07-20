use std::str::FromStr;

use solana_sdk::hash::Hash;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer};
use solana_zk_sdk::encryption::elgamal::{ElGamalPubkey, ElGamalSecretKey};

use crate::models::{BlockchainBallotResponse, FinalResultsResponse};
use crate::movies::movies_decades;

use zk_client::crypto::{decrypt_tally, encrypt_values};

use zk_client::solana_client::{
    close_election, connect_localnet, fetch_ballot, initialize_ballot, set_final_winner,
    submit_rollup_batch,
};

// Rollup batches

// Sends one encrypted batch tally to the Solana smart contract.
pub fn submit_rollup_batch_to_blockchain(
    ballot: Pubkey,
    decade_id: u8,
    merkle_root: &str,
    encrypted_batch_tally: Vec<[u8; 64]>,
    batch_size: usize,
) -> Result<(), String> {
    let program = connect_localnet()
        .map_err(|error| format!("Failed to connect to Solana localnet: {}", error))?;

    let merkle_root_hash =
        Hash::from_str(merkle_root).map_err(|error| format!("Invalid Merkle root: {}", error))?;

    submit_rollup_batch(
        &program,
        ballot,
        merkle_root_hash.to_bytes(),
        encrypted_batch_tally,
        batch_size as u64,
    )
    .map_err(|error| format!("Failed to submit rollup batch: {}", error))?;

    println!(
        "Submitted rollup batch on-chain for decade {}. Ballot: {}. Batch size: {}",
        decade_id, ballot, batch_size
    );

    Ok(())
}

// Ballot creation

// Creates one on-chain ballot for each decade.
pub fn create_all_ballots_on_chain(
    elgamal_public_keys_by_decade: Vec<[u8; 32]>,
) -> Result<Vec<(u8, Pubkey)>, String> {
    let program = connect_localnet()
        .map_err(|error| format!("Failed to connect to Solana localnet: {}", error))?;

    let mut created_ballots = Vec::new();

    for decade_id in 0..=5 {
        let movies =
            movies_decades(decade_id).ok_or_else(|| format!("Invalid decade {}", decade_id))?;

        let public_key = elgamal_public_keys_by_decade
            .get(decade_id as usize)
            .ok_or_else(|| format!("Missing ElGamal public key for decade {}", decade_id))?;

        let elgamal_public_key = ElGamalPubkey::try_from(public_key.as_slice())
            .map_err(|_| format!("Invalid ElGamal public key for decade {}", decade_id))?;

        let ballot = Keypair::new();

        // The encrypted tally starts with zero votes for every movie.
        let initial_values = vec![0_u64; movies.len()];
        let initial_encrypted_tally = encrypt_values(&initial_values, &elgamal_public_key);

        initialize_ballot(
            &program,
            &ballot,
            movies,
            *public_key,
            initial_encrypted_tally,
        )
        .map_err(|error| {
            format!(
                "Failed to initialize ballot for decade {}: {}",
                decade_id, error
            )
        })?;

        println!("decade {} -> ballot {}", decade_id, ballot.pubkey());

        created_ballots.push((decade_id, ballot.pubkey()));
    }

    Ok(created_ballots)
}

// Ballot closing

// Closes one on-chain ballot.
pub fn close_ballot_on_chain(ballot: Pubkey, decade_id: u8) -> Result<(), String> {
    let program = connect_localnet()
        .map_err(|error| format!("Failed to connect to Solana localnet: {}", error))?;

    match close_election(&program, ballot) {
        Ok(_) => {
            println!("Election closed on-chain for decade {}", decade_id);
            Ok(())
        }

        Err(error) => {
            let error_text = error.to_string();

            // If the ballot is already closed, we treat it as a successful close.
            if error_text.contains("ElectionNotOpen") || error_text.contains("Election is not open")
            {
                println!(
                    "Election for decade {} was already closed on-chain",
                    decade_id
                );

                Ok(())
            } else {
                Err(format!(
                    "Failed to close election on-chain for decade {}: {}",
                    decade_id, error
                ))
            }
        }
    }
}

// Ballot state

// Fetches the current on-chain state of one ballot.
pub fn get_ballot_state_from_blockchain(
    ballot: Pubkey,
    decade_id: u8,
) -> Result<BlockchainBallotResponse, String> {
    let program = connect_localnet()
        .map_err(|error| format!("Failed to connect to Solana localnet: {}", error))?;

    let ballot_account = fetch_ballot(&program, ballot)
        .map_err(|error| format!("Failed to fetch ballot: {}", error))?;

    Ok(BlockchainBallotResponse {
        success: true,
        decade_id,
        ballot: ballot.to_string(),
        merkle_root: bs58::encode(ballot_account.merkle_root).into_string(),
        total_votes: ballot_account.total_votes,
        batch_count: ballot_account.batch_count,
        encrypted_tally: ballot_account
            .encrypted_tally
            .iter()
            .map(|ciphertext| ciphertext.to_vec())
            .collect(),
        status: "Ballot fetched from blockchain".to_string(),
    })
}

// Election finalization

// Decrypts the on-chain encrypted tally and sets the final winner.
pub fn finalize_election_from_blockchain(
    ballot: Pubkey,
    decade_id: u8,
    secret_key: ElGamalSecretKey,
    resolved_winner_index: Option<usize>,
) -> Result<FinalResultsResponse, String> {
    let movies =
        movies_decades(decade_id).ok_or_else(|| format!("Invalid decade {}", decade_id))?;

    let program = connect_localnet()
        .map_err(|error| format!("Failed to connect to Solana localnet: {}", error))?;

    let ballot_account = fetch_ballot(&program, ballot)
        .map_err(|error| format!("Failed to fetch ballot: {}", error))?;

    let results = decrypt_tally(&ballot_account.encrypted_tally, &secret_key)
        .map_err(|error| format!("Failed to decrypt tally: {}", error))?;

    let decrypted_total_votes: u32 = results.iter().sum();

    if decrypted_total_votes == 0 {
        println!(
            "Election has no votes for decade {}. Results: {:?}",
            decade_id, results
        );

        return Ok(FinalResultsResponse {
            success: false,
            decade_id,
            results,
            winner_index: 0,
            winner_movie: String::new(),
            total_votes: ballot_account.total_votes,
            batch_count: ballot_account.batch_count,
            status: "NoVotes".to_string(),
        });
    }

    let max_votes = results.iter().copied().max().unwrap_or(0);

    let tie_indices = results
        .iter()
        .enumerate()
        .filter_map(|(index, votes)| {
            if *votes == max_votes {
                Some(index)
            } else {
                None
            }
        })
        .collect::<Vec<usize>>();

    let final_winner_index = if tie_indices.len() > 1 {
        match resolved_winner_index {
            // The chairperson already resolved the tie.
            Some(index) if tie_indices.contains(&index) => index,

            // The selected winner is invalid because it is not part of the tie.
            Some(index) => {
                return Ok(FinalResultsResponse {
                    success: false,
                    decade_id,
                    results,
                    winner_index: index,
                    winner_movie: String::new(),
                    total_votes: ballot_account.total_votes,
                    batch_count: ballot_account.batch_count,
                    status: format!(
                        "Resolved winner index {} is not part of the tie {:?}",
                        index, tie_indices
                    ),
                });
            }

            // The frontend must ask the chairperson to resolve the tie.
            None => {
                println!(
                    "Tie detected for decade {}. Tied indices: {:?}. Results: {:?}",
                    decade_id, tie_indices, results
                );

                return Ok(FinalResultsResponse {
                    success: false,
                    decade_id,
                    results,
                    winner_index: 0,
                    winner_movie: String::new(),
                    total_votes: ballot_account.total_votes,
                    batch_count: ballot_account.batch_count,
                    status: "Tie".to_string(),
                });
            }
        }
    } else {
        tie_indices[0]
    };

    let winner_movie = movies
        .get(final_winner_index)
        .ok_or_else(|| "Winner index does not match movie list".to_string())?
        .clone();

    set_final_winner(&program, ballot, final_winner_index as u8)
        .map_err(|error| format!("Failed to set final winner on-chain: {}", error))?;

    println!(
        "Election finalized for decade {}. Winner: {}. Results: {:?}",
        decade_id, winner_movie, results
    );

    Ok(FinalResultsResponse {
        success: true,
        decade_id,
        results,
        winner_index: final_winner_index,
        winner_movie,
        total_votes: ballot_account.total_votes,
        batch_count: ballot_account.batch_count,
        status: "Finalized".to_string(),
    })
}
