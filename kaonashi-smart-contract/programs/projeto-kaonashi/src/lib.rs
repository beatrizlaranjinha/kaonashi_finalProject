use anchor_lang::prelude::*;

pub mod crypto;
pub mod election;
pub mod proofs;
pub mod rollups;

use crypto::{encrypted_tally_after_vote, validate_ciphertexts, validate_public_key};
use election::ELECTION_OPEN;
use proofs::verify_encrypted_vote_proofs;

declare_id!("4ybufDXMBSQpQ6kxGqEud9afLC9ayoN925Fk6SkAJxx7");

pub const MAX_PROPOSALS: usize = 8;
pub const MAX_PROPOSAL_NAME: usize = 64;

pub const NO_FINAL_WINNER: u8 = u8::MAX;
pub const NO_VOTE: u8 = u8::MAX;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VoteProof {
    pub a0: [u8; 32],
    pub b0: [u8; 32],
    pub c0: [u8; 32],
    pub s0: [u8; 32],

    pub a1: [u8; 32],
    pub b1: [u8; 32],
    pub c1: [u8; 32],
    pub s1: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VoteSumProof {
    pub a: [u8; 32],
    pub b: [u8; 32],
    pub c: [u8; 32],
    pub s: [u8; 32],
}

#[program]
pub mod projeto_kaonashi {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        proposals: Vec<String>,
        public_key: [u8; 32],
        initial_encrypted_tally: Vec<[u8; 64]>,
    ) -> Result<()> {
        validate_initial_ballot(&proposals, &public_key, &initial_encrypted_tally)?;

        ctx.accounts.ballot.initialize(
            ctx.accounts.chairperson.key(),
            proposals,
            public_key,
            initial_encrypted_tally,
        );

        Ok(())
    }

    pub fn register_voter(ctx: Context<RegisterVoter>) -> Result<()> {
        ctx.accounts
            .voter_record
            .initialize(ctx.accounts.voter.key());

        Ok(())
    }

    pub fn cast_vote(
        ctx: Context<CastVote>,
        vote_index: u8,
        encrypted_vote: Vec<[u8; 64]>,
        vote_proofs: Vec<VoteProof>,
        vote_sum_proof: VoteSumProof,
    ) -> Result<()> {
        validate_cast_vote(
            &ctx.accounts.ballot,
            &ctx.accounts.voter_record,
            vote_index,
            &encrypted_vote,
            &vote_proofs,
            &vote_sum_proof,
        )?;

        let updated_tally =
            encrypted_tally_after_vote(&ctx.accounts.ballot.encrypted_tally, &encrypted_vote)?;

        ctx.accounts.ballot.encrypted_tally = updated_tally;
        ctx.accounts.voter_record.mark_as_voted(vote_index);

        Ok(())
    }

    pub fn submit_rollup_batch(
        ctx: Context<SubmitRollupBatchAccounts>,
        new_merkle_root: [u8; 32],
        encrypted_batch_tally: Vec<[u8; 64]>,
        batch_size: u64,
    ) -> Result<()> {
        rollups::submit_rollup_batch(ctx, new_merkle_root, encrypted_batch_tally, batch_size)
    }

    pub fn close_election(ctx: Context<ManageElection>) -> Result<()> {
        election::close(&mut ctx.accounts.ballot)
    }

    pub fn set_final_winner(ctx: Context<SetFinalWinner>, winner_index: u8) -> Result<()> {
        election::finalize(&mut ctx.accounts.ballot, winner_index)
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = chairperson,
        space = 8 + Ballot::INIT_SPACE
    )]
    pub ballot: Account<'info, Ballot>,

    #[account(mut)]
    pub chairperson: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterVoter<'info> {
    #[account(
        mut,
        has_one = chairperson
    )]
    pub ballot: Account<'info, Ballot>,

    #[account(mut)]
    pub chairperson: Signer<'info>,

    /// CHECK: Used only to obtain the voter's public key.
    pub voter: UncheckedAccount<'info>,

    #[account(
        init,
        payer = chairperson,
        space = 8 + VoterRecord::INIT_SPACE,
        seeds = [
            b"voter",
            ballot.key().as_ref(),
            voter.key().as_ref()
        ],
        bump
    )]
    pub voter_record: Account<'info, VoterRecord>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CastVote<'info> {
    #[account(mut)]
    pub ballot: Account<'info, Ballot>,

    #[account(
        mut,
        seeds = [
            b"voter",
            ballot.key().as_ref(),
            voter.key().as_ref()
        ],
        bump
    )]
    pub voter_record: Account<'info, VoterRecord>,

    pub voter: Signer<'info>,
}

#[derive(Accounts)]
pub struct SubmitRollupBatchAccounts<'info> {
    #[account(
        mut,
        has_one = chairperson
    )]
    pub ballot: Account<'info, Ballot>,

    pub chairperson: Signer<'info>,
}

#[derive(Accounts)]
pub struct ManageElection<'info> {
    #[account(
        mut,
        has_one = chairperson
    )]
    pub ballot: Account<'info, Ballot>,

    pub chairperson: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetFinalWinner<'info> {
    #[account(
        mut,
        has_one = chairperson
    )]
    pub ballot: Account<'info, Ballot>,

    pub chairperson: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct Ballot {
    pub chairperson: Pubkey,

    pub public_key: [u8; 32],

    #[max_len(8, 64)]
    pub proposals: Vec<String>,

    #[max_len(8)]
    pub encrypted_tally: Vec<[u8; 64]>,

    pub proposal_count: u8,

    pub final_winner_index: u8,

    pub status: u8,

    pub merkle_root: [u8; 32],

    pub total_votes: u64,

    pub batch_count: u64,
}

impl Ballot {
    pub fn initialize(
        &mut self,
        chairperson: Pubkey,
        proposals: Vec<String>,
        public_key: [u8; 32],
        encrypted_tally: Vec<[u8; 64]>,
    ) {
        self.chairperson = chairperson;
        self.public_key = public_key;
        self.proposal_count = proposals.len() as u8;
        self.proposals = proposals;
        self.encrypted_tally = encrypted_tally;
        self.final_winner_index = NO_FINAL_WINNER;
        self.status = ELECTION_OPEN;
        self.merkle_root = [0u8; 32];
        self.total_votes = 0;
        self.batch_count = 0;
    }

    pub fn is_valid_proposal_index(&self, proposal_index: u8) -> bool {
        proposal_index < self.proposal_count
    }
}

#[account]
#[derive(InitSpace)]
pub struct VoterRecord {
    pub voter: Pubkey,
    pub can_vote: bool,
    pub has_voted: bool,
    pub vote: u8,
}

impl VoterRecord {
    pub fn initialize(&mut self, voter: Pubkey) {
        self.voter = voter;
        self.can_vote = true;
        self.has_voted = false;
        self.vote = NO_VOTE;
    }

    pub fn mark_as_voted(&mut self, vote_index: u8) {
        self.has_voted = true;
        self.vote = vote_index;
    }
}

fn validate_initial_ballot(
    proposals: &[String],
    public_key: &[u8; 32],
    initial_encrypted_tally: &[[u8; 64]],
) -> Result<()> {
    validate_proposals(proposals)?;
    validate_public_key(public_key)?;
    validate_tally_size(proposals.len(), initial_encrypted_tally.len())?;
    validate_ciphertexts(initial_encrypted_tally)
}

fn validate_cast_vote(
    ballot: &Ballot,
    voter_record: &VoterRecord,
    vote_index: u8,
    encrypted_vote: &[[u8; 64]],
    vote_proofs: &[VoteProof],
    vote_sum_proof: &VoteSumProof,
) -> Result<()> {
    election::ensure_open(ballot)?;

    require!(voter_record.can_vote, ErrorCode::NotAllowedToVote);

    require!(!voter_record.has_voted, ErrorCode::AlreadyVoted);

    require!(
        ballot.is_valid_proposal_index(vote_index),
        ErrorCode::InvalidProposalIndex
    );

    validate_tally_size(ballot.proposal_count as usize, encrypted_vote.len())?;

    validate_ciphertexts(encrypted_vote)?;

    verify_encrypted_vote_proofs(
        &ballot.public_key,
        encrypted_vote,
        vote_proofs,
        vote_sum_proof,
    )
    .map_err(|verification_error| {
        msg!(
            "Encrypted vote proof verification failed: {}",
            verification_error
        );

        error!(ErrorCode::InvalidVoteProof)
    })?;

    Ok(())
}

fn validate_proposals(proposals: &[String]) -> Result<()> {
    require!(
        !proposals.is_empty() && proposals.len() <= MAX_PROPOSALS,
        ErrorCode::InvalidProposalCount
    );

    require!(
        proposals
            .iter()
            .all(|proposal| proposal.as_bytes().len() <= MAX_PROPOSAL_NAME),
        ErrorCode::ProposalNameTooLong
    );

    Ok(())
}

fn validate_tally_size(expected: usize, actual: usize) -> Result<()> {
    require!(expected == actual, ErrorCode::InvalidTallySize);
    Ok(())
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid ciphertext")]
    InvalidCiphertext,

    #[msg("Invalid public key")]
    InvalidPublicKey,

    #[msg("Invalid number of proposals")]
    InvalidProposalCount,

    #[msg("Proposal name too long")]
    ProposalNameTooLong,

    #[msg("Encrypted tally size must match number of proposals")]
    InvalidTallySize,

    #[msg("Voter is not allowed to vote")]
    NotAllowedToVote,

    #[msg("Voter has already voted")]
    AlreadyVoted,

    #[msg("Invalid proposal index")]
    InvalidProposalIndex,

    #[msg("Invalid vote proof")]
    InvalidVoteProof,

    #[msg("Invalid vote sum proof")]
    InvalidVoteSumProof,

    #[msg("Math overflow")]
    MathOverflow,

    #[msg("Invalid batch size")]
    InvalidBatchSize,

    #[msg("Election is closed")]
    ElectionClosed,

    #[msg("Election is not open")]
    ElectionNotOpen,

    #[msg("Election must be closed first")]
    ElectionNotClosed,

    #[msg("Final winner has already been set")]
    WinnerAlreadySet,
}
