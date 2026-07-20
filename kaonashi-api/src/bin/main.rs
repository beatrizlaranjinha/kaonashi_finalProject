use axum::{
    routing::{get, post},
    Router,
};
use kaonashi_api::{handler, keeping_votes::KeepingVotes};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() {
    // Shared application state used by the API handlers.
    let keeping_votes = Arc::new(KeepingVotes::new());

    // Allows the frontend to call the API during local development.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Defines all API routes.
    let router = Router::new()
        // Basic API route.
        .route("/api/is_running", get(handler::is_running))
        // Voting routes.
        .route("/api/vote", post(handler::submit_vote))
        .route(
            "/api/vote/receipt/{vote_hash}",
            get(handler::get_vote_receipt),
        )
        .route(
            "/api/vote/verify-receipt",
            post(handler::verify_vote_receipt),
        )
        // Movie and result routes.
        .route("/api/movies/{decade_id}", get(handler::get_movies))
        .route("/api/results/{decade_id}", get(handler::get_results))
        .route("/api/winner/{decade_id}", get(handler::get_winner))
        // ElGamal public key route.
        .route(
            "/api/election/{decade_id}/elgamal-public-key",
            get(handler::get_elgamal_public_key),
        )
        // Wallet authentication routes.
        .route("/api/auth/challenge", post(handler::create_auth_challenge))
        .route("/api/auth/login", post(handler::login_with_signature))
        // Chairperson status route.
        .route(
            "/api/chairperson/status/{public_key}",
            get(handler::get_chairperson_status),
        )
        // Chairperson admin routes.
        .route("/api/admin/create-ballots", post(handler::create_ballots))
        .route("/api/admin/close-election", post(handler::close_election))
        .route("/api/admin/flush-batches", post(handler::flush_batches))
        .route(
            "/api/admin/flush-batch/{decade_id}",
            post(handler::flush_batch),
        )
        .route("/api/admin/resolve-tie", post(handler::resolve_tie))
        .route(
            "/api/admin/finalize-election",
            post(handler::finalize_election),
        )
        // Keeps the old finalize-by-decade route available.
        .route(
            "/api/admin/finalize-election/{decade_id}",
            post(handler::finalize_election_for_decade),
        )
        // Blockchain debug route.
        .route(
            "/api/blockchain/ballot/{decade_id}",
            get(handler::get_blockchain_ballot),
        )
        // Election completion route used by the frontend.
        .route(
            "/api/admin/election-completion",
            get(handler::get_election_completion),
        )
        .with_state(keeping_votes)
        .layer(cors);

    // Starts the API server.
    let address = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind API address");

    println!("Kaonashi API running at http://{address}");

    axum::serve(listener, router)
        .await
        .expect("Failed to start API server");
}
