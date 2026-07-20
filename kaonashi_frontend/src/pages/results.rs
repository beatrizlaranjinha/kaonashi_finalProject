use futures::future::join_all;
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api::client::{
    get_results, verify_vote_receipt, ResultsResponse, VerifyReceiptResponse,
};

// ---------------------------------------------------
// Helpers
// ---------------------------------------------------

fn decade_number(decade_id: u8) -> &'static str {
    match decade_id {
        0 => "1970",
        1 => "1980",
        2 => "1990",
        3 => "2000",
        4 => "2010",
        _ => "2020",
    }
}

fn result_title(result: &ResultsResponse) -> String {
    if let Some(final_winner) = result.final_winner.clone() {
        return final_winner;
    }

    if let Some(winner) = result.winner.clone() {
        return winner;
    }

    if result.tie_indices.len() >= 2 {
        return "Tie pending".to_string();
    }

    if result.total_votes == 0 {
        return "No votes yet".to_string();
    }

    "Waiting for final result".to_string()
}

fn result_note(result: &ResultsResponse) -> &'static str {
    if result.final_winner.is_some() {
        "Final winner for this decade."
    } else if result.winner.is_some() {
        "Winner calculated from the current tally."
    } else if result.tie_indices.len() >= 2 {
        "This decade still needs tie resolution."
    } else if result.total_votes == 0 {
        "No confirmed votes were counted yet."
    } else {
        "The result is still being processed."
    }
}

fn result_pill_label(result: &ResultsResponse) -> &'static str {
    if result.final_winner.is_some() {
        "Final"
    } else if result.winner.is_some() {
        "Winner"
    } else if result.tie_indices.len() >= 2 {
        "Tie"
    } else {
        "Pending"
    }
}

fn result_pill_class(result: &ResultsResponse) -> &'static str {
    if result.final_winner.is_some() || result.winner.is_some() {
        "result-pill finalized"
    } else if result.tie_indices.len() >= 2 {
        "result-pill tie"
    } else {
        "result-pill empty"
    }
}

// ---------------------------------------------------
// Results page
// ---------------------------------------------------

#[component]
pub fn ResultsPage(page: RwSignal<&'static str>) -> impl IntoView {
    let _ = page;
    let loading_results = RwSignal::new(true);
    let results_error = RwSignal::new(None::<String>);
    let decade_results = RwSignal::new(Vec::<ResultsResponse>::new());

    let receipt_hash_input = RwSignal::new(String::new());
    let verifying_receipt = RwSignal::new(false);
    let verify_error = RwSignal::new(None::<String>);
    let verify_result = RwSignal::new(None::<VerifyReceiptResponse>);

    // ---------------------------------------------------
    // Load public results
    // ---------------------------------------------------

    let load_results = move || {
        loading_results.set(true);
        results_error.set(None);

        spawn_local(async move {
            let futures = (0_u8..6_u8).map(get_results).collect::<Vec<_>>();
            let responses = join_all(futures).await;

            let mut loaded_results = Vec::new();

            for response in responses {
                match response {
                    Ok(result) => loaded_results.push(result),
                    Err(error) => {
                        results_error.set(Some(error));
                        loading_results.set(false);
                        return;
                    }
                }
            }

            decade_results.set(loaded_results);
            loading_results.set(false);
        });
    };

    Effect::new(move |_| {
        load_results();
    });

    // ---------------------------------------------------
    // Verify vote hash in Merkle tree
    // ---------------------------------------------------

    let verify_receipt = move |_| {
        let vote_hash = receipt_hash_input.get().trim().to_string();

        if vote_hash.is_empty() {
            verify_error.set(Some("Paste your vote hash first.".to_string()));
            verify_result.set(None);
            return;
        }

        verifying_receipt.set(true);
        verify_error.set(None);
        verify_result.set(None);

        spawn_local(async move {
            match verify_vote_receipt(vote_hash).await {
                Ok(result) => verify_result.set(Some(result)),
                Err(error) => verify_error.set(Some(error)),
            }

            verifying_receipt.set(false);
        });
    };

    // ---------------------------------------------------
    // View
    // ---------------------------------------------------

    view! {
        <section class="results-page">
            <div class="results-container">
                <header class="results-hero">
                    <p class="chairperson-kicker">"Results"</p>
                    <h1>"The final cut"</h1>
                    <p class="results-hero-text">
                    </p>
                </header>

                // ---------------------------------------------------
                // Winners
                // ---------------------------------------------------

                <section class="results-block results-winners-block">
                    <div class="results-section-header">
                        <div>
                            <p class="results-section-kicker">"Public tally"</p>
                            <h2>"Winners by decade"</h2>
                        </div>

                        <button
                            class="results-small-button"
                            disabled=move || loading_results.get()
                            on:click=move |_| load_results()
                        >
                            {move || {
                                if loading_results.get() {
                                    "Refreshing..."
                                } else {
                                    "Refresh"
                                }
                            }}
                        </button>
                    </div>

                    {move || {
                        if loading_results.get() {
                            view! {
                                <p class="results-empty-message">
                                    "Loading results..."
                                </p>
                            }
                            .into_any()
                        } else if let Some(error) = results_error.get() {
                            view! {
                                <p class="vote-error">
                                    {error}
                                </p>
                            }
                            .into_any()
                        } else {
                            view! {
                                <div class="results-list">
                                    {decade_results
                                        .get()
                                        .into_iter()
                                        .map(|result| {
                                            let decade_label = format!(
                                                "{}s",
                                                decade_number(result.decade_id),
                                            );
                                            let title = result_title(&result);
                                            let note = result_note(&result);
                                            let pill_label = result_pill_label(&result);
                                            let pill_class = result_pill_class(&result);

                                            view! {
                                                <article class="result-row">
                                                    <div class="result-row-main">
                                                        <span class="result-decade">
                                                            {decade_label}
                                                        </span>

                                                        <h3>{title}</h3>
                                                        <p>{note}</p>
                                                    </div>

                                                    <div class="result-row-meta">
                                                        <span class=pill_class>
                                                            {pill_label}
                                                        </span>

                                                        <div class="result-votes">
                                                            <span>"Votes"</span>
                                                            <strong>{result.total_votes}</strong>
                                                        </div>
                                                    </div>
                                                </article>
                                            }
                                        })
                                        .collect_view()}
                                </div>
                            }
                            .into_any()
                        }
                    }}
                </section>

                // ---------------------------------------------------
                // Merkle verification
                // ---------------------------------------------------

                <section class="results-block results-verification-block">
                    <div class="results-section-header results-section-header-simple">
                        <div>
                            <p class="results-section-kicker">"Merkle proof"</p>
                            <h2>"Verify your vote"</h2>
                        </div>
                    </div>

                    <p class="results-muted">
                    </p>

                    <div class="results-form-row">
                        <input
                            class="results-input"
                            type="text"
                            placeholder="Vote hash"
                            prop:value=move || receipt_hash_input.get()
                            on:input=move |event| {
                                receipt_hash_input.set(event_target_value(&event));
                            }
                        />

                        <button
                            class="submit-vote-btn results-action-button"
                            disabled=move || verifying_receipt.get()
                            on:click=verify_receipt
                        >
                            {move || {
                                if verifying_receipt.get() {
                                    "Verifying..."
                                } else {
                                    "Verify"
                                }
                            }}
                        </button>
                    </div>

                    {move || {
                        verify_error.get().map(|error| {
                            view! {
                                <p class="vote-error">
                                    {error}
                                </p>
                            }
                        })
                    }}

                    {move || {
                        verify_result.get().map(|result| {
                            let pill_class = if result.verified {
                                "result-pill finalized"
                            } else {
                                "result-pill tie"
                            };
                            let pill_label = if result.verified {
                                "Verified"
                            } else {
                                "Not found"
                            };
                            let message = if result.verified {
                                "Your encrypted vote was included in the Merkle tree."
                            } else {
                                "This hash was not found in the Merkle tree."
                            };

                            view! {
                                <article class="verification-result">
                                    <div class="verification-result-main">
                                        <span class=pill_class>{pill_label}</span>
                                        <p>{message}</p>
                                    </div>

                                    <div class="verification-detail-grid">
                                        <div>
                                            <span>"Status"</span>
                                            <strong>{result.status}</strong>
                                        </div>

                                        <div>
                                            <span>"Batch"</span>
                                            <strong>{result.batch_id}</strong>
                                        </div>
                                    </div>

                                    <div class="verification-root">
                                        <span>"Merkle root"</span>
                                        <p class="receipt-code">{result.merkle_root}</p>
                                    </div>
                                </article>
                            }
                        })
                    }}
                </section>
            </div>
        </section>
    }
}
