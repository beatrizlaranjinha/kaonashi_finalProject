use leptos::ev::MouseEvent;
use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api::client::{close_election, create_ballots, finalize_election, flush_batches};

#[component]
pub fn ChairpersonPage(
    page: RwSignal<&'static str>,
    selected_decade: RwSignal<u8>,
    wallet_id: RwSignal<Option<String>>,
    wallet_address: RwSignal<Option<String>>,
    current_step: RwSignal<u8>,
) -> impl IntoView {
    let submitting = RwSignal::new(false);

    let success_message = RwSignal::new(None::<String>);
    let error_message = RwSignal::new(None::<String>);

    // Number of unresolved ties found during the decrypt/detect step.
    let detected_ties = RwSignal::new(0_usize);

    // Stores the private key only while this page is open.
    let chairperson_secret_key = RwSignal::new(String::new());

    // Gets the chairperson credentials for signed admin actions.
    let credentials = move || {
        let wallet = wallet_id
            .get()
            .ok_or_else(|| "Chairperson wallet is missing.".to_string())?;

        let public_key = wallet_address
            .get()
            .ok_or_else(|| "Chairperson public key is missing.".to_string())?;

        let secret_key = chairperson_secret_key.get().trim().to_string();

        if secret_key.is_empty() {
            return Err("Chairperson private key is missing.".to_string());
        }

        Ok::<_, String>((wallet, public_key, secret_key))
    };

    // Creates all on-chain ballots.
    let create_global_ballots = move |_: MouseEvent| {
        let Ok((_wallet, public_key, secret_key)) = credentials() else {
            error_message.set(Some("Chairperson credentials are missing.".to_string()));
            return;
        };

        submitting.set(true);
        success_message.set(None);
        error_message.set(None);
        detected_ties.set(0);

        spawn_local(async move {
            match create_ballots(public_key, secret_key).await {
                Ok(response) => {
                    success_message.set(Some(response));
                    current_step.set(2);
                }
                Err(error) => error_message.set(Some(error)),
            }

            submitting.set(false);
        });
    };

    // Closes the election when voting is over.
    let close_global_election = move |_: MouseEvent| {
        let Ok((wallet, public_key, secret_key)) = credentials() else {
            error_message.set(Some("Chairperson credentials are missing.".to_string()));
            return;
        };

        submitting.set(true);
        success_message.set(None);
        error_message.set(None);

        spawn_local(async move {
            match close_election(wallet, public_key, secret_key).await {
                Ok(response) => {
                    let closed = response.results.iter().filter(|r| r.success).count();

                    success_message.set(Some(format!(
                        "Election closed across {closed} decade ballot(s)."
                    )));

                    current_step.set(3);
                }
                Err(error) => error_message.set(Some(error)),
            }

            submitting.set(false);
        });
    };

    // Submits all pending batches.
    let submit_all_batches = move |_: MouseEvent| {
        let Ok((wallet, public_key, secret_key)) = credentials() else {
            error_message.set(Some("Chairperson credentials are missing.".to_string()));
            return;
        };

        submitting.set(true);
        success_message.set(None);
        error_message.set(None);

        spawn_local(async move {
            match flush_batches(wallet, public_key, secret_key).await {
                Ok(response) => {
                    success_message.set(Some(format!(
                        "{} batch(es) submitted with {} pending vote(s).",
                        response.total_batches, response.total_votes
                    )));

                    // Next step is decrypting results / detecting ties.
                    current_step.set(4);
                }
                Err(error) => error_message.set(Some(error)),
            }

            submitting.set(false);
        });
    };

    // Opens the tie resolution page.
    let open_tie_resolution = move |_: MouseEvent| {
        if detected_ties.get() == 0 {
            error_message.set(Some(
                "No unresolved ties were detected. Decrypt results first.".to_string(),
            ));
            return;
        }

        leptos::logging::log!("CLICKED RESOLVE TIES");

        success_message.set(None);
        error_message.set(None);

        // When the user comes back from the tie page, the next action is finalizing again.
        current_step.set(6);
        page.set("tie-resolution");
    };

    // Finalizes the election.
    //
    // This function is used twice:
    // 1. Step 04: decrypt results and detect ties.
    // 2. Step 06: after tie resolution, set the final winners on-chain.
    let finalize_global_election = move |_: MouseEvent| {
        let Ok((wallet, public_key, secret_key)) = credentials() else {
            error_message.set(Some("Chairperson credentials are missing.".to_string()));
            return;
        };

        let step_before_finalize = current_step.get();

        submitting.set(true);
        success_message.set(None);
        error_message.set(None);

        spawn_local(async move {
            match finalize_election(wallet, public_key, secret_key).await {
                Ok(response) => {
                    let finalized = response
                        .results
                        .iter()
                        .filter(|result| {
                            result.status == "Finalized" || result.status == "Already finalized"
                        })
                        .count();

                    let ties = response
                        .results
                        .iter()
                        .filter(|result| result.status == "Tie")
                        .count();

                    let no_votes = response
                        .results
                        .iter()
                        .filter(|result| result.status == "NoVotes")
                        .count();

                    let errors = response
                        .results
                        .iter()
                        .filter(|result| {
                            !result.success && result.status != "Tie" && result.status != "NoVotes"
                        })
                        .count();

                    detected_ties.set(ties);

                    if ties > 0 {
                        current_step.set(5);

                        success_message.set(Some(format!(
                            "{finalized} decade ballot(s) finalized. \
                             {ties} tie(s) require resolution. \
                             {no_votes} decade ballot(s) had no votes."
                        )));
                    } else if errors == 0 {
                        current_step.set(7);

                        if step_before_finalize == 6 {
                            success_message.set(Some(format!(
                                "Resolved winners finalized. \
                                 {finalized} decade ballot(s) finalized. \
                                 {no_votes} decade ballot(s) had no votes."
                            )));
                        } else {
                            success_message.set(Some(format!(
                                "{finalized} decade ballot(s) finalized. \
                                 No ties detected. \
                                 {no_votes} decade ballot(s) had no votes."
                            )));
                        }
                    } else {
                        success_message.set(Some(format!(
                            "{finalized} decade ballot(s) finalized. \
                             {ties} tie(s) require resolution. \
                             {no_votes} decade ballot(s) had no votes. \
                             {errors} error(s)."
                        )));
                    }
                }
                Err(error) => error_message.set(Some(error)),
            }

            submitting.set(false);
        });
    };

    // Returns the CSS class for each step.
    let step_class = move |step: u8| {
        if current_step.get() == step {
            "chairperson-step active"
        } else if current_step.get() > step {
            "chairperson-step completed"
        } else {
            "chairperson-step locked"
        }
    };

    view! {
        <section class="chairperson-page">
            <div class="chairperson-container">
                <header class="chairperson-header">
                    <p class="chairperson-kicker">"Chairperson"</p>
                    <h1>"Election control"</h1>
                </header>

                <div class="wallet-login-fields chairperson-actions">
                    <input
                        type="password"
                        placeholder="Chairperson private key"
                        prop:value=move || chairperson_secret_key.get()
                        on:input=move |event| {
                            chairperson_secret_key.set(event_target_value(&event));
                        }
                    />
                </div>

                <div class="chairperson-steps">
                    <article class=move || step_class(1)>
                        <div class="chairperson-step-number">"01"</div>
                        <div class="chairperson-step-content">
                            <button
                                class="chairperson-step-button"
                                disabled=move || submitting.get() || current_step.get() != 1
                                on:click=create_global_ballots
                            >
                                {move || {
                                    if submitting.get() && current_step.get() == 1 {
                                        "Creating..."
                                    } else {
                                        "Create ballots"
                                    }
                                }}
                            </button>
                        </div>
                    </article>

                    <article class=move || step_class(2)>
                        <div class="chairperson-step-number">"02"</div>
                        <div class="chairperson-step-content">
                            <button
                                class="chairperson-step-button"
                                disabled=move || submitting.get() || current_step.get() != 2
                                on:click=close_global_election
                            >
                                {move || {
                                    if submitting.get() && current_step.get() == 2 {
                                        "Closing..."
                                    } else {
                                        "Close election"
                                    }
                                }}
                            </button>
                        </div>
                    </article>

                    <article class=move || step_class(3)>
                        <div class="chairperson-step-number">"03"</div>
                        <div class="chairperson-step-content">
                            <button
                                class="chairperson-step-button"
                                disabled=move || submitting.get() || current_step.get() != 3
                                on:click=submit_all_batches
                            >
                                {move || {
                                    if submitting.get() && current_step.get() == 3 {
                                        "Submitting..."
                                    } else {
                                        "Submit pending batches"
                                    }
                                }}
                            </button>
                        </div>
                    </article>

                    <article class=move || step_class(4)>
                        <div class="chairperson-step-number">"04"</div>
                        <div class="chairperson-step-content">
                            <button
                                class="chairperson-step-button"
                                disabled=move || submitting.get() || current_step.get() != 4
                                on:click=finalize_global_election
                            >
                                {move || {
                                    if submitting.get() && current_step.get() == 4 {
                                        "Decrypting..."
                                    } else {
                                        "Decrypt results"
                                    }
                                }}
                            </button>
                        </div>
                    </article>

                    <article class=move || step_class(5)>
                        <div class="chairperson-step-number">"05"</div>
                        <div class="chairperson-step-content">
                            <button
                                class="chairperson-step-button"
                                disabled=move || {
                                    submitting.get()
                                        || current_step.get() != 5
                                        || detected_ties.get() == 0
                                }
                                on:click=open_tie_resolution
                            >
                                {move || {
                                    let ties = detected_ties.get();

                                    if ties > 0 {
                                        format!("Resolve tied votes ({ties})")
                                    } else {
                                        "Resolve tied votes".to_string()
                                    }
                                }}
                            </button>
                        </div>
                    </article>

                    <article class=move || step_class(6)>
                        <div class="chairperson-step-number">"06"</div>
                        <div class="chairperson-step-content">
                            <button
                                class="chairperson-step-button"
                                disabled=move || submitting.get() || current_step.get() != 6
                                on:click=finalize_global_election
                            >
                                {move || {
                                    if submitting.get() && current_step.get() == 6 {
                                        "Finalizing..."
                                    } else {
                                        "Finalize resolved winners"
                                    }
                                }}
                            </button>
                        </div>
                    </article>
                </div>

                {move || {
                    if current_step.get() >= 7 {
                        view! {
                            <p class="vote-success">
                                "Election workflow completed."
                            </p>
                        }
                        .into_any()
                    } else {
                        view! { <div></div> }.into_any()
                    }
                }}

                {move || {
                    success_message.get().map(|message| {
                        view! { <p class="vote-success">{message}</p> }
                    })
                }}

                {move || {
                    error_message.get().map(|message| {
                        view! { <p class="vote-error">{message}</p> }
                    })
                }}
            </div>
        </section>
    }
}
