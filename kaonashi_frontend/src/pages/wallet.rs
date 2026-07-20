use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api::client::get_chairperson_status;

#[component]
pub fn WalletPage(
    page: RwSignal<&'static str>,
    logged_wallet_id: RwSignal<Option<String>>,
    logged_wallet_address: RwSignal<Option<String>>,
) -> impl IntoView {
    let wallet_id = RwSignal::new(String::new());
    let public_key = RwSignal::new(String::new());

    let error = RwSignal::new(None::<String>);
    let checking_wallet = RwSignal::new(false);

    let connect_wallet = move |_| {
        let id = wallet_id.get().trim().to_string();
        let key = public_key.get().trim().to_string();

        if id.is_empty() || key.is_empty() {
            error.set(Some("Enter the wallet ID and public key.".to_string()));
            return;
        }

        checking_wallet.set(true);
        error.set(None);

        spawn_local(async move {
            match get_chairperson_status(key.clone()).await {
                Ok(status) => {
                    logged_wallet_id.set(Some(id));
                    logged_wallet_address.set(Some(key));

                    if status.is_chairperson {
                        page.set("chairperson");
                    } else {
                        page.set("decades");
                    }
                }
                Err(api_error) => {
                    error.set(Some(api_error));
                }
            }

            checking_wallet.set(false);
        });
    };

    view! {
        <section class="wallet-login-page">
            <div class="wallet-login-card">
                <p class="wallet-login-kicker">
                    "Kaonashi"
                </p>

                <h1>
                    "Connect wallet to start voting"
                </h1>

                <p class="wallet-login-description">

                </p>

                <div class="wallet-login-divider"></div>

                <div class="wallet-login-fields">
                    <input
                        type="text"
                        placeholder="Wallet ID"
                        prop:value=move || wallet_id.get()
                        on:input=move |event| {
                            wallet_id.set(event_target_value(&event));
                        }
                    />

                    <input
                        type="text"
                        placeholder="Solana public key"
                        prop:value=move || public_key.get()
                        on:input=move |event| {
                            public_key.set(event_target_value(&event));
                        }
                    />
                </div>

                {move || {
                    error.get().map(|message| {
                        view! {
                            <p class="wallet-login-error">
                                {message}
                            </p>
                        }
                    })
                }}

                <button
                    class="wallet-signin-button"
                    disabled=move || checking_wallet.get()
                    on:click=connect_wallet
                >
                    {move || {
                        if checking_wallet.get() {
                            "Checking wallet..."
                        } else {
                            "Continue to voting"
                        }
                    }}
                </button>
                <p class="wallet-login-note">

                </p>
            </div>
        </section>
    }
}
