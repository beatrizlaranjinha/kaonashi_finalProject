
Kaonashi Final Project


How to run :

1. Start Solana local validator

```bash
cd kaonashi-smart-contract
solana-test-validator --reset
```
Keep this terminal running.

2. Build and deploy the smart contract

```bash
cd kaonashi-smart-contract
anchor build
anchor deploy
```
3. Start the API

```bash
cd kaonashi-api
cargo run --bin main
```

4. Start the frontend

```bash
cd kaonashi_frontend
trunk serve --open
```


