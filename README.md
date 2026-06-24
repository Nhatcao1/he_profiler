# HE Profiler

Rule-based risk profiling with a BinFHE lookup-table adjustment.

## Project Split

```text
client/
  Runs on the data owner machine.
  Owns plaintext private client-side transaction signal input.
  Creates OpenFHE/BinFHE keys.
  Encrypts client_signal_code.
  Decrypts adjusted_risk_code response.

server/
  Runs near the risk-assessment database.
  Owns base_risk_code records.
  Receives ciphertext requests and public evaluation material.
  Runs BinFHE LUT evaluation.
  Returns ciphertext responses.
```

Both sides need OpenFHE:

```text
client: OpenFHE for keygen, encryption, decryption, serialization
server: OpenFHE for ciphertext deserialization and EvalFunc LUT calculation
```

## First Demo Shape

```text
1. Server builds risk_assessments.sqlite from CSV data.
2. Client prepares assessment_id + private client_signal_code rows.
3. Client encrypts client_signal_code.
4. Server looks up base_risk_code by assessment_id.
5. Server selects LUT for that base_risk_code.
6. Server computes Enc(client_signal_code) -> Enc(adjusted_risk_code).
7. Client decrypts adjusted_risk_code.
8. Plain LUT output and decrypted HE output are compared.
```

## Current Scope

```text
Risk model: rule-based only
Encrypted primitive: BinFHE LUT only
Input domain: client_signal_code 0..15
Output domain: adjusted_risk_code 0..15
No ML
No CKKS
No encrypted joins
```

## Build Skeletons

Client:

```bash
cmake -S client -B client/build -DHE_PROFILER_WITH_OPENFHE=OFF
cmake --build client/build
```

Server:

```bash
cmake -S server -B server/build -DHE_PROFILER_WITH_OPENFHE=OFF
cmake --build server/build
```

When OpenFHE is installed on the machine/container, switch the flag:

```bash
-DHE_PROFILER_WITH_OPENFHE=ON
```

## Generate Server DB

```bash
python3 server/src/build_risk_db.py \
  --transactions /path/to/transactions.csv \
  --customers /path/to/customers.csv \
  --out server/db/risk_assessments.sqlite \
  --client-inputs client/data/client_inputs.csv \
  --limit 1000
```
