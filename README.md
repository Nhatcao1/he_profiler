# HE Profiler

Private company-directory lookup with a BinFHE lookup table.

This demo answers a deliberately small question:

```text
Given a local phone number that maps to a known directory row,
which company code does that row belong to?
```

The client keeps the phone number local. The client sends only
`Enc(lookup_slot)`. The server evaluates a BinFHE LUT over its company
directory and returns `Enc(company_code)`.

The included directory data is synthetic demo data, not an authoritative
registry.

## Honest Scope

This is not full private search over arbitrary phone numbers.

```text
Supported now:
  phone_number on client -> local lookup_slot 0..7
  Enc(lookup_slot) -> BinFHE LUT -> Enc(company_code)

Not supported in this tiny demo:
  Enc(full phone number) -> private database search
```

Full private phone-number search would need PIR, PSI, or a much heavier
encrypted equality/search protocol. This project intentionally starts with the
small LUT primitive.

## Project Split

```text
client/
  Runs on the data owner machine.
  Owns plaintext phone_number.
  Creates OpenFHE/BinFHE keys.
  Maps phone_number to a tiny local demo lookup_slot.
  Encrypts lookup_slot.
  Decrypts company_code response.

server/
  Runs near the company-directory database.
  Owns lookup_slot -> company_code LUT records.
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
1. Server builds company_directory.sqlite with synthetic records.
2. Client selects one plaintext phone_number.
3. Client maps phone_number to a local demo lookup_slot.
4. Client encrypts lookup_slot.
5. Client sends Enc(lookup_slot) and eval key material.
6. Server computes Enc(lookup_slot) -> Enc(company_code).
7. Server returns Enc(company_code).
8. Client decrypts company_code and maps it to company_name locally.
```

Diagram:

```text
ARCHITECTURE_DIAGRAM.md
```

Protocol flow:

```text
PRIVATE_COMPANY_LOOKUP_FLOW.md
```

Tailscale transfer notes:

```text
TAILSCALE_TRANSFER.md
```

Server setup:

```text
SERVER_SETUP.md
```

## Server Data

```text
company_directory
  lookup_slot
  phone_number_masked
  phone_number_sha256
  company_code
  company_name
  registry_status
```

Server uses this table to build:

```text
lookup_slot -> company_code LUT
```

The server knows the directory, but it does not see which `lookup_slot` was
queried when the input is encrypted.

## Code Meaning

Input:

```text
lookup_slot 0..7
```

Output:

```text
company_code 0..7

0 Unknown
1 Viettel
2 VNPT/VinaPhone
3 MobiFone
4 Vietnamobile
5 Gmobile
6 Hanoi Landline
7 HCMC Landline
```

## Send Format

First file-based request shape:

```json
{
  "scheme": "BinFHE",
  "flow": "private_company_lookup",
  "context_id": "synthetic-v1",
  "context_params": {
    "paramset": "TOY",
    "method": "GINX",
    "arbitrary_function": true,
    "logQ": 12,
    "ringDim": 1024,
    "time_optimization": false
  },
  "encrypted_input": "lookup_slot",
  "refresh_key_file": "refresh_key.bin",
  "switch_key_file": "switch_key.bin",
  "ciphertext_file": "request_ct.bin"
}
```

First file-based response shape:

```json
{
  "scheme": "BinFHE",
  "flow": "private_company_lookup",
  "context_id": "synthetic-v1",
  "encrypted_output": "company_code",
  "ciphertext_file": "response_ct.bin"
}
```

OpenFHE deployments normally serialize:

```text
crypto context / parameters
public evaluation or bootstrapping key material
ciphertexts
```

This demo recreates the OpenFHE context from `context_params` on both sides
instead of sending `context.bin`.

The secret key stays on the client.

## Current Scope

```text
Data model: synthetic company directory
Encrypted primitive: BinFHE LUT only
Input domain: lookup_slot 0..7
Output domain: company_code 0..7
No ML
No CKKS
No encrypted joins
No raw phone-number encryption
No arbitrary private phone-number search
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
python3 server/src/build_company_directory_db.py \
  --out server/db/company_directory.sqlite \
  --client-inputs client/data/client_inputs.csv
```

## Run Commands

Do this after building both targets with `HE_PROFILER_WITH_OPENFHE=ON`.

Create encrypted client request:

```bash
client/build/encrypt_request \
  --phone-number +84911234567 \
  --outgoing client/outgoing \
  --private client/private
```

This writes `logs/client_encrypt.log`.

Copy or mount `client/outgoing/*` to the server incoming folder, then evaluate:

```bash
server/build/run_lut_server \
  --incoming server/incoming \
  --outgoing server/outgoing
```

This writes `logs/server_eval.log`.

Copy or mount `server/outgoing/response_ct.bin` to `client/incoming/`, then decrypt:

```bash
client/build/decrypt_response \
  --secret-key client/private/secret_key.bin \
  --response-ct client/incoming/response_ct.bin
```

This writes `logs/client_decrypt.log`.
