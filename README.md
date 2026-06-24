# HE Profiler

Private company-directory lookup with a BinFHE lookup table.

This demo answers a deliberately small question:

```text
Given a local phone number that maps to a known directory row,
which company code does that row belong to?
```

The client keeps the phone number local. The client sends only
`Enc(directory_code)`. The server evaluates a BinFHE LUT over its company
directory and returns `Enc(company_code)`.

The included directory data is synthetic demo data, not an authoritative
registry.

## Honest Scope

This is not full private search over arbitrary phone numbers.

```text
Supported now:
  Enc(directory_code 0..15) -> BinFHE LUT -> Enc(company_code)

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
  Owns plaintext directory_code for demo/enrollment.
  Creates OpenFHE/BinFHE keys.
  Encrypts directory_code.
  Decrypts company_code response.

server/
  Runs near the company-directory database.
  Owns directory_code -> company_code LUT records.
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
2. Client prepares local phone_number + directory_code rows.
3. Client encrypts directory_code.
4. Client sends Enc(directory_code), context, and eval key.
5. Server computes Enc(directory_code) -> Enc(company_code).
6. Server returns Enc(company_code).
7. Client decrypts company_code and maps it to company_name locally.
8. Plain LUT output and decrypted HE output are compared.
```

Diagram:

```text
ARCHITECTURE_DIAGRAM.md
```

Protocol flow:

```text
PRIVATE_COMPANY_LOOKUP_FLOW.md
```

## Server Data

```text
company_directory
  directory_code
  phone_number_masked
  phone_number_sha256
  company_code
  company_name
  registry_status
```

Server uses this table to build:

```text
directory_code -> company_code LUT
```

The server knows the directory, but it does not see which `directory_code` was
queried when the input is encrypted.

## Code Meaning

Input:

```text
directory_code 0..15
```

Output:

```text
company_code 0..8

0 Unknown
1 Viettel
2 VNPT/VinaPhone
3 MobiFone
4 Vietnamobile
5 Gmobile
6 Hanoi Landline
7 HCMC Landline
8 Other Registered
```

## Send Format

First file-based request shape:

```json
{"request_id":"req-0001","lut_version":"synthetic-v1","ct_directory_code":"<serialized BinFHE ciphertext>"}
```

First file-based response shape:

```json
{"request_id":"req-0001","lut_version":"synthetic-v1","ct_company_code":"<serialized BinFHE ciphertext>"}
```

OpenFHE deployments normally serialize:

```text
crypto context / parameters
public evaluation or bootstrapping key material
ciphertexts
```

The secret key stays on the client.

## Current Scope

```text
Data model: synthetic company directory
Encrypted primitive: BinFHE LUT only
Input domain: directory_code 0..15
Output domain: company_code 0..8
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
