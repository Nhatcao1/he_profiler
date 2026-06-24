# HE Profiler

Phone-prefix organization lookup with a BinFHE lookup table.

This demo answers a deliberately simple question:

```text
Given a phone number, which organization/operator bucket does its prefix map to?
```

The phone number stays on the client side. The client converts it to a tiny
`phone_prefix_code` and encrypts that code. The server runs a BinFHE LUT and
returns an encrypted `organization_code`.

The included prefix data is synthetic demo data, not an authoritative telecom
registry.

## Project Split

```text
client/
  Runs on the data owner machine.
  Owns plaintext phone_number.
  Derives phone_prefix_code 0..15.
  Creates OpenFHE/BinFHE keys.
  Encrypts phone_prefix_code.
  Decrypts organization_code response.

server/
  Runs near the organization-prefix database.
  Owns phone_prefix_code -> organization_code LUT records.
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
1. Server builds phone_org.sqlite with synthetic prefix mappings.
2. Client prepares local phone_number rows.
3. Client converts phone_number -> phone_prefix_code.
4. Client encrypts phone_prefix_code.
5. Server computes Enc(phone_prefix_code) -> Enc(organization_code).
6. Client decrypts organization_code.
7. Plain LUT output and decrypted HE output are compared.
```

Diagram:

```text
ARCHITECTURE_DIAGRAM.md
```

## Code Meaning

Input:

```text
phone_prefix_code 0..15
```

Output:

```text
organization_code 0..7

0 Unknown
1 Viettel
2 VNPT/VinaPhone
3 MobiFone
4 Vietnamobile
5 Gmobile
6 Landline
7 Other Registered
```

## Current Scope

```text
Data model: synthetic phone-prefix organization mapping
Encrypted primitive: BinFHE LUT only
Input domain: phone_prefix_code 0..15
Output domain: organization_code 0..7
No ML
No CKKS
No encrypted joins
No raw phone-number encryption
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
python3 server/src/build_phone_org_db.py \
  --out server/db/phone_org.sqlite \
  --client-inputs client/data/client_inputs.csv
```
