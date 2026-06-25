# HE Profiler Architecture Diagram

## Flow

```text
Server company directory -> lookup_slot -> company_code LUT
Client phone number stays local
Client sends Enc(lookup_slot)
Server evaluates BinFHE LUT
Client decrypts company_code and maps it to company_name
```

## Mermaid

```mermaid
flowchart TD
    PHONE[phone_number local on client] --> SLOT[lookup_slot local on client]
    SLOT --> ENC[Client encrypts lookup_slot]
    ENC --> CT[Enc lookup_slot]

    DIR[(company_directory.sqlite)] --> LUT[lookup_slot -> company_code LUT]
    CT --> EVAL[BinFHE EvalFunc]
    LUT --> EVAL
    EVAL --> OUT[Enc company_code]
    OUT --> DEC[Client decrypts]
    DEC --> CODE[company_code 0..8]
    CODE --> NAME[company_name local display]
```

## Wire Boundary

```text
Client sends to server:
  Enc(lookup_slot)
  BinFHE context/config
  BinFHE evaluation key

Server returns to client:
  Enc(company_code)
```

## Client Keeps Private

```text
secret key
plaintext phone_number
plaintext lookup_slot
decrypted company_code
displayed company_name
```

## Server Sees

```text
company_directory.sqlite
full lookup_slot -> company_code LUT
encrypted input ciphertext
encrypted output ciphertext
public/evaluation key material
```

The server does not see which directory row was queried because it never sees
plaintext `lookup_slot` or `phone_number`.

## Important Limit

```text
This demo is private LUT evaluation, not full private search.
```

For a real arbitrary phone-number search where the client only has a phone
number and no directory code, use PIR, PSI, or encrypted equality/search.

## Codes

```text
company_code:
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
