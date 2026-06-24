# HE Profiler Architecture Diagram

## Flow

```text
Server synthetic prefix data -> phone_org.sqlite
Client phone number -> phone_prefix_code -> BinFHE encryption
Server LUT evaluation -> encrypted organization code
Client decrypts organization code
```

## Mermaid

```mermaid
flowchart TD
    S[synthetic prefix mappings] --> DB[(phone_org.sqlite)]
    DB --> LUT[phone_prefix_code -> organization_code LUT]

    PHONE[phone_number local on client] --> PREFIX[derive phone_prefix_code 0..15]
    PREFIX --> ENC[Client encrypts phone_prefix_code]
    ENC --> CT[Enc phone_prefix_code]

    CT --> EVAL[BinFHE EvalFunc]
    LUT --> EVAL
    EVAL --> OUT[Enc organization_code]
    OUT --> DEC[Client decrypts]
    DEC --> FINAL[organization_code 0..7]
```

## Boundary

```text
Client sends:
  Enc(phone_prefix_code)
  BinFHE context/config
  BinFHE evaluation key
  LUT version

Server returns:
  Enc(organization_code)

Client keeps private:
  secret key
  plaintext phone_number
  plaintext phone_prefix_code
  decrypted organization_code
```

## Codes

```text
organization_code:
  0 Unknown
  1 Viettel
  2 VNPT/VinaPhone
  3 MobiFone
  4 Vietnamobile
  5 Gmobile
  6 Landline
  7 Other Registered
```
