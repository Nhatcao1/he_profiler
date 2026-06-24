# HE Profiler Architecture Diagram

## Flow

```text
Server CSV data -> rule-based profiler -> risk_assessments.sqlite
Client signal -> BinFHE encryption -> server LUT evaluation -> encrypted result
Client decrypts final adjusted risk code
```

## Mermaid

```mermaid
flowchart TD
    T[transactions.csv] --> P[Rule-based profiler]
    C[customers.csv] --> P
    P --> DB[(risk_assessments.sqlite)]
    DB --> B[base_risk_code by assessment_id]

    CI[client_inputs.csv] --> AID[assessment_id]
    CI --> SIG[client_signal_code 0..15]
    SIG --> ENC[Client encrypts client_signal_code]
    ENC --> CT[Enc client_signal_code]

    AID --> LOOKUP[Server lookup assessment_id]
    LOOKUP --> B
    B --> SELECT[Select LUT for base_risk_code]
    CT --> EVAL[BinFHE EvalFunc]
    SELECT --> EVAL
    EVAL --> OUT[Enc adjusted_risk_code]
    OUT --> DEC[Client decrypts]
    DEC --> FINAL[adjusted_risk_code 0..15]
```

## Boundary

```text
Client sends:
  assessment_id
  Enc(client_signal_code)
  BinFHE context/config
  BinFHE evaluation key
  LUT version

Server returns:
  Enc(adjusted_risk_code)

Client keeps private:
  secret key
  plaintext client_signal_code
  decrypted adjusted_risk_code
```
