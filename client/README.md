# Client

The client is the data-owner side.

It owns:

```text
client_signal_code plaintext
BinFHE secret key
decrypted adjusted_risk_code
```

It sends:

```text
assessment_id
encrypted client_signal_code
BinFHE context/config
BinFHE evaluation key
lut_version
```

It must not send:

```text
secret key
plaintext client_signal_code
plaintext adjusted_risk_code
```

## First Code Targets

```text
encrypt_request
  read client/data/client_inputs.csv
  encrypt client_signal_code
  write client/outgoing/encrypted_requests.jsonl

decrypt_response
  read client/incoming/encrypted_responses.jsonl
  decrypt adjusted_risk_code
  compare with plaintext expected output for demo QA
```
