# Client

The client is the data-owner side.

It owns:

```text
phone_number plaintext
phone_prefix_code plaintext
BinFHE secret key
decrypted organization_code
```

It sends:

```text
encrypted phone_prefix_code
BinFHE context/config
BinFHE evaluation key
lut_version
```

It must not send:

```text
secret key
plaintext phone_number
plaintext phone_prefix_code
plaintext organization_code
```

## First Code Targets

```text
encrypt_request
  read client/data/client_inputs.csv
  encrypt phone_prefix_code
  write client/outgoing/encrypted_requests.jsonl

decrypt_response
  read client/incoming/encrypted_responses.jsonl
  decrypt organization_code
  compare with plaintext expected output for demo QA
```
