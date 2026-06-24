# Client

The client is the data-owner side.

It owns:

```text
phone_number plaintext
directory_code plaintext
BinFHE secret key
decrypted company_code
displayed company_name
```

It sends:

```text
request_id
lut_version
encrypted directory_code
BinFHE context/config
BinFHE evaluation key
```

It must not send:

```text
secret key
plaintext phone_number
plaintext directory_code
plaintext company_code
```

## First Code Targets

```text
encrypt_request
  read client/data/client_inputs.csv
  encrypt directory_code
  write client/outgoing/encrypted_requests.jsonl

decrypt_response
  read client/incoming/encrypted_responses.jsonl
  decrypt company_code
  compare with plaintext expected output for demo QA
```

## Commands

```bash
client/build/encrypt_request \
  --directory-code 8 \
  --outgoing client/outgoing \
  --private client/private \
  --request-id req-0001
```

After the server writes `response_ct.bin`:

```bash
client/build/decrypt_response \
  --context client/outgoing/context.bin \
  --secret-key client/private/secret_key.bin \
  --response-ct client/incoming/response_ct.bin
```
