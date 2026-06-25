# Client

The client is the data-owner side.

It owns:

```text
phone_number plaintext
BinFHE secret key
decrypted company_code
displayed company_name
```

It sends:

```text
encrypted lookup_slot
BinFHE context/config
BinFHE evaluation key
```

It must not send:

```text
secret key
plaintext phone_number
plaintext lookup_slot
plaintext company_code
```

## First Code Targets

```text
encrypt_request
  read one --phone-number
  map it to a local demo lookup_slot
  encrypt lookup_slot
  write OpenFHE artifacts under client/outgoing/

decrypt_response
  read client/incoming/response_ct.bin
  decrypt company_code
  print company_code and company_name
```

## Commands

```bash
client/build/encrypt_request \
  --phone-number +84901234567 \
  --outgoing client/outgoing \
  --private client/private
```

After the server writes `response_ct.bin`:

```bash
client/build/decrypt_response \
  --context client/outgoing/context.bin \
  --secret-key client/private/secret_key.bin \
  --response-ct client/incoming/response_ct.bin
```
