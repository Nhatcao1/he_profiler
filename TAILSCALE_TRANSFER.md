# Tailscale Transfer Notes

Server Tailscale IP:

```text
100.84.97.118
```

Use this only as the private network address for moving OpenFHE artifacts and
running commands on the server. The server should never receive the client
secret key.

## Files Sent Client -> Server

Send these from `client/outgoing/`:

```text
context.bin
refresh_key.bin
switch_key.bin
request_ct.bin
request.json
```

Meaning:

```text
context.bin       OpenFHE/BinFHE parameters
refresh_key.bin   bootstrapping refresh key
switch_key.bin    key switching key
request_ct.bin    Enc(directory_code)
request.json      request metadata
```

Do not send:

```text
client/private/secret_key.bin
```

## Files Returned Server -> Client

Return these from `server/outgoing/`:

```text
response_ct.bin
response.json
```

Meaning:

```text
response_ct.bin   Enc(company_code)
response.json     response metadata
```

## Suggested Remote Paths

On the server:

```text
~/he_profiler/server/incoming/
~/he_profiler/server/outgoing/
```

On the client:

```text
client/outgoing/
client/incoming/
client/private/
```

## Transfer Commands

Replace `<server-user>` with the SSH user on the Tailscale server.

Create remote folders:

```bash
ssh <server-user>@100.84.97.118 \
  'mkdir -p ~/he_profiler/server/incoming ~/he_profiler/server/outgoing'
```

Send encrypted request artifacts:

```bash
rsync -av \
  client/outgoing/context.bin \
  client/outgoing/refresh_key.bin \
  client/outgoing/switch_key.bin \
  client/outgoing/request_ct.bin \
  client/outgoing/request.json \
  <server-user>@100.84.97.118:~/he_profiler/server/incoming/
```

Run the server evaluator over SSH:

```bash
ssh <server-user>@100.84.97.118 \
  'cd ~/he_profiler && server/build/run_lut_server \
    --incoming server/incoming \
    --outgoing server/outgoing \
    --request-id req-0001'
```

Fetch encrypted response:

```bash
rsync -av <server-user>@100.84.97.118:~/he_profiler/server/outgoing/response_ct.bin \
  client/incoming/

rsync -av <server-user>@100.84.97.118:~/he_profiler/server/outgoing/response.json \
  client/incoming/
```

Decrypt locally:

```bash
client/build/decrypt_response \
  --context client/outgoing/context.bin \
  --secret-key client/private/secret_key.bin \
  --response-ct client/incoming/response_ct.bin
```

## Full Flow

```bash
client/build/encrypt_request \
  --directory-code 8 \
  --outgoing client/outgoing \
  --private client/private \
  --request-id req-0001

rsync -av \
  client/outgoing/context.bin \
  client/outgoing/refresh_key.bin \
  client/outgoing/switch_key.bin \
  client/outgoing/request_ct.bin \
  client/outgoing/request.json \
  <server-user>@100.84.97.118:~/he_profiler/server/incoming/

ssh <server-user>@100.84.97.118 \
  'cd ~/he_profiler && server/build/run_lut_server \
    --incoming server/incoming \
    --outgoing server/outgoing \
    --request-id req-0001'

rsync -av <server-user>@100.84.97.118:~/he_profiler/server/outgoing/response_ct.bin \
  client/incoming/

rsync -av <server-user>@100.84.97.118:~/he_profiler/server/outgoing/response.json \
  client/incoming/

client/build/decrypt_response \
  --context client/outgoing/context.bin \
  --secret-key client/private/secret_key.bin \
  --response-ct client/incoming/response_ct.bin
```

## Security Checklist

```text
Do send:
  context.bin
  refresh_key.bin
  switch_key.bin
  request_ct.bin
  request.json

Do not send:
  secret_key.bin
  plaintext phone_number
  plaintext directory_code
```

The server can evaluate the encrypted request, but only the client can decrypt
the returned `company_code`.
