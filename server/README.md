# Server

The server is the company-directory and encrypted-evaluation side.

It owns:

```text
company_directory.sqlite
directory_code -> company_code mappings
BinFHE LUT rules
```

It receives:

```text
request_id
lut_version
encrypted directory_code
BinFHE context/config
BinFHE evaluation key
```

It returns:

```text
request_id
lut_version
encrypted company_code
```

## Database Build

```bash
python3 src/build_company_directory_db.py \
  --out db/company_directory.sqlite \
  --client-inputs ../client/data/client_inputs.csv
```

## Docker Compose

Use Compose for the server side only:

```bash
docker compose -f docker/docker-compose.yml run --rm he-profiler-server
```

## Command

```bash
server/build/run_lut_server \
  --incoming server/incoming \
  --outgoing server/outgoing \
  --request-id req-0001
```
