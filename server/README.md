# Server

The server is the organization-prefix database and encrypted-evaluation side.

It owns:

```text
phone_org.sqlite
phone_prefix_code -> organization_code mappings
organization LUT rules
```

It receives:

```text
encrypted phone_prefix_code
BinFHE context/config
BinFHE evaluation key
lut_version
```

It returns:

```text
encrypted organization_code
```

## Database Build

```bash
python3 src/build_phone_org_db.py \
  --out db/phone_org.sqlite \
  --client-inputs ../client/data/client_inputs.csv
```

## Docker Compose

Use Compose for the server side only:

```bash
docker compose -f docker/docker-compose.yml run --rm he-profiler-server
```
