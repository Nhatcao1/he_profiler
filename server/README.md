# Server

The server is the database and encrypted-evaluation side.

It owns:

```text
risk_assessments.sqlite
base_risk_code
adjustment LUT rules
```

It receives:

```text
assessment_id
encrypted client_signal_code
BinFHE context/config
BinFHE evaluation key
lut_version
```

It returns:

```text
encrypted adjusted_risk_code
```

## Database Build

```bash
python3 src/build_risk_db.py \
  --transactions ../../utility_bench/data/generated/medium_100k/transactions.csv \
  --customers ../../utility_bench/data/generated/medium_100k/customers.csv \
  --out db/risk_assessments.sqlite \
  --client-inputs ../client/data/client_inputs.csv \
  --limit 1000
```

## Docker Compose

Use Compose for the server side only:

```bash
docker compose -f docker/docker-compose.yml run --rm he-profiler-server
```
