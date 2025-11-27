# FIPS-203 / KEM Performance Test

This repository provides a client/server test harness to measure post-quantum KEM operations (liboqs) for a FIPS-203 style performance study. The client repeatedly generates KEM keys, encapsulates to the server, sends ciphertexts, and measures keygen/encap/decap times plus CPU/memory. The server decapsulates, encapsulates back, signs the exchange, measures its own timings and packet sizes, and logs metrics to CSV for later analysis.

## Contents

- `server_app.py` — Flask server exposing `GET /public_info` and `POST /handshake`.
- `client.py` — client runner that performs multiple iterations and records metrics.
- `client_metrics.csv` (default) — client-side results (written by `client.py`).
- `server_metrics.csv` (default) — server-side results (written by `server_app.py`).

## Quick Setup

1. Create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Confirm `oqs` and `liboqs` have the KEM mechanisms you intend to test (e.g. Kyber/ML-KEM).

## Running

Run the server (development):

```bash
python3 server_app.py
```

Or run behind `gunicorn` for a more production-like process:

```bash
gunicorn -w 1 -b 0.0.0.0:5000 server_app:app
```

Run the client (default 100 iterations):

```bash
python3 client.py --server http://127.0.0.1:5000 --iterations 100 --out client_metrics.csv
```

To test against a remote server on AWS replace the `--server` URL with your server's public address.

## CSV output schemas

Client CSV (columns):

- `Iteration`: 1-based iteration index
- `timestamp`: epoch timestamp when row was recorded
- `keygen_time_s`: client key generation time (s)
- `keygen_cpu_before`, `keygen_cpu_after`: CPU % around key generation
- `keygen_mem_before`, `keygen_mem_after`: RSS memory around key generation
- `client_encap_s`: encapsulation time (client->server)
- `client_decap_s`: decapsulation time (server->client)
- `cpu_before_pct`, `cpu_after_pct`: CPU % recorded before/after handshake round-trip
- `mem_before_bytes`, `mem_after_bytes`: RSS memory recorded before/after
- `server_decap_s`, `server_encap_s`, `server_sign_s`: server-returned timings
- `server_client_ct_bytes`, `server_server_ct_bytes`, `server_total_packet_bytes`: sizes returned by server
- `final_key_hex`: derived symmetric key (hex) — useful to verify agreement

Server CSV (columns):

- `Iteration`: iteration number received from client (0 for server keygen row)
- `timestamp`: epoch timestamp when row was recorded
- `event`: `server_keygen` or `handshake`
- `time_s`: for `server_keygen` this is keygen time; for `handshake` this is a pipe-delimited `decap|encap|sign` string
- `cpu_before_percent`, `cpu_after_percent`: CPU % around event
- `mem_before_bytes`, `mem_after_bytes`: RSS memory around event
- `client_ct_bytes`, `server_ct_bytes`, `total_packet_bytes`: sizes in bytes

## Notes & Recommendations

- Run client and server on separate machines for accurate network-included measurements.
- For consistent CPU timing, fix CPU frequency scaling or run with a stable governor.
- Use `pandas` or R to aggregate CSV results and compute percentiles (p50/p95/p99).
- The server signs `client_ct || server_ct` with Ed25519; the client currently logs the signature but does not verify it by default — add verification if you require authentication checks.

## AWS Deployment Guidance

- Launch an EC2 instance, install Python and project dependencies in a venv.
- Restrict server access using security groups (limit port 5000 to your client IP or VPC range).
- Run the app with `gunicorn` and optionally place an Application Load Balancer (ALB) in front for TLS termination.
- Store logs/CSV on the instance's EBS or periodically upload to S3 for centralized analysis.

## Next Steps (optional)

- Add AES-GCM payload encryption on the server using the derived key and measure encryption time + ciphertext size.
- Provide an `analyze_metrics.py` that reads both CSVs and prints summary statistics and percentiles.
- Add a `systemd` unit file and `gunicorn` configuration to support repeatable AWS deployments.


