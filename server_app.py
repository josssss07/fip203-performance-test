#!/usr/bin/env python3
"""
server.py
- Provides:
  GET  /public_info    -> returns server KEM public key and server signing public key (base64)
  POST /handshake      -> accepts client's public key + ciphertext (client->server)
                         decapsulates, encapsulates back to client, signs server response
- Measures decapsulation/encapsulation times and returns benchmarking metrics
"""

import base64
import time
import json
import os
import csv
from flask import Flask, request, jsonify
import psutil
import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configuration
ALG = next((a for a in oqs.get_enabled_kem_mechanisms() if "KYBER" in a.upper() or "ML-KEM" in a.upper()), None)
if not ALG:
    raise SystemExit("No suitable KEM (Kyber/ML-KEM) available in liboqs")

app = Flask(__name__)

# Server CSV path
SERVER_CSV = os.environ.get("SERVER_CSV", "server_metrics.csv")

# Generate server long-term KEM keypair and signing key on startup
proc = psutil.Process()
server_keygen_cpu_before = proc.cpu_percent(interval=None)
server_keygen_mem_before = proc.memory_info().rss
t0 = time.perf_counter()
with oqs.KeyEncapsulation(ALG) as kem:
    SERVER_PUBLIC_KEY = kem.generate_keypair()
    SERVER_PRIVATE_KEY = kem.export_secret_key()
t1 = time.perf_counter()
server_keygen_cpu_after = proc.cpu_percent(interval=None)
server_keygen_mem_after = proc.memory_info().rss
server_keygen_time = t1 - t0

# Write initial server keygen metrics to CSV (append if exists)
write_header = not os.path.exists(SERVER_CSV)
with open(SERVER_CSV, "a", newline="") as f:
    writer = csv.writer(f)
    if write_header:
        writer.writerow([
            "Iteration",
            "timestamp",
            "event",
            "time_s",
            "cpu_before_percent",
            "cpu_after_percent",
            "mem_before_bytes",
            "mem_after_bytes",
            "client_ct_bytes",
            "server_ct_bytes",
            "total_packet_bytes",
        ])
    writer.writerow([
        0,
        time.time(),
        "server_keygen",
        f"{server_keygen_time:.9f}",
        f"{server_keygen_cpu_before:.2f}",
        f"{server_keygen_cpu_after:.2f}",
        server_keygen_mem_before,
        server_keygen_mem_after,
        "",
        len(SERVER_PUBLIC_KEY),
        len(SERVER_PUBLIC_KEY),
    ])

# Server signing key (Ed25519) for authenticating responses
SIGN_PRIV = Ed25519PrivateKey.generate()
SIGN_PUB = SIGN_PRIV.public_key()

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

@app.route("/public_info", methods=["GET"])
def public_info():
    # Return server public KEM key and server signing pubkey (both base64)
    pub_sign_bytes = SIGN_PUB.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return jsonify({
        "kem_algorithm": ALG,
        "server_kem_public_b64": b64(SERVER_PUBLIC_KEY),
        "server_sign_public_b64": b64(pub_sign_bytes)
    })

@app.route("/handshake", methods=["POST"])
def handshake():
    try:
        data = request.get_json()
        client_pk = b64d(data["client_kem_public_b64"])
        ct_c2s = b64d(data["client_to_server_ciphertext_b64"])
        iteration = data.get("iteration", None)

        proc = psutil.Process()
        cpu_before = proc.cpu_percent(interval=None)
        mem_before = proc.memory_info().rss

        # Decapsulate client's ciphertext (ciphertext was created with server public key)
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(ALG) as kem_server:
            # decapsulate returns shared secret bytes
            ss_server = kem_server.decap_secret(ct_c2s, SERVER_PRIVATE_KEY)
        t1 = time.perf_counter()
        decap_time = t1 - t0

        # Now encapsulate back to client's public key
        t2 = time.perf_counter()
        with oqs.KeyEncapsulation(ALG) as kem_server2:
            ct_s2c, ss_s2c = kem_server2.encap_secret(client_pk)
        t3 = time.perf_counter()
        encap_time = t3 - t2

        cpu_after = proc.cpu_percent(interval=None)
        mem_after = proc.memory_info().rss

        # Create a signature over the concatenation: client_ct || server_ct
        payload = ct_c2s + ct_s2c
        t_sign0 = time.perf_counter()
        sig = SIGN_PRIV.sign(payload)
        t_sign1 = time.perf_counter()
        sign_time = t_sign1 - t_sign0

        # Sizes
        client_ct_len = len(ct_c2s)
        server_ct_len = len(ct_s2c)
        total_packet = client_ct_len + server_ct_len

        # Append metrics to server CSV
        with open(SERVER_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                iteration if iteration is not None else "",
                time.time(),
                "handshake",
                f"{decap_time:.9f}|{encap_time:.9f}|{sign_time:.9f}",
                f"{cpu_before:.2f}",
                f"{cpu_after:.2f}",
                mem_before,
                mem_after,
                client_ct_len,
                server_ct_len,
                total_packet,
            ])

        # Return base64 for safe JSON transport
        return jsonify({
            "server_to_client_ciphertext_b64": base64.b64encode(ct_s2c).decode("ascii"),
            "metrics": {
                "decap_time_s": decap_time,
                "encap_time_s": encap_time,
                "sign_time_s": sign_time,
                "cpu_before_percent": cpu_before,
                "cpu_after_percent": cpu_after,
                "mem_before_bytes": mem_before,
                "mem_after_bytes": mem_after,
                "client_ct_bytes": client_ct_len,
                "server_ct_bytes": server_ct_len,
                "total_packet_bytes": total_packet,
            },
            "signature_b64": base64.b64encode(sig).decode("ascii")
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    # For real deployment: use gunicorn/uvicorn + TLS in front.
    app.run(host="0.0.0.0", port=5000)
