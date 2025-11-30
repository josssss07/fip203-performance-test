#!/usr/bin/env python3
"""
server.py
Supports both ML-KEM (Kyber/ML-KEM family via liboqs) and RSA.

Endpoints provided:
    /public_info                 ML-KEM public info
    /handshake                   ML-KEM handshake
    /public_info_rsa             RSA public key
    /handshake_rsa               RSA handshake
"""

import base64
import time
import json
import os
import csv
from flask import Flask, request, jsonify
import psutil
import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ============================================================
#   Utility
# ============================================================



def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

app = Flask(__name__)

# ============================================================
#   ML-KEM SETUP
# ============================================================

ALG = next((a for a in oqs.get_enabled_kem_mechanisms()
            if "KYBER" in a.upper() or "ML-KEM" in a.upper()), None)

if not ALG:
    raise SystemExit("No Kyber/ML-KEM KEM available via liboqs")

SERVER_CSV = os.environ.get("SERVER_CSV", "server_kem_metrics.csv")

proc = psutil.Process()
cpu_before = proc.cpu_percent(interval=None)
mem_before = proc.memory_info().rss
t0 = time.perf_counter()

with oqs.KeyEncapsulation(ALG) as kem:
    SERVER_KEM_PUBLIC = kem.generate_keypair()
    SERVER_KEM_PRIVATE = kem.export_secret_key()

t1 = time.perf_counter()
cpu_after = proc.cpu_percent(interval=None)
mem_after = proc.memory_info().rss
keygen_time = t1 - t0

# Write server KEM keygen metrics
write_header = not os.path.exists(SERVER_CSV)
with open(SERVER_CSV, "a", newline="") as f:
    writer = csv.writer(f)
    if write_header:
        writer.writerow([
            "Iteration", "timestamp", "event",
            "time_s", "cpu_before", "cpu_after",
            "mem_before", "mem_after",
            "client_ct_bytes", "server_ct_bytes",
            "total_packet_bytes"
        ])
    writer.writerow([
        0, time.time(), "server_kem_keygen",
        f"{keygen_time:.9f}", f"{cpu_before:.2f}", f"{cpu_after:.2f}",
        mem_before, mem_after,
        "", len(SERVER_KEM_PUBLIC), len(SERVER_KEM_PUBLIC)
    ])


# Ed25519 signing key for ML-KEM authentication
SIGN_PRIV = Ed25519PrivateKey.generate()
SIGN_PUB = SIGN_PRIV.public_key()

# ============================================================
#   RSA SETUP
# ============================================================

RSA_CSV = os.environ.get("RSA_CSV", "server_rsa_metrics.csv")

proc = psutil.Process()
cpu_before_rsa = proc.cpu_percent(interval=None)
mem_before_rsa = proc.memory_info().rss
t2 = time.perf_counter()

RSA_SERVER_PRIVATE = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
RSA_SERVER_PUBLIC = RSA_SERVER_PRIVATE.public_key()

t3 = time.perf_counter()
cpu_after_rsa = proc.cpu_percent(interval=None)
mem_after_rsa = proc.memory_info().rss
rsa_keygen_time = t3 - t2

write_header_rsa = not os.path.exists(RSA_CSV)
with open(RSA_CSV, "a", newline="") as f:
    writer = csv.writer(f)
    if write_header_rsa:
        writer.writerow([
            "Iteration", "timestamp", "event",
            "time_s", "cpu_before", "cpu_after",
            "mem_before", "mem_after",
            "ciphertext_bytes"
        ])
    writer.writerow([
        0, time.time(), "server_rsa_keygen",
        f"{rsa_keygen_time:.9f}",
        f"{cpu_before_rsa:.2f}",
        f"{cpu_after_rsa:.2f}",
        mem_before_rsa, mem_after_rsa,
        ""
    ])

# ============================================================
#   ML-KEM ENDPOINTS
# ============================================================

@app.route("/public_info", methods=["GET"])
def public_info():
    sign_pub_bytes = SIGN_PUB.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return jsonify({
        "kem_algorithm": ALG,
        "server_kem_public_b64": b64(SERVER_KEM_PUBLIC),
        "server_sign_public_b64": b64(sign_pub_bytes)
    })


@app.route("/handshake", methods=["POST"])
def handshake():
    try:
        print("DEBUG /handshake received:", request.data, request.json)
        data = request.get_json()

        # Expect the client to send its KEM public key and the ciphertext
        if not data or "client_kem_public_b64" not in data or "client_to_server_ciphertext_b64" not in data:
            return jsonify({"error": "Missing client_kem_public_b64 or client_to_server_ciphertext_b64"}), 400

        client_pk = b64d(data["client_kem_public_b64"])
        ct_c2s = b64d(data["client_to_server_ciphertext_b64"])
        iteration = data.get("iteration", None)

        proc = psutil.Process()
        cpu_before = proc.cpu_percent(interval=None)
        mem_before = proc.memory_info().rss

        # Decap
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(ALG, secret_key=SERVER_KEM_PRIVATE) as kem:
            ss_s = kem.decap_secret(ct_c2s)
        t1 = time.perf_counter()
        decap_time = t1 - t0

        # Encap to client
        t2 = time.perf_counter()
        with oqs.KeyEncapsulation(ALG) as kem:
            ct_s2c, ss_s2c = kem.encap_secret(client_pk)
        t3 = time.perf_counter()
        encap_time = t3 - t2

        cpu_after = proc.cpu_percent(interval=None)
        mem_after = proc.memory_info().rss

        # Sign the two ciphertexts
        to_sign = ct_c2s + ct_s2c
        t4 = time.perf_counter()
        sig = SIGN_PRIV.sign(to_sign)
        t5 = time.perf_counter()
        sign_time = t5 - t4

        client_ct_len = len(ct_c2s)
        server_ct_len = len(ct_s2c)
        total_packet = client_ct_len + server_ct_len

        # Write to CSV
        with open(SERVER_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                iteration, time.time(), "kem_handshake",
                f"{decap_time:.9f}|{encap_time:.9f}|{sign_time:.9f}",
                f"{cpu_before:.2f}", f"{cpu_after:.2f}",
                mem_before, mem_after,
                client_ct_len, server_ct_len, total_packet
            ])

        return jsonify({
            "server_to_client_ciphertext_b64": b64(ct_s2c),
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
            "signature_b64": b64(sig)
        })

    except Exception as e:
        app.logger.exception("Exception in /handshake")
        return jsonify({"error": str(e)}), 400

# ============================================================
#   RSA ENDPOINTS
# ============================================================

@app.route("/public_info_rsa", methods=["GET"])
def public_info_rsa():
    pub_bytes = RSA_SERVER_PUBLIC.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({
        "rsa_public_b64": b64(pub_bytes)
    })


@app.route("/handshake_rsa", methods=["POST"])
def handshake_rsa():
    try:
        data = request.get_json()
        ct = b64d(data["ciphertext_b64"])
        client_pub_pem = b64d(data["client_public_b64"])
        iteration = data.get("iteration", None)

        client_pub = serialization.load_pem_public_key(client_pub_pem)

        proc = psutil.Process()
        cpu_before = proc.cpu_percent(interval=None)
        mem_before = proc.memory_info().rss

        # RSA decrypt (server decap)
        t0 = time.perf_counter()
        plaintext = RSA_SERVER_PRIVATE.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        t1 = time.perf_counter()
        decap_time = t1 - t0

        # RSA encrypt back to client
        t2 = time.perf_counter()
        ct_s2c = client_pub.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        t3 = time.perf_counter()
        encap_time = t3 - t2

        cpu_after = proc.cpu_percent(interval=None)
        mem_after = proc.memory_info().rss

        total_ct = len(ct) + len(ct_s2c)

        # Write to CSV
        with open(RSA_CSV, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                iteration, time.time(), "rsa_handshake",
                f"{decap_time:.9f}|{encap_time:.9f}",
                f"{cpu_before:.2f}", f"{cpu_after:.2f}",
                mem_before, mem_after,
                total_ct
            ])

        return jsonify({
            "ciphertext_b64": b64(ct_s2c),
            "metrics": {
                "decap_time_s": decap_time,
                "encap_time_s": encap_time,
                "cpu_before_percent": cpu_before,
                "cpu_after_percent": cpu_after,
                "mem_before_bytes": mem_before,
                "mem_after_bytes": mem_after,
                "ciphertext_bytes": total_ct
            }
        })

    except Exception as e:
        app.logger.exception("Exception in /handshake_rsa")
        return jsonify({"error": str(e)}), 400


# ============================================================
#   RUN SERVER
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
