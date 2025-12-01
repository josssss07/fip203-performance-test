"""
client.py
Supports:
    --mode kem     → Run ML-KEM handshake benchmark
    --mode rsa     → Run RSA handshake benchmark

Each writes to its own CSV file.
"""

import argparse
import base64
import time
import csv
import os
import requests
import psutil
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
DEFAULT_ITERATIONS = 50

KEM_CSV = os.environ.get("KEM_CSV", "client_kem_metrics.csv")
RSA_CSV = os.environ.get("RSA_CSV", "client_rsa_metrics.csv")

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

# ============================================================
#   ML-KEM Route
# ============================================================

def derive_key(k1: bytes, k2: bytes):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"mutual-kem-v1"
    )
    return hkdf.derive(k1 + k2)

def run_kem_once(info, iteration, session, server_url):
    ALG = info["kem_algorithm"]
    server_pub = b64d(info["server_kem_public_b64"])

    proc = psutil.Process()

    # Client KEM keypair
    cpu_before = proc.cpu_percent(interval=None)
    mem_before = proc.memory_info().rss
    t0 = time.perf_counter()
    with oqs.KeyEncapsulation(ALG) as kem:
        client_pub = kem.generate_keypair()
        client_priv = kem.export_secret_key()
    t1 = time.perf_counter()
    keygen_time = t1 - t0
    cpu_after = proc.cpu_percent(interval=None)
    mem_after = proc.memory_info().rss

    # Encap → server
    t2 = time.perf_counter()
    with oqs.KeyEncapsulation(ALG) as kem:
        ct_c2s, ss_c2s = kem.encap_secret(server_pub)
    t3 = time.perf_counter()
    encap_time = t3 - t2

    payload = {
        "client_kem_public_b64": b64(client_pub),
        "client_to_server_ciphertext_b64": b64(ct_c2s),
        "iteration": iteration
    }

    resp = session.post(f"{server_url}/handshake", json=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"/handshake HTTP {resp.status_code}: {resp.text}")
    r = resp.json()

    ct_s2c = b64d(r["server_to_client_ciphertext_b64"])
    server_metrics = r["metrics"]

    # Decap
    t4 = time.perf_counter()
    with oqs.KeyEncapsulation(ALG, secret_key=client_priv) as kem:
        ss_s2c = kem.decap_secret(ct_s2c)
    t5 = time.perf_counter()
    decap_time = t5 - t4

    final_key = derive_key(ss_c2s, ss_s2c)

    return {
        "keygen_s": keygen_time,
        "encap_s": encap_time,
        "decap_s": decap_time,
        "server": server_metrics,
        "final_key": final_key.hex()
    }

# ============================================================
#   RSA Route
# ============================================================

def run_rsa_once(info, iteration, session, server_url):
    rsa_pub = serialization.load_pem_public_key(
        b64d(info["rsa_public_b64"])
    )

    proc = psutil.Process()

    # Generate RSA client keypair
    cpu_before = proc.cpu_percent(interval=None)
    mem_before = proc.memory_info().rss
    t0 = time.perf_counter()
    client_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_pub = client_priv.public_key()
    t1 = time.perf_counter()
    keygen_s = t1 - t0
    cpu_after = proc.cpu_percent(interval=None)
    mem_after = proc.memory_info().rss

    # Encrypt → server
    message = b"rsa-client-test"
    t2 = time.perf_counter()
    ct = rsa_pub.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t3 = time.perf_counter()
    enc_s = t3 - t2

    pub_bytes = client_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    payload = {
        "ciphertext_b64": b64(ct),
        "client_public_b64": b64(pub_bytes),
        "iteration": iteration
    }

    resp = session.post(f"{server_url}/handshake_rsa", json=payload)
    if resp.status_code != 200:
        raise RuntimeError(f"/handshake_rsa HTTP {resp.status_code}: {resp.text}")
    r = resp.json()

    ct2 = b64d(r["ciphertext_b64"])

    # Decrypt → client
    t4 = time.perf_counter()
    pt = client_priv.decrypt(
        ct2,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t5 = time.perf_counter()
    dec_s = t5 - t4

    return {
        "keygen_s": keygen_s,
        "enc_s": enc_s,
        "dec_s": dec_s,
        "server": r["metrics"]
    }

# ============================================================
#   MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default=SERVER_URL)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--mode", choices=["kem", "rsa"], required=True)
    args = parser.parse_args()

    session = requests.Session()

    if args.mode == "kem":
        info_resp = session.get(f"{args.server}/public_info")
        info_resp.raise_for_status()
        info = info_resp.json()

        # CSV header
        write_header = not os.path.exists(KEM_CSV)
        if write_header:
            with open(KEM_CSV, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Iteration", "timestamp",
                    "client_keygen_s", "client_enc_s", "client_dec_s",
                    "server_enc_s", "server_dec_s", "server_sign_s",
                    "final_key_hex"
                ])

        for i in range(1, args.iterations + 1):
            out = run_kem_once(info, i, session, args.server)
            s = out["server"]

            with open(KEM_CSV, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    i, time.time(),
                    f"{out['keygen_s']:.9f}",
                    f"{out['encap_s']:.9f}",
                    f"{out['decap_s']:.9f}",
                    f"{s['encap_time_s']:.9f}",
                    f"{s['decap_time_s']:.9f}",
                    f"{s['sign_time_s']:.9f}",
                    out["final_key"]
                ])

            print(f"[KEM] {i:03d}  C_enc={out['encap_s']:.6f}s   C_dec={out['decap_s']:.6f}s")

    # =======================================================
    #   RSA MODE
    # =======================================================

    else:
        info_resp = session.get(f"{args.server}/public_info_rsa")
        info_resp.raise_for_status()
        info = info_resp.json()

        write_header_rsa = not os.path.exists(RSA_CSV)
        if write_header_rsa:
            with open(RSA_CSV, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Iteration", "timestamp",
                    "client_keygen_s", "client_enc_s", "client_dec_s",
                    "server_enc_s", "server_dec_s",
                    "ciphertext_bytes"
                ])

        for i in range(1, args.iterations + 1):
            out = run_rsa_once(info, i, session, args.server)
            s = out["server"]

            with open(RSA_CSV, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    i, time.time(),
                    f"{out['keygen_s']:.9f}",
                    f"{out['enc_s']:.9f}",
                    f"{out['dec_s']:.9f}",
                    f"{s['encap_time_s']:.9f}",
                    f"{s['decap_time_s']:.9f}",
                    s["ciphertext_bytes"]
                ])

            print(f"[RSA] {i:03d}  C_enc={out['enc_s']:.6f}s   C_dec={out['dec_s']:.6f}s")


if __name__ == "__main__":
    main()
