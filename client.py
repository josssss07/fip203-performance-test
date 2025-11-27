"""
client.py
- Fetches server info, does a mutual KEM handshake:
  1) client encapsulates to server public key -> ciphertext_c2s, ss_c2s
  2) client sends its KEM public key + ciphertext_c2s to server (/handshake)
  3) server decapsulates, encapsulates back to client, signs response
  4) client decapsulates server ciphertext -> ss_s2c
  5) Both sides can derive final symmetric key: HKDF(ss_c2s || ss_s2c || context)
- Records benchmark metrics (client encap time, client decap time, plus server metrics returned)
"""

import argparse
import base64
import time
import csv
import os
import requests
import psutil
import statistics
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
DEFAULT_ITERATIONS = 100
CLIENT_CSV = os.environ.get("CLIENT_CSV", "client_metrics.csv")

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def derive_final_key(ss1: bytes, ss2: bytes, info=b"mutual-kem-v1"):
    # Derive a final symmetric key from both shared secrets
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(ss1 + ss2)

def run_once(server_info, iteration, session: requests.Session):
    ALG = server_info["kem_algorithm"]
    server_kem_pub = b64d(server_info["server_kem_public_b64"])
    server_sign_pub = b64d(server_info["server_sign_public_b64"])

    proc = psutil.Process()

    # Measure client key generation
    cpu_k_gen_before = proc.cpu_percent(interval=None)
    mem_k_gen_before = proc.memory_info().rss
    tkg0 = time.perf_counter()
    with oqs.KeyEncapsulation(ALG) as kem_client:
        client_pub = kem_client.generate_keypair()
        client_priv = kem_client.export_secret_key()
    tkg1 = time.perf_counter()
    keygen_time = tkg1 - tkg0
    cpu_k_gen_after = proc.cpu_percent(interval=None)
    mem_k_gen_after = proc.memory_info().rss

    # Client encapsulates to server public key (client->server)
    t0 = time.perf_counter()
    with oqs.KeyEncapsulation(ALG) as kem_enc:
        ct_c2s, ss_c2s = kem_enc.encap_secret(server_kem_pub)
    t1 = time.perf_counter()
    client_encap_time = t1 - t0

    # Send client's public key + ciphertext to server (include iteration)
    payload = {
        "client_kem_public_b64": b64(client_pub),
        "client_to_server_ciphertext_b64": b64(ct_c2s),
        "iteration": iteration
    }

    # Record cpu/mem before sending (for total round-trip measurement)
    cpu_before = proc.cpu_percent(interval=None)
    mem_before = proc.memory_info().rss

    resp = session.post(f"{SERVER_URL}/handshake", json=payload)
    resp.raise_for_status()
    server_resp = resp.json()

    # Parse server response
    ct_s2c = b64d(server_resp["server_to_client_ciphertext_b64"])
    server_metrics = server_resp.get("metrics", {})
    server_signature = b64d(server_resp.get("signature_b64", "")) if server_resp.get("signature_b64") else b""

    # Client decapsulates server->client ciphertext (measure time and memory)
    t2 = time.perf_counter()
    with oqs.KeyEncapsulation(ALG) as kem_dec:
        ss_s2c = kem_dec.decap_secret(ct_s2c, client_priv)
    t3 = time.perf_counter()
    client_decap_time = t3 - t2
    cpu_after = proc.cpu_percent(interval=None)
    mem_after = proc.memory_info().rss

    # Derive final symmetric key (for usage)
    final_key = derive_final_key(ss_c2s, ss_s2c)

    # Return all metrics and derived key (for demonstration)
    return {
        "keygen_time_s": keygen_time,
        "keygen_cpu_before": cpu_k_gen_before,
        "keygen_cpu_after": cpu_k_gen_after,
        "keygen_mem_before": mem_k_gen_before,
        "keygen_mem_after": mem_k_gen_after,
        "client_encap_time_s": client_encap_time,
        "client_decap_time_s": client_decap_time,
        "cpu_before_percent": cpu_before,
        "cpu_after_percent": cpu_after,
        "mem_before_bytes": mem_before,
        "mem_after_bytes": mem_after,
        "server_metrics": server_metrics,
        "final_key_hex": final_key.hex()
    }

def main():
    parser = argparse.ArgumentParser(description="KEM performance client")
    parser.add_argument("--server", default=SERVER_URL, help="Server base URL (e.g. http://1.2.3.4:5000)")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS, help="Number of iterations")
    parser.add_argument("--out", default=CLIENT_CSV, help="CSV file to write client metrics to")
    args = parser.parse_args()

    # Fetch server info
    r = requests.get(f"{args.server}/public_info")
    r.raise_for_status()
    server_info = r.json()

    # CSV header
    write_header = not os.path.exists(args.out)
    with open(args.out, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow([
                "Iteration",
                "timestamp",
                "keygen_time_s",
                "keygen_cpu_before",
                "keygen_cpu_after",
                "keygen_mem_before",
                "keygen_mem_after",
                "client_encap_s",
                "client_decap_s",
                "cpu_before_pct",
                "cpu_after_pct",
                "mem_before_bytes",
                "mem_after_bytes",
                "server_decap_s",
                "server_encap_s",
                "server_sign_s",
                "server_client_ct_bytes",
                "server_server_ct_bytes",
                "server_total_packet_bytes",
                "final_key_hex"
            ])

    results = []
    session = requests.Session()
    for i in range(args.iterations):
        try:
            out = run_once(server_info, i+1, session)
            srv = out["server_metrics"]
            row = [
                i+1,
                time.time(),
                f"{out['keygen_time_s']:.9f}",
                f"{out['keygen_cpu_before']:.2f}",
                f"{out['keygen_cpu_after']:.2f}",
                out['keygen_mem_before'],
                out['keygen_mem_after'],
                f"{out['client_encap_time_s']:.9f}",
                f"{out['client_decap_time_s']:.9f}",
                f"{out['cpu_before_percent']:.2f}",
                f"{out['cpu_after_percent']:.2f}",
                out['mem_before_bytes'],
                out['mem_after_bytes'],
                f"{srv.get('decap_time_s', 0):.9f}",
                f"{srv.get('encap_time_s', 0):.9f}",
                f"{srv.get('sign_time_s', 0):.9f}",
                srv.get('client_ct_bytes', ''),
                srv.get('server_ct_bytes', ''),
                srv.get('total_packet_bytes', ''),
                out['final_key_hex']
            ]
            with open(args.out, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(row)

            print(f"Run {i+1:03d}: keygen {out['keygen_time_s']:.6f}s | C_enc {out['client_encap_time_s']:.6f}s | C_dec {out['client_decap_time_s']:.6f}s | S_enc {srv.get('encap_time_s',0):.6f}s | S_dec {srv.get('decap_time_s',0):.6f}s")

            results.append(out)
        except Exception as e:
            print("Error on iteration", i+1, e)

    # Brief summary:
    encs = [r["client_encap_time_s"] for r in results]
    decs = [r["client_decap_time_s"] for r in results]
    if encs and decs:
        print("\n=== Summary ===")
        print(f"Avg client encap: {statistics.mean(encs):.9f}s")
        print(f"Avg client decap: {statistics.mean(decs):.9f}s")
    else:
        print("No successful runs recorded.")

if __name__ == "__main__":
    main()
