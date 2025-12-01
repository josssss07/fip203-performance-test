#!/usr/bin/env python3
"""
presentation_detailed.py

Generate graphs for:
- Key generation time (client RSA vs client KEM)
- Encryption/Decryption (Encapsulation/Decapsulation) times (client/server)
- Signature generation and verification time (KEM server sign time; RSA has no signature in this flow)
- Key, ciphertext, and signature sizes (from server CSVs; signature size approximated via Ed25519 64 bytes if not logged)

Inputs (defaults):
  --client-kem client_kem_metrics.csv
  --client-rsa client_rsa_metrics.csv
  --server-kem server_kem_metrics.csv
  --server-rsa server_rsa_metrics.csv
Outputs (graphs/):
  keygen_times.png
  enc_dec_times.png
  sign_times.png
  sizes_kem.png
  sizes_rsa.png
"""

import argparse
import csv
import os
from statistics import mean


def read_csv(path):
    rows = []
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing CSV: {path}")
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows


def to_float(row, key, default=None):
    v = row.get(key)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except Exception:
        return default


def mean_of(rows, key):
    vals = [to_float(r, key) for r in rows]
    vals = [v for v in vals if isinstance(v, (int, float))]
    return mean(vals) if vals else 0.0


def sum_of(rows, key):
    vals = [to_float(r, key) for r in rows]
    vals = [v for v in vals if isinstance(v, (int, float))]
    return sum(vals) if vals else 0.0


def plot_keygen(client_kem_rows, client_rsa_rows, outpath):
    import matplotlib.pyplot as plt
    kem = mean_of(client_kem_rows, "client_keygen_s")
    rsa = mean_of(client_rsa_rows, "client_keygen_s")
    plt.figure(figsize=(7,5))
    plt.bar(["KEM", "RSA"], [kem, rsa], color=["#4e79a7", "#f28e2b"]) 
    for i, v in enumerate([kem, rsa]):
        plt.text(i, v, f"{v:.6f}s", ha="center", va="bottom")
    plt.title("Client Key Generation Time (mean)")
    plt.ylabel("Seconds")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def plot_enc_dec(client_kem_rows, client_rsa_rows, server_kem_rows, server_rsa_rows, outpath):
    import matplotlib.pyplot as plt
    labels = ["Client Enc", "Client Dec", "Server Enc", "Server Dec"]
    kem_vals = [
        mean_of(client_kem_rows, "client_enc_s"),
        mean_of(client_kem_rows, "client_dec_s"),
        mean_of(client_kem_rows, "server_enc_s"),
        mean_of(client_kem_rows, "server_dec_s"),
    ]
    rsa_vals = [
        mean_of(client_rsa_rows, "client_enc_s"),
        mean_of(client_rsa_rows, "client_dec_s"),
        mean_of(client_rsa_rows, "server_enc_s"),
        mean_of(client_rsa_rows, "server_dec_s"),
    ]
    x = range(len(labels))
    width = 0.38
    plt.figure(figsize=(10,5))
    plt.bar([i - width/2 for i in x], kem_vals, width=width, label="KEM", color="#4e79a7")
    plt.bar([i + width/2 for i in x], rsa_vals, width=width, label="RSA", color="#f28e2b")
    plt.xticks(list(x), labels)
    plt.ylabel("Seconds (mean)")
    plt.title("Enc/Dec (Encap/Decap) Times (mean)")
    plt.legend()
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def plot_sign_times(client_kem_rows, outpath):
    import matplotlib.pyplot as plt
    # Only KEM flow includes signing in this app
    sign_mean = mean_of(client_kem_rows, "server_sign_s")
    plt.figure(figsize=(6,5))
    plt.bar(["KEM Server Sign"], [sign_mean], color=["#59a14f"]) 
    plt.text(0, sign_mean, f"{sign_mean:.6f}s", ha="center", va="bottom")
    plt.ylabel("Seconds (mean)")
    plt.title("Signature Generation Time (Server)")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def plot_sizes_kem(server_kem_rows, outpath):
    import matplotlib.pyplot as plt
    # Use sums or means from server side bytes
    client_ct = mean_of(server_kem_rows, "client_ct_bytes")
    server_ct = mean_of(server_kem_rows, "server_ct_bytes")
    total_pkt = mean_of(server_kem_rows, "total_packet_bytes")
    # Signature size (Ed25519 fixed 64 bytes). If you log it, replace here.
    sign_size = 64.0
    labels = ["Client CT", "Server CT", "Total Packet", "Signature"]
    vals = [client_ct, server_ct, total_pkt, sign_size]
    plt.figure(figsize=(9,5))
    plt.bar(labels, vals, color=["#4e79a7", "#f28e2b", "#76b7b2", "#59a14f"]) 
    for i, v in enumerate(vals):
        plt.text(i, v, f"{v:.0f} B", ha="center", va="bottom")
    plt.ylabel("Bytes (mean)")
    plt.title("KEM Sizes (mean)")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def plot_sizes_rsa(server_rsa_rows, outpath):
    import matplotlib.pyplot as plt
    # RSA server csv logs total ciphertext bytes across both directions
    ct_total = mean_of(server_rsa_rows, "ciphertext_bytes")
    labels = ["RSA Total Ciphertext"]
    vals = [ct_total]
    plt.figure(figsize=(7,5))
    plt.bar(labels, vals, color=["#f28e2b"]) 
    plt.text(0, vals[0], f"{vals[0]:.0f} B", ha="center", va="bottom")
    plt.ylabel("Bytes (mean)")
    plt.title("RSA Sizes (mean)")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-kem", default="client_kem_metrics.csv")
    ap.add_argument("--client-rsa", default="client_rsa_metrics.csv")
    ap.add_argument("--server-kem", default="server_kem_metrics.csv")
    ap.add_argument("--server-rsa", default="server_rsa_metrics.csv")
    ap.add_argument("--outdir", default=".")
    args = ap.parse_args()

    ck = read_csv(args.client_kem)
    cr = read_csv(args.client_rsa)
    sk = read_csv(args.server_kem)
    sr = read_csv(args.server_rsa)

    graphs = os.path.join(args.outdir, "graphs")
    os.makedirs(graphs, exist_ok=True)

    plot_keygen(ck, cr, os.path.join(graphs, "keygen_times.png"))
    plot_enc_dec(ck, cr, sk, sr, os.path.join(graphs, "enc_dec_times.png"))
    plot_sign_times(ck, os.path.join(graphs, "sign_times.png"))
    plot_sizes_kem(sk, os.path.join(graphs, "sizes_kem.png"))
    plot_sizes_rsa(sr, os.path.join(graphs, "sizes_rsa.png"))

    print("Graphs written to:")
    for fn in [
        "keygen_times.png",
        "enc_dec_times.png",
        "sign_times.png",
        "sizes_kem.png",
        "sizes_rsa.png",
    ]:
        print(" -", os.path.join(graphs, fn))


if __name__ == "__main__":
    main()
