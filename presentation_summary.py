#!/usr/bin/env python3
"""
presentation_summary.py

Generate simple, presentation-friendly charts comparing KEM vs RSA.

Inputs (defaults):
  --kem client_kem_metrics.csv
  --rsa client_rsa_metrics.csv
Outputs:
    graphs/presentation_breakdown.png  → grouped bars of mean times per component
    graphs/presentation_total.png      → total approx compute time (client+server)
    graphs/metric_*.png                → per-metric RSA vs KEM comparisons (bars and timeseries)
"""

import argparse
import csv
import os
from statistics import mean


METRIC_LABELS = {
    "client_keygen_s": "Client Keygen",
    "client_enc_s": "Client Encrypt",
    "client_dec_s": "Client Decrypt",
    "server_enc_s": "Server Encrypt",
    "server_dec_s": "Server Decrypt",
}


def read_rows(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"CSV not found: {path}")
    out = []
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            # cast known numeric fields
            for k in list(METRIC_LABELS.keys()) + ["Iteration", "timestamp"]:
                if k in row and row[k] not in (None, ""):
                    try:
                        row[k] = float(row[k])
                    except ValueError:
                        pass
            out.append(row)
    return out


def metric_mean(rows, key):
    vals = [r[key] for r in rows if key in r and isinstance(r[key], (int, float))]
    return mean(vals) if vals else 0.0


def compute_means(kem_rows, rsa_rows):
    kem_means = {k: metric_mean(kem_rows, k) for k in METRIC_LABELS}
    rsa_means = {k: metric_mean(rsa_rows, k) for k in METRIC_LABELS}
    return kem_means, rsa_means


def plot_breakdown(kem_means, rsa_means, outpath):
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

    rcParams.update({
        "figure.figsize": (12, 6),
        "axes.titlesize": 18,
        "axes.labelsize": 14,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12,
        "legend.fontsize": 12,
    })

    keys = list(METRIC_LABELS.keys())
    labels = [METRIC_LABELS[k] for k in keys]
    kem_vals = [kem_means[k] for k in keys]
    rsa_vals = [rsa_means[k] for k in keys]

    x = range(len(labels))
    width = 0.38

    plt.bar([i - width / 2 for i in x], kem_vals, width=width, label="KEM", color="#4e79a7")
    plt.bar([i + width / 2 for i in x], rsa_vals, width=width, label="RSA", color="#f28e2b")
    plt.xticks(list(x), labels, rotation=15, ha="right")
    plt.ylabel("Seconds (mean)")
    plt.title("Handshake Components — RSA vs KEM (mean)")
    plt.grid(axis="y", alpha=0.25)
    plt.legend()
    plt.tight_layout()
    plt.savefig(outpath, dpi=180)
    plt.close()


def plot_metric_bars(metric_key, kem_mean, rsa_mean, outpath):
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

    rcParams.update({
        "figure.figsize": (7, 5),
        "axes.titlesize": 16,
        "axes.labelsize": 13,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12,
    })

    label = METRIC_LABELS.get(metric_key, metric_key)
    vals = [kem_mean, rsa_mean]
    colors = ["#4e79a7", "#f28e2b"]
    names = ["KEM", "RSA"]

    plt.bar(names, vals, color=colors)
    for i, v in enumerate(vals):
        plt.text(i, v, f"{v:.6f}s", ha="center", va="bottom")
    plt.ylabel("Seconds (mean)")
    plt.title(f"{label} — RSA vs KEM")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def plot_metric_timeseries(metric_key, kem_rows, rsa_rows, outpath):
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

    rcParams.update({
        "figure.figsize": (9, 5),
        "axes.titlesize": 16,
        "axes.labelsize": 13,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12,
        "legend.fontsize": 12,
    })

    label = METRIC_LABELS.get(metric_key, metric_key)

    # build iteration-indexed series
    def series(rows):
        xs, ys = [], []
        for r in rows:
            val = r.get(metric_key)
            if isinstance(val, (int, float)):
                it = r.get("Iteration")
                x = int(it) if isinstance(it, (int, float, str)) and str(it).isdigit() else len(xs) + 1
                xs.append(x)
                ys.append(val)
        return xs, ys

    kx, ky = series(kem_rows)
    rx, ry = series(rsa_rows)

    plt.plot(kx, ky, marker="o", linestyle="-", color="#4e79a7", label="KEM") if ky else None
    plt.plot(rx, ry, marker="s", linestyle="--", color="#f28e2b", label="RSA") if ry else None
    plt.xlabel("Iteration")
    plt.ylabel("Seconds")
    plt.title(f"{label} — Timeseries")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(outpath, dpi=160)
    plt.close()


def plot_totals(kem_means, rsa_means, outpath):
    import matplotlib.pyplot as plt
    from matplotlib import rcParams

    rcParams.update({
        "figure.figsize": (8, 5),
        "axes.titlesize": 18,
        "axes.labelsize": 14,
        "xtick.labelsize": 12,
        "ytick.labelsize": 12,
        "legend.fontsize": 12,
    })

    # Approximate total compute time = sum of shared components
    components = ["client_enc_s", "client_dec_s", "server_enc_s", "server_dec_s"]
    kem_total = sum(kem_means[k] for k in components)
    rsa_total = sum(rsa_means[k] for k in components)

    labels = ["KEM", "RSA"]
    vals = [kem_total, rsa_total]
    colors = ["#4e79a7", "#f28e2b"]

    plt.bar(labels, vals, color=colors)
    for i, v in enumerate(vals):
        plt.text(i, v, f"{v:.4f}s", ha="center", va="bottom", fontsize=12)
    plt.ylabel("Seconds (mean)")
    plt.title("Approx. Total Handshake Compute Time")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(outpath, dpi=180)
    plt.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--kem", default="client_kem_metrics.csv")
    p.add_argument("--rsa", default="client_rsa_metrics.csv")
    p.add_argument("--outdir", default=".")
    args = p.parse_args()

    kem_rows = read_rows(args.kem)
    rsa_rows = read_rows(args.rsa)
    kem_means, rsa_means = compute_means(kem_rows, rsa_rows)

    graphs_dir = os.path.join(args.outdir, "graphs")
    os.makedirs(graphs_dir, exist_ok=True)
    breakdown_png = os.path.join(graphs_dir, "presentation_breakdown.png")
    total_png = os.path.join(graphs_dir, "presentation_total.png")

    plot_breakdown(kem_means, rsa_means, breakdown_png)
    plot_totals(kem_means, rsa_means, total_png)

    print(f"Wrote: {breakdown_png}")
    print(f"Wrote: {total_png}")

    # Per-metric graphs
    for mk in METRIC_LABELS.keys():
        mb_png = os.path.join(graphs_dir, f"metric_{mk}_bars.png")
        mt_png = os.path.join(graphs_dir, f"metric_{mk}_timeseries.png")
        plot_metric_bars(mk, kem_means[mk], rsa_means[mk], mb_png)
        plot_metric_timeseries(mk, kem_rows, rsa_rows, mt_png)
        print(f"Wrote: {mb_png}")
        print(f"Wrote: {mt_png}")

    # Compose a single slide overview PNG using the two main charts and one metric example
    def compose_overview(breakdown_path, total_path, example_metric_key):
        import matplotlib.pyplot as plt
        import matplotlib.image as mpimg

        fig = plt.figure(figsize=(14, 8))
        fig.suptitle("RSA vs KEM — Overview", fontsize=20)

        ax1 = plt.subplot2grid((2, 2), (0, 0))
        ax1.imshow(mpimg.imread(breakdown_path))
        ax1.axis('off')
        ax1.set_title('Components (Mean)')

        ax2 = plt.subplot2grid((2, 2), (0, 1))
        ax2.imshow(mpimg.imread(total_path))
        ax2.axis('off')
        ax2.set_title('Total Compute (Mean)')

        # pick metric example images
        mb_png = os.path.join(graphs_dir, f"metric_{example_metric_key}_bars.png")
        mt_png = os.path.join(graphs_dir, f"metric_{example_metric_key}_timeseries.png")
        ax3 = plt.subplot2grid((2, 2), (1, 0))
        ax3.imshow(mpimg.imread(mb_png))
        ax3.axis('off')
        ax3.set_title(f'{METRIC_LABELS.get(example_metric_key, example_metric_key)} (Bars)')

        ax4 = plt.subplot2grid((2, 2), (1, 1))
        ax4.imshow(mpimg.imread(mt_png))
        ax4.axis('off')
        ax4.set_title(f'{METRIC_LABELS.get(example_metric_key, example_metric_key)} (Timeseries)')

        out = os.path.join(graphs_dir, 'slide_overview.png')
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig(out, dpi=180)
        plt.close()
        print(f"Wrote: {out}")

    # Choose a representative metric for the example section
    compose_overview(breakdown_png, total_png, 'client_enc_s')


if __name__ == "__main__":
    main()
