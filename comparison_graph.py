#!/usr/bin/env python3
"""
comparison_graph.py

Generate 1-to-1 RSA vs KEM comparisons from client CSV metrics using matplotlib.

Inputs (defaults):
  --kem client_kem_metrics.csv
  --rsa client_rsa_metrics.csv
Outputs:
  comparison_means.png       → side-by-side bar chart of mean times
  comparison_timeseries.png  → per-iteration overlays for each metric
"""

import argparse
import csv
import os
from statistics import mean


def read_client_csv(path):
	rows = []
	if not os.path.exists(path):
		raise FileNotFoundError(f"CSV not found: {path}")
	with open(path, newline="") as f:
		r = csv.DictReader(f)
		for row in r:
			# Coerce known numeric fields to float where present
			for k in [
				"Iteration",
				"timestamp",
				"client_keygen_s",
				"client_enc_s",
				"client_dec_s",
				"server_enc_s",
				"server_dec_s",
				"server_sign_s",
			]:
				if k in row and row[k] not in (None, ""):
					try:
						row[k] = float(row[k])
					except ValueError:
						pass
			rows.append(row)
	return rows


def metric_mean(rows, key):
	vals = [r[key] for r in rows if key in r and isinstance(r[key], (int, float))]
	return mean(vals) if vals else None


def build_means(k_rows, r_rows):
	# Focus on common metrics for 1-to-1 comparison
	metrics = [
		("client_keygen_s", "Client Keygen (s)"),
		("client_enc_s", "Client Enc (s)"),
		("client_dec_s", "Client Dec (s)"),
		("server_enc_s", "Server Enc (s)"),
		("server_dec_s", "Server Dec (s)"),
	]
	data = []
	for key, label in metrics:
		km = metric_mean(k_rows, key)
		rm = metric_mean(r_rows, key)
		if km is not None or rm is not None:
			data.append((key, label, km or 0.0, rm or 0.0))
	return data


def prepare_timeseries(rows, key):
	xs = []
	ys = []
	for r in rows:
		if key in r and isinstance(r[key], (int, float)):
			it = r.get("Iteration")
			xs.append(int(it) if isinstance(it, (int, float, str)) and str(it).isdigit() else len(xs) + 1)
			ys.append(r[key])
	return xs, ys


def plot_means(means_data, outpath):
	try:
		import matplotlib.pyplot as plt
	except Exception as e:
		raise SystemExit("matplotlib is required. Install with: pip install matplotlib") from e

	labels = [label for _, label, _, _ in means_data]
	kem_vals = [km for _, _, km, _ in means_data]
	rsa_vals = [rm for _, _, _, rm in means_data]

	x = range(len(labels))
	width = 0.38

	plt.figure(figsize=(10, 5))
	plt.bar([i - width / 2 for i in x], kem_vals, width=width, label="KEM", color="#4e79a7")
	plt.bar([i + width / 2 for i in x], rsa_vals, width=width, label="RSA", color="#f28e2b")
	plt.xticks(list(x), labels, rotation=20, ha="right")
	plt.ylabel("Seconds (mean)")
	plt.title("RSA vs KEM — Mean Times")
	plt.legend()
	plt.tight_layout()
	plt.savefig(outpath, dpi=150)
	plt.close()


def plot_timeseries(k_rows, r_rows, outpath):
	try:
		import matplotlib.pyplot as plt
	except Exception as e:
		raise SystemExit("matplotlib is required. Install with: pip install matplotlib") from e

	metrics = [
		("client_keygen_s", "Client Keygen (s)"),
		("client_enc_s", "Client Enc (s)"),
		("client_dec_s", "Client Dec (s)"),
		("server_enc_s", "Server Enc (s)"),
		("server_dec_s", "Server Dec (s)"),
	]

	n = len(metrics)
	cols = 2
	rows = (n + cols - 1) // cols

	plt.figure(figsize=(12, 6))
	for idx, (key, label) in enumerate(metrics, start=1):
		kx, ky = prepare_timeseries(k_rows, key)
		rx, ry = prepare_timeseries(r_rows, key)
		if not ky and not ry:
			continue
		ax = plt.subplot(rows, cols, idx)
		if ky:
			ax.plot(kx, ky, marker="o", linestyle="-", color="#4e79a7", label="KEM")
		if ry:
			ax.plot(rx, ry, marker="s", linestyle="--", color="#f28e2b", label="RSA")
		ax.set_title(label)
		ax.set_xlabel("Iteration")
		ax.set_ylabel("Seconds")
		ax.grid(True, alpha=0.3)
		ax.legend()

	plt.tight_layout()
	plt.savefig(outpath, dpi=150)
	plt.close()


def main():
	p = argparse.ArgumentParser()
	p.add_argument("--kem", default="client_kem_metrics.csv")
	p.add_argument("--rsa", default="client_rsa_metrics.csv")
	p.add_argument("--outdir", default=".")
	p.add_argument("--show", type=int, default=0, help="Set to 1 to display plots interactively")
	args = p.parse_args()

	k_rows = read_client_csv(args.kem)
	r_rows = read_client_csv(args.rsa)

	means_data = build_means(k_rows, r_rows)
	os.makedirs(args.outdir, exist_ok=True)

	means_png = os.path.join(args.outdir, "comparison_means.png")
	ts_png = os.path.join(args.outdir, "comparison_timeseries.png")

	plot_means(means_data, means_png)
	plot_timeseries(k_rows, r_rows, ts_png)

	print(f"Wrote: {means_png}")
	print(f"Wrote: {ts_png}")

	if args.show:
		# Re-render to screen (simple approach: open the images)
		try:
			import matplotlib.pyplot as plt
			import matplotlib.image as mpimg
		except Exception:
			raise SystemExit("matplotlib is required. Install with: pip install matplotlib")
		for img in [means_png, ts_png]:
			plt.figure()
			plt.imshow(mpimg.imread(img))
			plt.axis('off')
			plt.title(os.path.basename(img))
		plt.show()


if __name__ == "__main__":
	main()

