#!/usr/bin/env python3
# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.
"""Calibrate ConfidenceModelV2 weights using labeled scan data.

Usage:
    python tools/calibrate_confidence.py [--data PATH] [--epochs N] [--output PATH]

Loads labeled (features, verdict) pairs, trains FeedbackLoop via SGD,
then exports calibrated weights to v2_weights_baseline.json.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from hdwp.core.ml.models.feedback_loop import FeedbackLoop  # noqa: E402

DEFAULT_DATA = ROOT / "tests/integration/fixtures/calibration_data.jsonl"
DEFAULT_OUTPUT = ROOT / "src/hdwp/core/ml/models/v2_weights_baseline.json"
DEFAULT_EPOCHS = 50


def load_data(path: Path) -> list[dict]:
    samples = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            samples.append(json.loads(line))
    return samples


def evaluate(loop: FeedbackLoop, samples: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    for s in samples:
        score = loop.predict(s["features"])
        predicted = "CONFIRMED" if score >= 0.5 else "REFUTED"
        actual = s["verdict"]
        if predicted == "CONFIRMED" and actual == "CONFIRMED":
            tp += 1
        elif predicted == "CONFIRMED" and actual == "REFUTED":
            fp += 1
        elif predicted == "REFUTED" and actual == "REFUTED":
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.data.exists():
        print(f"ERROR: data file not found: {args.data}", file=sys.stderr)
        sys.exit(1)

    samples = load_data(args.data)
    n_confirmed = sum(1 for s in samples if s["verdict"] == "CONFIRMED")
    n_refuted = sum(1 for s in samples if s["verdict"] == "REFUTED")
    print(f"Loaded {len(samples)} samples — {n_confirmed} CONFIRMED, {n_refuted} REFUTED")

    loop = FeedbackLoop()

    before = evaluate(loop, samples)
    print(f"Before training : precision={before['precision']}  recall={before['recall']}  F1={before['f1']}")

    for epoch in range(args.epochs):
        for s in samples:
            loop.observe(s["features"], s["verdict"])

    after = evaluate(loop, samples)
    print(f"After {args.epochs} epochs: precision={after['precision']}  recall={after['recall']}  F1={after['f1']}")

    serialized = loop.to_serializable()
    output_data = {
        **serialized,
        "calibration": {
            "epochs": args.epochs,
            "n_samples": len(samples),
            "n_confirmed": n_confirmed,
            "n_refuted": n_refuted,
            "metrics_before": before,
            "metrics_after": after,
            "data_source": str(args.data),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output_data, indent=2))
    print(f"Weights saved → {args.output}")

    if after["f1"] < 0.8:
        print(f"WARNING: F1={after['f1']} < 0.8 — add more labeled data for better calibration")
        sys.exit(1)

    print("Calibration complete.")


if __name__ == "__main__":
    main()
