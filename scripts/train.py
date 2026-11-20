"""Train on Tuesday/Wednesday, evaluate once on the Friday port-scan capture."""

import argparse
import hashlib
import json
from pathlib import Path
from shutil import copyfileobj
from urllib.request import urlopen

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from nids.features import COLUMNS, SCHEMA

FILES = [
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]
BASE = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/4e9edfa727f800b6f595bc2ee7420527156562b2/"


def load(path):
    df = pd.read_csv(
        path, encoding="cp1252", usecols=lambda s: s.strip() in (*COLUMNS, "Label")
    )
    df.columns = df.columns.str.strip()
    df["Label"] = df.Label.str.strip()
    clean = df.dropna().copy()
    return clean.loc[
        np.isfinite(clean[list(COLUMNS)]).all(axis=1)
        & (clean[list(COLUMNS)] >= 0).all(axis=1)
    ]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--download", action="store_true")
    args = p.parse_args()
    args.data.mkdir(parents=True, exist_ok=True)
    fingerprints = {}
    for name in FILES:
        path = args.data / name
        if args.download and not path.exists():
            tmp = path.with_suffix(".part")
            with urlopen(BASE + name, timeout=180) as src, tmp.open("wb") as dest:
                copyfileobj(src, dest)
            tmp.replace(path)
        with path.open("rb") as f:
            fingerprints[name] = hashlib.file_digest(f, "sha256").hexdigest()
    train = pd.concat([load(args.data / n) for n in FILES[:2]], ignore_index=True)
    test = load(args.data / FILES[-1])
    # Limit training cost with deterministic within-family sampling after the day split.
    train = pd.concat(
        [
            group.sample(min(40000, len(group)), random_state=42)
            for _, group in train.groupby("Label")
        ]
    )
    model = RandomForestClassifier(
        n_estimators=48,
        max_depth=12,
        min_samples_leaf=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=1,
    )
    model.fit(train[list(COLUMNS)].to_numpy(), (train.Label != "BENIGN").astype(int))
    truth = (test.Label != "BENIGN").astype(int)
    pred = (model.predict_proba(test[list(COLUMNS)].to_numpy())[:, 1] >= 0.8).astype(
        int
    )

    def metrics(y):
        return {
            "per_class": classification_report(
                truth,
                y,
                labels=[0, 1],
                target_names=["normal", "attack"],
                output_dict=True,
                zero_division=0,
            ),
            "confusion_matrix": confusion_matrix(truth, y, labels=[0, 1]).tolist(),
        }

    majority = int((train.Label != "BENIGN").mean() > 0.5)
    report = dict(
        schema=SCHEMA,
        columns=COLUMNS,
        sklearn=sklearn.__version__,
        sha256=fingerprints,
        train_files=FILES[:2],
        test_files=FILES[2:],
        threshold=0.8,
        train_counts=train.Label.value_counts().to_dict(),
        test_counts=test.Label.value_counts().to_dict(),
        unseen_families=sorted(set(test.Label) - set(train.Label)),
        forest=metrics(pred),
        majority_baseline=metrics(np.full(len(test), majority)),
    )
    out = Path("model")
    out.mkdir(exist_ok=True)
    joblib.dump(
        dict(schema=SCHEMA, columns=COLUMNS, model=model),
        out / "forest.joblib",
        compress=3,
    )
    (out / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["forest"], indent=2))


if __name__ == "__main__":
    main()
