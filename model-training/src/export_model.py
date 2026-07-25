from __future__ import annotations

import json
import pickle
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder


def save_pickle(path: Path | str, obj: Any) -> None:
    """Persist an object to disk using pickle."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        pickle.dump(obj, handle)


def load_pickle(path: Path | str) -> Any:
    """Load a pickle object from disk. Only load files created by this project."""
    with Path(path).open("rb") as handle:
        return pickle.load(handle)


def save_json(path: Path | str, payload: Any) -> None:
    """Persist a JSON-compatible payload to disk."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def build_evaluation_payload(y_true, y_pred, label_encoder: Optional[LabelEncoder] = None) -> dict:
    """Create a consistent evaluation payload for the notebook and artifact export."""
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "balanced_accuracy": round(float(balanced_accuracy_score(y_true, y_pred)), 6),
        "precision": round(float(precision_score(y_true, y_pred, average="weighted", zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, y_pred, average="weighted", zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 6),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classification_report": classification_report(
            y_true,
            y_pred,
            output_dict=True,
            zero_division=0,
        ),
        "labels": label_encoder.classes_.tolist() if label_encoder is not None else sorted(pd.Index(y_true).unique().tolist()),
    }


def build_model_metadata(
    *,
    model_name: str,
    dataset_name: str,
    mode: str,
    model_class: str,
    target_labels: list[str],
    benign_label: str,
    feature_count: int,
    missing_value_policy: str,
    infinity_policy: str,
    scaling_required: bool,
    train_test_split: dict,
    random_seed: int,
    metrics: dict,
) -> dict:
    """Collect metadata for the exported artifacts."""
    return {
        "model_version": "0.1.0",
        "creation_timestamp": datetime.now(timezone.utc).isoformat(),
        "dataset_name": dataset_name,
        "mode": mode,
        "model_class": model_class,
        "target_labels": target_labels,
        "benign_label": benign_label,
        "feature_count": feature_count,
        "missing_value_policy": missing_value_policy,
        "infinity_handling_policy": infinity_policy,
        "scaling_required": scaling_required,
        "train_test_split": train_test_split,
        "random_seed": random_seed,
        "metrics": metrics,
        "python_version": platform.python_version(),
        "scikit_learn_version": __import__("sklearn").__version__,
        "model_name": model_name,
    }


def export_artifacts(
    output_dir: Path | str,
    *,
    model: Any,
    preprocessor: Any,
    feature_columns: list[str],
    label_encoder: Optional[LabelEncoder],
    metadata: dict,
    evaluation: dict,
) -> None:
    """Export the trained model, preprocessing objects, and evaluation artifacts."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    save_pickle(output_path / "model.pkl", model)
    save_pickle(output_path / "scaler.pkl", preprocessor)
    save_json(output_path / "feature_columns.json", feature_columns)
    if label_encoder is not None:
        save_pickle(output_path / "label_encoder.pkl", label_encoder)
    save_json(output_path / "model_metadata.json", metadata)
    save_json(output_path / "evaluation.json", evaluation)


def load_artifacts(output_dir: Path | str) -> dict:
    """Reload the exported artifacts from disk."""
    output_path = Path(output_dir)
    artifacts = {
        "model": load_pickle(output_path / "model.pkl"),
        "preprocessor": load_pickle(output_path / "scaler.pkl"),
        "feature_columns": json.loads((output_path / "feature_columns.json").read_text(encoding="utf-8")),
        "label_encoder": None,
        "model_metadata": json.loads((output_path / "model_metadata.json").read_text(encoding="utf-8")),
        "evaluation": json.loads((output_path / "evaluation.json").read_text(encoding="utf-8")),
    }

    if (output_path / "label_encoder.pkl").exists():
        artifacts["label_encoder"] = load_pickle(output_path / "label_encoder.pkl")

    return artifacts
