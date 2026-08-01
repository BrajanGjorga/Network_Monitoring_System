import json
import logging
import pickle
from pathlib import Path
from typing import Any, Optional

import pandas as pd


class Predictor:
    def __init__(self, model_dir: str, logger: Optional[logging.Logger] = None):
        self.model_dir = Path(model_dir)
        self.logger = logger or logging.getLogger(__name__)
        self.model = None
        self.preprocessor = None
        self.feature_columns = []
        self.label_encoder = None
        self.metadata = {}
        self.is_ready = False
        self._load()

    def _load(self) -> None:
        required_files = ["model.pkl", "scaler.pkl", "feature_columns.json", "model_metadata.json"]
        missing = [name for name in required_files if not (self.model_dir / name).exists()]
        if missing:
            self.logger.error("Missing model artifacts: %s", ", ".join(missing))
            return

        try:
            with (self.model_dir / "model.pkl").open("rb") as handle:
                self.model = pickle.load(handle)
            with (self.model_dir / "scaler.pkl").open("rb") as handle:
                self.preprocessor = pickle.load(handle)
            self.feature_columns = json.loads((self.model_dir / "feature_columns.json").read_text(encoding="utf-8"))
            self.metadata = json.loads((self.model_dir / "model_metadata.json").read_text(encoding="utf-8"))
            if (self.model_dir / "label_encoder.pkl").exists():
                with (self.model_dir / "label_encoder.pkl").open("rb") as handle:
                    self.label_encoder = pickle.load(handle)
        except Exception as exc:
            self.logger.error("Failed to load model artifacts from %s: %s", self.model_dir, exc)
            self.is_ready = False
            return

        self.is_ready = True
        self.logger.info("Loaded model artifact directory: %s", self.model_dir)

    def validate(self) -> bool:
        if not self.is_ready:
            return False
        if self.metadata.get("feature_count") != len(self.feature_columns):
            self.logger.error("Artifact feature count mismatch")
            return False
        mode = self.metadata.get("mode")
        if mode not in {"binary", "multiclass"}:
            self.logger.error("Unknown model mode: %s", mode)
            return False
        return True

    def predict(self, row: dict[str, Any]) -> tuple[str, float]:
        if not self.is_ready:
            raise RuntimeError("Model artifacts are not loaded")
        frame = pd.DataFrame([row], columns=self.feature_columns)
        if self.preprocessor is not None:
            frame = self.preprocessor.transform(frame)
        prediction = self.model.predict(frame)[0]
        label = str(prediction)
        if self.label_encoder is not None and hasattr(self.label_encoder, "inverse_transform"):
            label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = 0.0
        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(frame)[0]
            confidence = float(max(probabilities))
        return label, confidence

    @staticmethod
    def is_dangerous_label(label: str, dangerous_labels: list[str]) -> bool:
        if not label:
            return False
        if label.upper() == "BENIGN":
            return False
        return label in dangerous_labels or label.upper() in {value.upper() for value in dangerous_labels}

    @staticmethod
    def meets_confidence_threshold(confidence: float, minimum_confidence: float) -> bool:
        return confidence >= minimum_confidence
