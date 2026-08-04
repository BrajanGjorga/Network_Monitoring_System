from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path
from typing import Any, Optional, Sequence

import numpy as np
import pandas as pd


class Predictor:
    """Load exported artifacts and perform batch predictions safely."""

    def __init__(self, model_dir: str | Path, logger: Optional[logging.Logger] = None) -> None:
        self.model_dir = Path(model_dir)
        self.logger = logger or logging.getLogger(__name__)

        self.model: Any = None
        self.preprocessor: Any = None
        self.feature_columns: list[str] = []
        self.label_encoder: Any = None
        self.metadata: dict[str, Any] = {}
        self.is_ready = False

        self._load()

    @staticmethod
    def _load_pickle(path: Path) -> Any:
        # Only load pickle files created and controlled by this project.
        with path.open("rb") as handle:
            return pickle.load(handle)

    def _load(self) -> None:
        preprocessor_candidates = [
            self.model_dir / "preprocessor.pkl",
            self.model_dir / "scaler.pkl",
        ]
        preprocessor_file = next((path for path in preprocessor_candidates if path.exists()), None)
        if preprocessor_file is None:
            self.logger.error("Missing preprocessing artifact: expected one of %s", ", ".join(str(path.name) for path in preprocessor_candidates))
            return

        required_paths = {
            "model": self.model_dir / "model.pkl",
            "preprocessor": preprocessor_file,
            "feature_columns": self.model_dir / "feature_columns.json",
            "metadata": self.model_dir / "model_metadata.json",
        }

        missing = [name for name, path in required_paths.items() if not path.exists()]
        if missing:
            self.logger.error("Missing model artifacts: %s", ", ".join(missing))
            return

        try:
            self.model = self._load_pickle(required_paths["model"])
            self.preprocessor = self._load_pickle(required_paths["preprocessor"])
            self.feature_columns = json.loads(
                required_paths["feature_columns"].read_text(encoding="utf-8")
            )
            self.metadata = json.loads(required_paths["metadata"].read_text(encoding="utf-8"))

            label_encoder_path = self.model_dir / "label_encoder.pkl"
            if label_encoder_path.exists():
                self.label_encoder = self._load_pickle(label_encoder_path)
        except Exception as exc:
            self.logger.exception("Failed to load model artifacts from %s: %s", self.model_dir, exc)
            self.is_ready = False
            return

        self.is_ready = self.validate()
        if self.is_ready:
            self.logger.info("Loaded model artifacts from %s", self.model_dir.resolve())

    def validate(self) -> bool:
        if self.model is None or self.preprocessor is None:
            self.logger.error("Model or preprocessor is not loaded")
            return False
        if not self.feature_columns:
            self.logger.error("Feature column list is empty")
            return False

        expected_count = self.metadata.get("feature_count")
        if expected_count is not None and int(expected_count) != len(self.feature_columns):
            self.logger.error(
                "Artifact feature count mismatch: metadata=%s, feature_columns=%s",
                expected_count,
                len(self.feature_columns),
            )
            return False

        mode = self.metadata.get("mode")
        if mode not in {"binary", "multiclass"}:
            self.logger.error("Unknown model mode: %s", mode)
            return False

        return True

    @staticmethod
    def _clean_column_names(dataframe: pd.DataFrame) -> pd.DataFrame:
        cleaned = dataframe.copy()
        cleaned.columns = [str(column).strip() for column in cleaned.columns]
        return cleaned

    @staticmethod
    def prepare_feature_frame_static(dataframe: pd.DataFrame, feature_columns: Sequence[str]) -> pd.DataFrame:
        """Prepare a feature frame without requiring an initialized predictor instance."""
        if dataframe.empty:
            raise ValueError("The incoming dataframe contains no rows")

        cleaned = Predictor._clean_column_names(dataframe)

        duplicated = cleaned.columns[cleaned.columns.duplicated()].tolist()
        if duplicated:
            raise ValueError(f"Duplicate input columns detected: {duplicated}")

        missing = [column for column in feature_columns if column not in cleaned.columns]
        if missing:
            raise ValueError(f"Missing required feature columns: {missing}")

        prepared = cleaned.loc[:, list(feature_columns)].copy()
        prepared = prepared.apply(pd.to_numeric, errors="coerce")
        prepared.replace([np.inf, -np.inf], np.nan, inplace=True)
        return prepared

    def prepare_feature_frame(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        """Apply the same input preparation used during model training."""
        prepared = self.prepare_feature_frame_static(dataframe, self.feature_columns)

        entirely_missing = prepared.columns[prepared.isna().all()].tolist()
        if entirely_missing:
            self.logger.warning(
                "These input features are entirely missing/non-numeric in this batch: %s",
                entirely_missing,
            )

        return prepared

    def _decode(self, predictions: Sequence[Any]) -> np.ndarray:
        predictions_array = np.asarray(predictions)
        if self.label_encoder is not None and hasattr(self.label_encoder, "inverse_transform"):
            return np.asarray(self.label_encoder.inverse_transform(predictions_array))
        return predictions_array.astype(str)

    def predict_dataframe(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        if not self.is_ready:
            raise RuntimeError("Model artifacts are not loaded or failed validation")

        prepared = self.prepare_feature_frame(dataframe)
        transformed = self.preprocessor.transform(prepared)

        encoded_predictions = self.model.predict(transformed)
        decoded_predictions = self._decode(encoded_predictions)

        results = dataframe.reset_index(drop=True).copy()
        results["Predicted Label"] = decoded_predictions

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(transformed)
            encoded_classes = np.asarray(self.model.classes_)
            decoded_classes = self._decode(encoded_classes)

            for index, class_name in enumerate(decoded_classes):
                results[f"Probability {class_name}"] = probabilities[:, index]

            class_to_position = {
                encoded_class: index for index, encoded_class in enumerate(encoded_classes.tolist())
            }
            confidences = [
                float(probabilities[row_index, class_to_position[prediction]])
                for row_index, prediction in enumerate(encoded_predictions.tolist())
            ]
            results["Prediction Confidence"] = confidences
        else:
            results["Prediction Confidence"] = np.nan

        return results

    def predict(self, row: dict[str, Any]) -> tuple[str, float]:
        results = self.predict_dataframe(pd.DataFrame([row]))
        return (
            str(results.loc[0, "Predicted Label"]),
            float(results.loc[0, "Prediction Confidence"]),
        )

    def is_dangerous_label(self, label: str, dangerous_labels: list[str]) -> bool:
        normalized = str(label).strip().upper()
        if not normalized or normalized == "BENIGN":
            return False

        if self.metadata.get("mode") == "binary":
            return normalized == "MALICIOUS"

        normalized_dangerous = {str(value).strip().upper() for value in dangerous_labels}
        return normalized in normalized_dangerous

    @staticmethod
    def meets_confidence_threshold(confidence: float, minimum_confidence: float) -> bool:
        return float(confidence) >= float(minimum_confidence)
