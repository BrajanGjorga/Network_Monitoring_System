from typing import Iterable, Optional, Sequence, Union

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
"""In this file i have created some functions that will help in the 
preprocessing of the data. These functions will be used in the training 
workflow to prepare the data for model training and evaluation."""

def clean_column_names(dataframe: pd.DataFrame) -> pd.DataFrame:
    cleaned = dataframe.copy()
    cleaned.columns = [str(column).strip() for column in cleaned.columns]
    return cleaned


def detect_label_column(
    dataframe: pd.DataFrame,
    label_column: Optional[str] = None,
    candidates: Optional[Sequence[str]] = None,
) -> str:
    cleaned = clean_column_names(dataframe)
    normalized_columns = {str(column).strip().lower(): column for column in cleaned.columns}

    if label_column is not None:
        candidate = str(label_column).strip()
        if candidate in cleaned.columns:
            return candidate
        if candidate.lower() in normalized_columns:
            return normalized_columns[candidate.lower()]

    if candidates is None:
        candidates = ["Label", "label", "Attack", "attack"]

    for candidate in candidates:
        normalized = str(candidate).strip().lower()
        if normalized in normalized_columns:
            return normalized_columns[normalized]

    for column in cleaned.columns:
        lower_name = str(column).strip().lower()
        if "label" in lower_name or "attack" in lower_name:
            return column

    raise ValueError("Could not safely detect a label column from the dataframe.")


def select_feature_columns(
    dataframe: pd.DataFrame,
    label_column: str,
    metadata_columns: Optional[Iterable[str]] = None,
) -> list[str]:
    cleaned = clean_column_names(dataframe)
    metadata = {str(column).strip() for column in (metadata_columns or [])}
    metadata.update({"Flow ID", "Source IP", "Destination IP", "Timestamp"})

    feature_columns = [
        column for column in cleaned.columns if column not in metadata and column != label_column
    ]
    if not feature_columns:
        raise ValueError("No feature columns were found after removing metadata columns.")

    return feature_columns


def prepare_feature_frame(
    dataframe: pd.DataFrame,
    feature_columns: Sequence[str],
    metadata_columns: Optional[Iterable[str]] = None,
) -> pd.DataFrame:
    """Convert columns to numeric values and handle infinity and missing values."""
    cleaned = clean_column_names(dataframe)

    if metadata_columns is not None:
        for column in metadata_columns:
            column_name = str(column).strip()
            if column_name in cleaned.columns:
                cleaned = cleaned.drop(columns=[column_name])

    missing_features = [column for column in feature_columns if column not in cleaned.columns]
    if missing_features:
        raise ValueError(f"Missing required feature columns: {missing_features}")

    prepared = cleaned.loc[:, list(feature_columns)].copy()
    prepared = prepared.apply(pd.to_numeric, errors="coerce")
    prepared.replace([np.inf, -np.inf], np.nan, inplace=True)
    return prepared


def build_preprocessor(scaling_required: bool = True) -> Pipeline:
    """Create a simple preprocessing pipeline for the training workflow."""
    steps = [("imputer", SimpleImputer(strategy="median"))]
    if scaling_required:
        steps.append(("scaler", StandardScaler()))
    return Pipeline(steps)


def split_train_test(
    features: pd.DataFrame,
    labels: pd.Series,
    test_size: float = 0.2,
    random_state: int = 42,
    stratify: bool = True,
):
    """Split data into train and test sets while avoiding leakage."""
    stratify_vector = labels if stratify else None
    return train_test_split(
        features,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify_vector,
    )


def build_binary_labels(labels: pd.Series, benign_label: str = "BENIGN") -> pd.Series:
    """Convert labels to a simple BENIGN versus MALICIOUS target."""
    cleaned = labels.astype(str).str.strip()
    return pd.Series(
        np.where(cleaned == benign_label, "BENIGN", "MALICIOUS"),
        index=labels.index,
        name="binary_label",
    )


def prepare_single_record(
    record: Union[dict, pd.Series],
    feature_columns: Sequence[str],
    metadata_columns: Optional[Iterable[str]] = None,
    preprocessor: Optional[Pipeline] = None,
):
    if isinstance(record, pd.Series):
        row = record.to_dict()
    elif isinstance(record, dict):
        row = dict(record)
    else:
        raise TypeError("Expected a dictionary or a pandas Series input.")

    row = {str(key).strip(): value for key, value in row.items()}

    if metadata_columns is not None:
        for column in metadata_columns:
            row.pop(str(column).strip(), None)

    missing_features = [column for column in feature_columns if column not in row]
    if missing_features:
        raise KeyError(f"Missing required feature columns: {missing_features}")

    prepared = pd.DataFrame([row], columns=list(feature_columns))
    prepared = prepared.apply(pd.to_numeric, errors="coerce")
    prepared.replace([np.inf, -np.inf], np.nan, inplace=True)

    if preprocessor is not None:
        return preprocessor.transform(prepared)

    return prepared
