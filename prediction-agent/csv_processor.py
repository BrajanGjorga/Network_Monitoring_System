import json
import math
import logging
from pathlib import Path
from typing import Any, Optional

import pandas as pd


class CSVProcessor:
    def __init__(self, feature_columns: list[str], metadata: dict, logger: Optional[logging.Logger] = None):
        self.feature_columns = feature_columns
        self.metadata = metadata
        self.logger = logger or logging.getLogger(__name__)

    def prepare_row(self, row: dict[str, Any]) -> dict[str, Any]:
        cleaned = {key.strip(): value for key, value in row.items()}
        for feature in self.feature_columns:
            if feature not in cleaned:
                raise ValueError(f"Missing required feature: {feature}")
        prepared = {}
        for feature in self.feature_columns:
            value = cleaned[feature]
            if isinstance(value, str):
                value = value.strip()
                if value == "":
                    value = None
                else:
                    try:
                        value = float(value)
                    except ValueError:
                        value = None
            elif isinstance(value, (int, float)):
                value = float(value)
            prepared[feature] = value
        for feature, value in list(prepared.items()):
            if value is None:
                continue
            if isinstance(value, float) and (math.isinf(value) or math.isnan(value)):
                prepared[feature] = None
        return prepared

    def process_csv(self, csv_path: str) -> list[dict[str, Any]]:
        csv_file = Path(csv_path)
        dataframe = pd.read_csv(csv_file)
        dataframe.columns = [column.strip() for column in dataframe.columns]
        dataframe = dataframe.dropna(how="all")
        if "Label" in dataframe.columns:
            dataframe = dataframe.drop(columns=["Label"])
        rows = []
        for _, row in dataframe.iterrows():
            cleaned = row.to_dict()
            rows.append(cleaned)
        return rows
