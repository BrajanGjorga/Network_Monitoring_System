from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import pandas as pd


class CSVProcessor:
    """Read CICFlowMeter CSV files and perform file-level cleanup only.

    Model-specific validation, numeric conversion, feature ordering, infinity
    handling, and imputation are intentionally handled by Predictor so the
    deployment path matches the training path.
    """

    def __init__(self, logger: Optional[logging.Logger] = None) -> None:
        self.logger = logger or logging.getLogger(__name__)

    def read_csv(self, csv_path: str | Path) -> pd.DataFrame:
        csv_file = Path(csv_path)

        if not csv_file.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_file}")
        if not csv_file.is_file():
            raise ValueError(f"CSV path is not a file: {csv_file}")

        dataframe = pd.read_csv(csv_file, low_memory=False)
        dataframe.columns = [str(column).strip() for column in dataframe.columns]
        dataframe = dataframe.dropna(how="all").reset_index(drop=True)

        duplicated = dataframe.columns[dataframe.columns.duplicated()].tolist()
        if duplicated:
            raise ValueError(f"Duplicate CSV columns detected: {duplicated}")

        # A live CICFlowMeter file normally has no Label column, but dropping it
        # makes the pipeline safe for labeled test files too.
        label_columns = [
            column
            for column in dataframe.columns
            if str(column).strip().lower() in {"label", "attack"}
        ]
        if label_columns:
            dataframe = dataframe.drop(columns=label_columns)

        if dataframe.empty:
            self.logger.warning("CSV file contains no usable rows: %s", csv_file)

        return dataframe
