from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence, Union

import pandas as pd


def resolve_data_dir(data_dir: Optional[Union[str, Path]] = None) -> Path:
    """Resolve the directory that contains the CSV files."""
    project_root = Path(__file__).resolve().parents[1]
    candidates: List[Path] = []

    if data_dir is not None:
        candidates.append(Path(data_dir))

    candidates.extend(
        [
            project_root / "data",
            project_root.parent / "CSE-dataset",
            project_root / ".." / "CSE-dataset",
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            csv_files = sorted(candidate.rglob("*.csv"))
            if csv_files:
                return candidate.resolve()

    if data_dir is not None and Path(data_dir).exists():
        return Path(data_dir).resolve()

    raise FileNotFoundError(
        "No data directory was found. Place the CSV files in the project data/ folder or in ../CSE-dataset."
    )


def discover_csv_files(data_dir: Optional[Union[str, Path]] = None, pattern: str = "*.csv") -> List[Path]:
    """Return all CSV files in the target directory."""
    data_path = resolve_data_dir(data_dir)
    return sorted(data_path.rglob(pattern))


def load_csv_files(csv_paths: Sequence[Union[str, Path]], **read_csv_kwargs) -> pd.DataFrame:
    """Load and concatenate multiple CSV files into a single dataframe."""
    if not csv_paths:
        raise ValueError("No CSV files were supplied.")

    frames = []
    for path in csv_paths:
        frames.append(pd.read_csv(path, low_memory=False, **read_csv_kwargs))

    return pd.concat(frames, ignore_index=True)


def summarize_csv_files(csv_paths: Sequence[Union[str, Path]]) -> pd.DataFrame:
    """Create a compact overview of the discovered files."""
    rows = []
    for path in csv_paths:
        dataframe = pd.read_csv(path, nrows=5, low_memory=False)
        rows.append(
            {
                "file": Path(path).name,
                "rows": len(dataframe),
                "columns": list(dataframe.columns),
            }
        )
    return pd.DataFrame(rows)
