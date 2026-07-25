# CSE-CIC-IDS2018 training project

This starter project trains simple machine-learning models for the CSE-CIC-IDS2018 intrusion-detection dataset.

## Project layout

- notebooks/train_model.ipynb: the main beginner-friendly training workflow
- src/: reusable preprocessing, data loading, and artifact export logic
- data/: place the dataset CSV files here or use the workspace-level CSE-dataset folder
- artifacts/: exported model and evaluation artifacts

## Setup

From this folder, install the dependencies:

```bash
pip install -r requirements.txt
```

## Dataset location

Place the CSV files in:

- model-training/data/
- or the workspace-level CSE-dataset folder

## Run the notebook

Open the notebook with Jupyter:

```bash
jupyter notebook notebooks/train_model.ipynb
```

## Mode selection

At the top of the notebook, set:

- MODE = "binary" for BENIGN vs MALICIOUS
- MODE = "multiclass" for BENIGN plus individual attack categories

## Exported artifacts

The notebook writes the following artifacts to the artifacts folder:

- model.pkl
- scaler.pkl
- feature_columns.json
- label_encoder.pkl
- model_metadata.json
- evaluation.json

## Important limitations

- This project is intended as a beginner-friendly training example.
- The model should not be considered production-ready based on dataset evaluation alone.
- The notebook avoids leakage and keeps class balancing only in the training split.
- Do not load pickle files from untrusted sources.
