"""Embedded Layer 4 implementation from the prototype ML workbench.

The Streamlit UI is intentionally excluded. These functions preserve the
prototype's preprocessing, model, inference, and risk-scoring behavior.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def find_target_column(frame: pd.DataFrame, target_column: str | None = None) -> str:
    if target_column:
        if target_column not in frame.columns:
            raise ValueError(f"Target column '{target_column}' was not found.")
        return target_column
    for column in frame.columns:
        if column.lower() in {"label", "target", "class", "attack", "y"}:
            return column
    raise ValueError(
        "Could not find the target column. Expected one of: Label, Target, Class, Attack."
    )


def prepare_dataset(
    frame: pd.DataFrame, target_column: str | None = None
) -> tuple[pd.DataFrame, pd.Series, str, dict[str, float]]:
    frame = frame.copy()
    frame.columns = frame.columns.astype(str).str.strip()
    target_name = find_target_column(frame, target_column)
    target = frame.pop(target_name).astype(str).str.strip().str.casefold().ne("benign").astype(int)
    features = frame.apply(pd.to_numeric, errors="coerce")
    features = features.replace([np.inf, -np.inf], np.nan).dropna(axis=1, how="all")
    if features.shape[1] == 0:
        raise ValueError("No numeric feature columns were found in the CSV.")
    fill_values = features.median(numeric_only=True).fillna(0.0).to_dict()
    features = features.fillna(fill_values).fillna(0.0).astype(float)
    if target.nunique() < 2:
        raise ValueError("Training requires both BENIGN and attack rows.")
    return features, target, target_name, fill_values


def split_and_scale(
    features: pd.DataFrame, target: pd.Series, random_state: int = 42
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, StandardScaler]:
    x_train, x_test, y_train, y_test = train_test_split(
        features, target, test_size=0.2, random_state=random_state, stratify=target
    )
    scaler = StandardScaler()
    x_train_scaled = pd.DataFrame(
        scaler.fit_transform(x_train), columns=features.columns, index=x_train.index
    )
    x_test_scaled = pd.DataFrame(
        scaler.transform(x_test), columns=features.columns, index=x_test.index
    )
    return x_train_scaled, x_test_scaled, y_train, y_test, scaler


def save_preprocessing(
    scaler: StandardScaler,
    feature_columns: list[str],
    fill_values: dict[str, float],
    target_column: str,
    artifact_dir: str | Path,
) -> None:
    directory = Path(artifact_dir)
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, directory / "scaler.joblib")
    joblib.dump(
        {
            "feature_columns": feature_columns,
            "fill_values": fill_values,
            "target_column": target_column,
        },
        directory / "preprocessing.joblib",
    )


def train_random_forest(
    x_train: pd.DataFrame, y_train: pd.Series, artifact_dir: str | Path
) -> RandomForestClassifier:
    model = RandomForestClassifier(
        n_estimators=100, random_state=42, class_weight="balanced", n_jobs=-1
    )
    model.fit(x_train, y_train)
    Path(artifact_dir).mkdir(parents=True, exist_ok=True)
    joblib.dump(model, Path(artifact_dir) / "random_forest.joblib")
    return model


def train_isolation_forest(
    x_train: pd.DataFrame, y_train: pd.Series, artifact_dir: str | Path
) -> IsolationForest:
    normal_rows = x_train.loc[y_train == 0]
    if normal_rows.empty:
        raise ValueError("Isolation Forest requires at least one BENIGN training row.")
    model = IsolationForest(random_state=42, contamination="auto", n_estimators=100)
    model.fit(normal_rows)
    Path(artifact_dir).mkdir(parents=True, exist_ok=True)
    joblib.dump(model, Path(artifact_dir) / "isolation_forest.joblib")
    return model


def _prepared_row(
    features_dict: dict[str, float],
    artifact_dir: str | Path,
    loaded: tuple[Any, Any] | None = None,
) -> tuple[pd.DataFrame, StandardScaler]:
    directory = Path(artifact_dir)
    scaler, metadata = loaded if loaded else (
        joblib.load(directory / "scaler.joblib"),
        joblib.load(directory / "preprocessing.joblib"),
    )
    row = pd.DataFrame(
        [{column: features_dict.get(column, np.nan) for column in metadata["feature_columns"]}]
    )
    row = row.apply(pd.to_numeric, errors="coerce").fillna(
        metadata["fill_values"]
    ).fillna(0.0)
    return row, scaler


def predict_flow(
    features_dict: dict[str, float],
    artifact_dir: str | Path,
    loaded: tuple[Any, Any, Any, dict[str, Any]] | None = None,
) -> float:
    directory = Path(artifact_dir)
    model = loaded[0] if loaded else joblib.load(directory / "random_forest.joblib")
    row, scaler = _prepared_row(features_dict, directory, loaded[2:] if loaded else None)
    scaled = pd.DataFrame(scaler.transform(row), columns=row.columns)
    return float(model.predict_proba(scaled)[:, 1][0])


def predict_anomaly(
    features_dict: dict[str, float],
    artifact_dir: str | Path,
    loaded: tuple[Any, Any, Any, dict[str, Any]] | None = None,
) -> dict[str, float | int]:
    directory = Path(artifact_dir)
    model = loaded[1] if loaded else joblib.load(directory / "isolation_forest.joblib")
    row, scaler = _prepared_row(features_dict, directory, loaded[2:] if loaded else None)
    scaled = pd.DataFrame(scaler.transform(row), columns=row.columns)
    raw_prediction = int(model.predict(scaled)[0])
    decision_score = float(model.decision_function(scaled)[0])
    anomaly_score = float(np.clip(0.5 - decision_score, 0.0, 1.0))
    return {"is_anomaly": int(raw_prediction == -1), "anomaly_score": anomaly_score}


def calculate_risk(supervised_probability: float, anomaly_score: float) -> dict[str, float | str]:
    supervised_probability = max(0.0, min(1.0, supervised_probability))
    anomaly_score = max(0.0, min(1.0, anomaly_score))
    risk_score = (0.7 * supervised_probability) + (0.3 * anomaly_score)
    severity = "HIGH" if risk_score >= 0.7 else "MEDIUM" if risk_score >= 0.4 else "LOW"
    return {
        "risk_score": risk_score,
        "severity": severity,
        "supervised_probability": supervised_probability,
        "anomaly_score": anomaly_score,
    }
