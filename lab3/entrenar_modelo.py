#!/usr/bin/env python3
"""Entrena Isolation Forest y exporta modelo_anomalias.pkl (Lab 3.4)."""

import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler

BASE = Path(__file__).parent
DATASET = BASE / "network_traffic.csv"
MODELO = BASE / "modelo_anomalias.pkl"


def cargar_y_preprocesar() -> tuple[pd.DataFrame, pd.Series, list[str]]:
    df = pd.read_csv(DATASET)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Tratar outliers extremos (percentil 99)
    for col in ("bytes_sent", "bytes_recv", "duration_sec", "packets"):
        limite = df[col].quantile(0.99)
        df[col] = df[col].clip(upper=limite)

    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = (df["bytes_sent"] + df["bytes_recv"]) / (
        df["duration_sec"] + 0.001
    )
    df["packets_por_segundo"] = df["packets"] / (df["duration_sec"] + 0.001)
    df["log_bytes_sent"] = np.log1p(df["bytes_sent"])
    df["log_bytes_recv"] = np.log1p(df["bytes_recv"])

    le = LabelEncoder()
    df["protocol_enc"] = le.fit_transform(df["protocol"])

    feature_cols = [
        "dst_port",
        "bytes_sent",
        "bytes_recv",
        "duration_sec",
        "packets",
        "ratio_bytes",
        "bytes_por_segundo",
        "packets_por_segundo",
        "log_bytes_sent",
        "log_bytes_recv",
        "protocol_enc",
    ]

    X = df[feature_cols].copy()
    y = (df["label"] == "anomaly").astype(int)

    scaler = StandardScaler()
    X_scaled = pd.DataFrame(
        scaler.fit_transform(X), columns=feature_cols, index=df.index
    )

    return df, X_scaled, y, feature_cols, scaler, le


def main() -> None:
    df, X_scaled, y, feature_cols, scaler, le = cargar_y_preprocesar()

    model = IsolationForest(
        contamination=0.04,
        n_estimators=200,
        random_state=42,
    )
    model.fit(X_scaled)

    pred = model.predict(X_scaled)
    y_pred = (pred == -1).astype(int)

    print("Métricas (Isolation Forest default):")
    print(f"  Precision: {precision_score(y, y_pred):.4f}")
    print(f"  Recall:    {recall_score(y, y_pred):.4f}")
    print(f"  F1-Score:  {f1_score(y, y_pred):.4f}")
    print("\nMatriz de confusión:")
    print(confusion_matrix(y, y_pred))

    scores = -model.decision_function(X_scaled)
    umbrales = np.linspace(scores.min(), scores.max(), 200)
    best_f1, best_umbral = 0.0, 0.0
    for umbral in umbrales:
        pred_u = (scores >= umbral).astype(int)
        f1 = f1_score(y, pred_u, zero_division=0)
        if f1 > best_f1:
            best_f1, best_umbral = f1, umbral

    print(f"\nUmbral óptimo F1: {best_umbral:.6f} (F1={best_f1:.4f})")

    artefacto = {
        "model": model,
        "scaler": scaler,
        "label_encoder": le,
        "feature_cols": feature_cols,
        "umbral_optimo": best_umbral,
    }
    joblib.dump(artefacto, MODELO)
    print(f"\nModelo guardado: {MODELO}")


if __name__ == "__main__":
    main()
