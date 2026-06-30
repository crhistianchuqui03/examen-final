#!/usr/bin/env python3
"""Predicción de anomalías en tráfico de red — Lab 3.4.

Uso:
    python predecir.py nuevo_trafico.csv
"""

import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

BASE = Path(__file__).parent
MODELO = BASE / "modelo_anomalias.pkl"


def preparar_features(df: pd.DataFrame, le: LabelEncoder, feature_cols: list) -> pd.DataFrame:
    df = df.copy()
    for col in ("bytes_sent", "bytes_recv", "duration_sec", "packets"):
        if col in df.columns:
            limite = df[col].quantile(0.99)
            df[col] = df[col].clip(upper=limite)

    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = (df["bytes_sent"] + df["bytes_recv"]) / (
        df["duration_sec"] + 0.001
    )
    df["packets_por_segundo"] = df["packets"] / (df["duration_sec"] + 0.001)
    df["log_bytes_sent"] = np.log1p(df["bytes_sent"])
    df["log_bytes_recv"] = np.log1p(df["bytes_recv"])

    protocolos = set(le.classes_)
    df["protocol_enc"] = df["protocol"].apply(
        lambda p: le.transform([p])[0] if p in protocolos else -1
    )

    return df[feature_cols]


def main() -> None:
    if len(sys.argv) < 2:
        print("Uso: python predecir.py <archivo.csv>")
        sys.exit(1)

    csv_path = Path(sys.argv[1])
    if not csv_path.exists():
        print(f"Error: no se encontró {csv_path}")
        sys.exit(1)

    if not MODELO.exists():
        print(f"Error: ejecute primero entrenar_modelo.py para generar {MODELO}")
        sys.exit(1)

    artefacto = joblib.load(MODELO)
    model = artefacto["model"]
    scaler = artefacto["scaler"]
    le = artefacto["label_encoder"]
    feature_cols = artefacto["feature_cols"]
    umbral = artefacto.get("umbral_optimo")

    df = pd.read_csv(csv_path)
    X = preparar_features(df, le, feature_cols)
    X_scaled = scaler.transform(X)
    scores = -model.decision_function(X_scaled)
    pred_if = model.predict(X_scaled)

    print("=" * 70)
    print(" PREDICCIÓN DE ANOMALÍAS EN TRÁFICO DE RED")
    print("=" * 70)

    anomalias = 0
    for i, row in df.iterrows():
        es_anomalia = pred_if[i] == -1
        if umbral is not None:
            es_anomalia = scores[i] >= umbral
        if es_anomalia:
            anomalias += 1
            print(f"\n[ANOMALÍA] Registro #{i + 1} | score={scores[i]:.4f}")
            print(f"  timestamp    : {row.get('timestamp', 'N/A')}")
            print(f"  src_ip       : {row.get('src_ip', 'N/A')}")
            print(f"  dst_ip       : {row.get('dst_ip', 'N/A')}")
            print(f"  dst_port     : {row.get('dst_port', 'N/A')}")
            print(f"  protocol     : {row.get('protocol', 'N/A')}")
            print(f"  bytes_sent   : {row.get('bytes_sent', 'N/A')}")
            print(f"  bytes_recv   : {row.get('bytes_recv', 'N/A')}")
            print(f"  duration_sec : {row.get('duration_sec', 'N/A')}")
            print(f"  packets      : {row.get('packets', 'N/A')}")

    print(f"\n--- Resumen: {anomalias}/{len(df)} registros clasificados como anomalía ---")


if __name__ == "__main__":
    main()
