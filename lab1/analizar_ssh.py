#!/usr/bin/env python3
"""Análisis forense de auth.log — intentos fallidos SSH (Lab 1.1)."""

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

AUTH_LOG = Path(__file__).parent / "auth.log"
REPORTE = Path(__file__).parent / "reporte_ssh.json"
UMBRAL_ALERTA = 50

# Failed password for [invalid user ]?<user> from <ip> port <port>
PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)"
)


def analizar_auth_log(ruta: Path) -> Counter:
    contador = Counter()
    with ruta.open(encoding="utf-8", errors="replace") as f:
        for linea in f:
            if "Failed password" not in linea:
                continue
            match = PATRON_FALLO.search(linea)
            if match:
                contador[match.group(1)] += 1
    return contador


def main() -> None:
    if not AUTH_LOG.exists():
        raise FileNotFoundError(f"No se encontró {AUTH_LOG}")

    contador = analizar_auth_log(AUTH_LOG)
    total = sum(contador.values())
    top10 = contador.most_common(10)

    print("=" * 60)
    print(" ANÁLISIS SSH — Intentos fallidos por IP")
    print("=" * 60)
    print(f"Total intentos fallidos: {total}\n")
    print("Ranking Top 10 IPs:")
    for i, (ip, n) in enumerate(top10, 1):
        print(f"  {i:2d}. {ip:<18} {n:4d} intentos")

    print("\n--- Alertas ---")
    for ip, n in contador.items():
        if n > UMBRAL_ALERTA:
            print(
                f"[ALERTA] IP: {ip} — {n} intentos fallidos — "
                "Posible ataque de fuerza bruta"
            )

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total,
        "ips_sospechosas": [
            {"ip": ip, "intentos": n, "alerta": n > UMBRAL_ALERTA}
            for ip, n in top10
        ],
    }

    with REPORTE.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado: {REPORTE}")


if __name__ == "__main__":
    main()
