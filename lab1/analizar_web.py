#!/usr/bin/env python3
"""Análisis forense de access.log Apache — Lab 1.2."""

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

ACCESS_LOG = Path(__file__).parent / "access.log"
REPORTE = Path(__file__).parent / "reporte_web.json"

# Combined Log Format
PATRON_LOG = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) \S+" (\d{3})'
)

PATRONES_SQLI = {
    "UNION": re.compile(r"UNION", re.IGNORECASE),
    "SELECT": re.compile(r"SELECT", re.IGNORECASE),
    "--": re.compile(r"--"),
    "OR 1=1": re.compile(r"OR\s+1\s*=\s*1", re.IGNORECASE),
    "'": re.compile(r"'"),
}


def parsear_timestamp(raw: str) -> datetime:
    return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S")


def parsear_log(ruta: Path) -> list[dict]:
    registros = []
    with ruta.open(encoding="utf-8", errors="replace") as f:
        for num, linea in enumerate(f, 1):
            match = PATRON_LOG.match(linea.strip())
            if not match:
                continue
            ip, ts_raw, _method, url, codigo = match.groups()
            registros.append(
                {
                    "linea": num,
                    "ip": ip,
                    "timestamp": parsear_timestamp(ts_raw),
                    "url": unquote(url),
                    "codigo": int(codigo),
                }
            )
    return registros


def detectar_escaneo(registros: list[dict]) -> list[dict]:
    """>20 rutas distintas en <60 s desde la misma IP."""
    por_ip: dict[str, list[dict]] = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append(r)

    hallazgos = []
    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda x: x["timestamp"])
        for i, inicio in enumerate(eventos):
            ventana_fin = inicio["timestamp"] + timedelta(seconds=60)
            rutas = set()
            peticiones = []
            for ev in eventos[i:]:
                if ev["timestamp"] > ventana_fin:
                    break
                rutas.add(ev["url"].split("?")[0])
                peticiones.append(ev)

            if len(rutas) > 20 or (len(rutas) >= 15 and len(peticiones) > 20):
                hallazgos.append(
                    {
                        "ip": ip,
                        "inicio": inicio["timestamp"].isoformat(),
                        "fin": peticiones[-1]["timestamp"].isoformat(),
                        "rutas_distintas": len(rutas),
                        "total_peticiones": len(peticiones),
                        "rutas_muestra": sorted(rutas)[:25],
                    }
                )
                break
    return hallazgos


def agrupar_errores(registros: list[dict]) -> dict:
    errores: dict[str, dict] = defaultdict(lambda: {"4xx": 0, "5xx": 0, "total": 0})
    for r in registros:
        if 400 <= r["codigo"] < 500:
            errores[r["ip"]]["4xx"] += 1
            errores[r["ip"]]["total"] += 1
        elif 500 <= r["codigo"] < 600:
            errores[r["ip"]]["5xx"] += 1
            errores[r["ip"]]["total"] += 1
    return dict(errores)


def detectar_sqli(registros: list[dict]) -> list[dict]:
    hallazgos = []
    for r in registros:
        url = r["url"]
        patrones = [nombre for nombre, rx in PATRONES_SQLI.items() if rx.search(url)]
        if patrones:
            hallazgos.append(
                {
                    "ip": r["ip"],
                    "linea": r["linea"],
                    "url": url,
                    "codigo": r["codigo"],
                    "patrones": patrones,
                    "timestamp": r["timestamp"].isoformat(),
                }
            )
    return hallazgos


def main() -> None:
    if not ACCESS_LOG.exists():
        raise FileNotFoundError(f"No se encontró {ACCESS_LOG}")

    registros = parsear_log(ACCESS_LOG)
    escaneos = detectar_escaneo(registros)
    errores = agrupar_errores(registros)
    sqli = detectar_sqli(registros)

    print("=" * 60)
    print(" ANÁLISIS WEB — access.log Apache")
    print("=" * 60)
    print(f"Total peticiones parseadas: {len(registros)}")

    print(f"\n--- Escaneo de directorios ({len(escaneos)} detectados) ---")
    for e in escaneos:
        print(
            f"  [ESCANEO] IP: {e['ip']} — {e['rutas_distintas']} rutas distintas "
            f"en {e['total_peticiones']} peticiones ({e['inicio']} -> {e['fin']})"
        )

    print(f"\n--- Errores 4xx/5xx ({len(errores)} IPs) ---")
    top_errores = sorted(errores.items(), key=lambda x: x[1]["total"], reverse=True)[:5]
    for ip, stats in top_errores:
        print(f"  {ip}: 4xx={stats['4xx']}, 5xx={stats['5xx']}, total={stats['total']}")

    print(f"\n--- SQL Injection ({len(sqli)} intentos) ---")
    for s in sqli[:10]:
        print(f"  [SQLi] IP: {s['ip']} | {s['url'][:70]} | patrones: {s['patrones']}")
    if len(sqli) > 10:
        print(f"  ... y {len(sqli) - 10} más")

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones": len(registros),
        "escaneo_directorios": escaneos,
        "errores_por_ip": errores,
        "intentos_sqli": sqli,
        "resumen": {
            "ips_con_escaneo": len(escaneos),
            "total_intentos_sqli": len(sqli),
            "ips_con_errores": len(errores),
        },
    }

    with REPORTE.open("w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\nReporte exportado: {REPORTE}")


if __name__ == "__main__":
    main()
