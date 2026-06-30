#!/usr/bin/env python3
"""Visualizaciones forenses — Lab 1.3."""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import seaborn as sns

BASE = Path(__file__).parent
AUTH_LOG = BASE / "auth.log"
ACCESS_LOG = BASE / "access.log"
REPORTE_SSH = BASE / "reporte_ssh.json"
GRAFICAS = BASE / "graficas"

PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)"
)
PATRON_LOG = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) \S+" (\d{3})'
)
CODIGOS_HEATMAP = [200, 301, 404, 500]


def cargar_top10_ssh() -> list[tuple[str, int]]:
    if REPORTE_SSH.exists():
        with REPORTE_SSH.open(encoding="utf-8") as f:
            data = json.load(f)
        return [(x["ip"], x["intentos"]) for x in data["ips_sospechosas"]]

    contador: Counter = Counter()
    with AUTH_LOG.open(encoding="utf-8", errors="replace") as f:
        for linea in f:
            if "Failed password" in linea:
                m = PATRON_FALLO.search(linea)
                if m:
                    contador[m.group(1)] += 1
    return contador.most_common(10)


def parsear_access() -> list[dict]:
    registros = []
    with ACCESS_LOG.open(encoding="utf-8", errors="replace") as f:
        for linea in f:
            m = PATRON_LOG.match(linea.strip())
            if not m:
                continue
            ip, ts_raw, _method, _url, codigo = m.groups()
            ts = datetime.strptime(ts_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
            registros.append({"hora": ts.hour, "codigo": int(codigo)})
    return registros


def grafico_top10_ssh(top10: list[tuple[str, int]]) -> None:
    ips = [ip for ip, _ in top10]
    vals = [n for _, n in top10]

    fig, ax = plt.subplots(figsize=(10, 6))
    sns.barplot(x=vals, y=ips, hue=ips, palette="Reds_r", legend=False, ax=ax)
    ax.set_title("Top 10 IPs con más intentos fallidos SSH")
    ax.set_xlabel("Intentos fallidos")
    ax.set_ylabel("Dirección IP")
    plt.tight_layout()
    fig.savefig(GRAFICAS / "top10_ssh.png", dpi=150)
    plt.close(fig)


def grafico_timeline(registros: list[dict]) -> None:
    por_hora = Counter(r["hora"] for r in registros)
    horas = sorted(por_hora.keys())
    conteos = [por_hora[h] for h in horas]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(horas, conteos, marker="o", linewidth=2, color="#2563eb")
    ax.fill_between(horas, conteos, alpha=0.2, color="#2563eb")
    ax.set_title("Peticiones HTTP por hora del día analizado")
    ax.set_xlabel("Hora (UTC)")
    ax.set_ylabel("Número de peticiones")
    ax.set_xticks(horas)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    fig.savefig(GRAFICAS / "timeline_http.png", dpi=150)
    plt.close(fig)


def grafico_heatmap(registros: list[dict]) -> None:
    matriz: dict[int, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    horas = sorted({r["hora"] for r in registros})

    for r in registros:
        if r["codigo"] in CODIGOS_HEATMAP:
            matriz[r["hora"]][r["codigo"]] += 1

    data = []
    for h in horas:
        fila = [matriz[h].get(c, 0) for c in CODIGOS_HEATMAP]
        data.append(fila)

    fig, ax = plt.subplots(figsize=(8, 10))
    sns.heatmap(
        data,
        annot=True,
        fmt="d",
        cmap="YlOrRd",
        xticklabels=[str(c) for c in CODIGOS_HEATMAP],
        yticklabels=[f"{h:02d}:00" for h in horas],
        ax=ax,
    )
    ax.set_title("Peticiones HTTP por hora y código de respuesta")
    ax.set_xlabel("Código HTTP")
    ax.set_ylabel("Hora del día")
    plt.tight_layout()
    fig.savefig(GRAFICAS / "heatmap_http.png", dpi=150)
    plt.close(fig)


def main() -> None:
    GRAFICAS.mkdir(exist_ok=True)
    sns.set_theme(style="whitegrid")

    top10 = cargar_top10_ssh()
    registros = parsear_access()

    grafico_top10_ssh(top10)
    grafico_timeline(registros)
    grafico_heatmap(registros)

    print("Gráficas generadas en lab1/graficas/:")
    for nombre in ("top10_ssh.png", "timeline_http.png", "heatmap_http.png"):
        print(f"  - {GRAFICAS / nombre}")


if __name__ == "__main__":
    main()
