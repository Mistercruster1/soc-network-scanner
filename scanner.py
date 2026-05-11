#!/usr/bin/env python3
"""
SOC Network Scanner
Escanea una red o host, detecta puertos abiertos, servicios y genera reporte.
Uso: python3 scanner.py --target 192.168.1.0/24
"""

import nmap
import json
import argparse
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from report_generator import generate_html_report

console = Console()

# ─── Puertos más relevantes para un analista SOC ──────────────────────────────
SOC_PORTS = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5900,8080,8443"

RISK_PORTS = {
    21:   ("FTP",        "alto",   "Transferencia de archivos sin cifrado"),
    22:   ("SSH",        "medio",  "Acceso remoto — verificar versión y auth"),
    23:   ("Telnet",     "alto",   "Protocolo sin cifrado, reemplazar por SSH"),
    25:   ("SMTP",       "medio",  "Servidor de correo — verificar relay abierto"),
    53:   ("DNS",        "medio",  "Verificar transferencias de zona permitidas"),
    80:   ("HTTP",       "medio",  "Tráfico web sin cifrado"),
    139:  ("NetBIOS",    "alto",   "Compartición de archivos Windows — revisar"),
    443:  ("HTTPS",      "bajo",   "Tráfico web cifrado"),
    445:  ("SMB",        "alto",   "Blanco frecuente de ransomware (EternalBlue)"),
    1433: ("MSSQL",      "alto",   "Base de datos expuesta — no debería ser pública"),
    3306: ("MySQL",      "alto",   "Base de datos expuesta — no debería ser pública"),
    3389: ("RDP",        "alto",   "Escritorio remoto — blanco frecuente de fuerza bruta"),
    5900: ("VNC",        "alto",   "Acceso remoto gráfico — frecuentemente sin auth"),
    8080: ("HTTP-Alt",   "medio",  "Puerto web alternativo — verificar aplicación"),
    8443: ("HTTPS-Alt",  "medio",  "Puerto HTTPS alternativo"),
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="SOC Network Scanner — Reconocimiento y análisis de red"
    )
    parser.add_argument("--target", required=True,
                        help="IP, rango CIDR o hostname. Ej: 192.168.1.1 o 192.168.1.0/24")
    parser.add_argument("--ports", default=SOC_PORTS,
                        help="Puertos a escanear (default: puertos SOC comunes)")
    parser.add_argument("--output", default="reports",
                        help="Carpeta de salida para reportes (default: reports/)")
    parser.add_argument("--format", choices=["json", "html", "both"], default="both",
                        help="Formato del reporte (default: both)")
    return parser.parse_args()


def get_risk_level(port):
    info = RISK_PORTS.get(port, ("Desconocido", "info", "Puerto no clasificado"))
    return info


def scan_target(target, ports):
    console.print(Panel(
        f"[bold]Objetivo:[/bold] {target}\n[bold]Puertos:[/bold] {ports}",
        title="SOC Network Scanner",
        border_style="blue"
    ))

    nm = nmap.PortScanner()

    console.print("\n[yellow]Iniciando escaneo...[/yellow]")
    start_time = datetime.now()

    try:
        nm.scan(hosts=target, ports=ports, arguments="-sV -T4 --open")
    except Exception as e:
        console.print(f"[red]Error durante el escaneo: {e}[/red]")
        console.print("[yellow]Tip: En Linux puede requerir sudo. En Windows ejecuta como Administrador.[/yellow]")
        return None

    end_time = datetime.now()
    duration = (end_time - start_time).seconds

    results = {
        "scan_info": {
            "target": target,
            "ports_scanned": ports,
            "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration,
            "hosts_found": len(nm.all_hosts()),
        },
        "hosts": []
    }

    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "hostname": nm[host].hostname() or "N/A",
            "state": nm[host].state(),
            "open_ports": [],
            "risk_summary": {"alto": 0, "medio": 0, "bajo": 0, "info": 0}
        }

        for proto in nm[host].all_protocols():
            ports_list = sorted(nm[host][proto].keys())
            for port in ports_list:
                state = nm[host][proto][port]["state"]
                if state == "open":
                    service = nm[host][proto][port].get("name", "unknown")
                    version = nm[host][proto][port].get("version", "")
                    product = nm[host][proto][port].get("product", "")

                    service_name, risk, description = get_risk_level(port)

                    port_data = {
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "product": f"{product} {version}".strip() or "N/A",
                        "risk": risk,
                        "risk_description": description,
                    }
                    host_data["open_ports"].append(port_data)
                    host_data["risk_summary"][risk] += 1

        results["hosts"].append(host_data)

    results["scan_info"]["total_open_ports"] = sum(
        len(h["open_ports"]) for h in results["hosts"]
    )

    return results


def print_results(results):
    if not results or not results["hosts"]:
        console.print("[yellow]No se encontraron hosts activos.[/yellow]")
        return

    info = results["scan_info"]
    console.print(f"\n[green]✓ Escaneo completado en {info['duration_seconds']}s[/green]")
    console.print(f"  Hosts encontrados: [bold]{info['hosts_found']}[/bold]")
    console.print(f"  Puertos abiertos totales: [bold]{info['total_open_ports']}[/bold]\n")

    risk_colors = {"alto": "red", "medio": "yellow", "bajo": "green", "info": "blue"}

    for host in results["hosts"]:
        table = Table(
            title=f"Host: {host['ip']} ({host['hostname']})",
            box=box.ROUNDED,
            border_style="blue"
        )
        table.add_column("Puerto", style="cyan", width=8)
        table.add_column("Protocolo", width=10)
        table.add_column("Servicio", width=12)
        table.add_column("Versión/Producto", width=25)
        table.add_column("Riesgo", width=8)
        table.add_column("Descripción", width=40)

        for p in host["open_ports"]:
            risk = p["risk"]
            color = risk_colors.get(risk, "white")
            table.add_row(
                str(p["port"]),
                p["protocol"],
                p["service"],
                p["product"],
                f"[{color}]{risk.upper()}[/{color}]",
                p["risk_description"]
            )

        console.print(table)

        summary = host["risk_summary"]
        console.print(
            f"  Resumen de riesgo — "
            f"[red]Alto: {summary['alto']}[/red] | "
            f"[yellow]Medio: {summary['medio']}[/yellow] | "
            f"[green]Bajo: {summary['bajo']}[/green]\n"
        )


def save_results(results, output_dir, fmt):
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_clean = results["scan_info"]["target"].replace("/", "_").replace(".", "-")
    base_name = f"scan_{target_clean}_{timestamp}"

    saved = []

    if fmt in ("json", "both"):
        json_path = Path(output_dir) / f"{base_name}.json"
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        saved.append(str(json_path))
        console.print(f"[green]✓ Reporte JSON:[/green] {json_path}")

    if fmt in ("html", "both"):
        html_path = Path(output_dir) / f"{base_name}.html"
        generate_html_report(results, html_path)
        saved.append(str(html_path))
        console.print(f"[green]✓ Reporte HTML:[/green] {html_path}")

    return saved


def main():
    args = parse_args()
    results = scan_target(args.target, args.ports)

    if results:
        print_results(results)
        save_results(results, args.output, args.format)
        console.print("\n[bold green]Escaneo finalizado.[/bold green]")


if __name__ == "__main__":
    main()
