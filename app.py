#!/usr/bin/env python3
"""
SOC Network Scanner — Web App
Flask app con historial de escaneos y base de datos SQLite.
"""

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file

from scanner import scan_target, SOC_PORTS
from report_generator import generate_html_report

app = Flask(__name__)

DB_PATH    = Path("data/scans.db")
REPORTS_DIR = Path("reports")

# ─── Base de datos ────────────────────────────────────────────────────────────

def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT    NOT NULL,
            started_at  TEXT    NOT NULL,
            finished_at TEXT,
            status      TEXT    DEFAULT 'running',
            hosts_found INTEGER DEFAULT 0,
            open_ports  INTEGER DEFAULT 0,
            high_risk   INTEGER DEFAULT 0,
            medium_risk INTEGER DEFAULT 0,
            low_risk    INTEGER DEFAULT 0,
            report_html TEXT,
            report_json TEXT,
            error       TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─── Rutas principales ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/history")
def history():
    conn = get_db()
    scans = conn.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return render_template("history.html", scans=scans)


@app.route("/report/<int:scan_id>")
def view_report(scan_id):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan or not scan["report_html"]:
        return "Reporte no encontrado", 404
    return send_file(scan["report_html"])


@app.route("/download/<int:scan_id>/<fmt>")
def download_report(scan_id, fmt):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        return "No encontrado", 404
    path = scan["report_json"] if fmt == "json" else scan["report_html"]
    if not path or not Path(path).exists():
        return "Archivo no encontrado", 404
    return send_file(path, as_attachment=True)


# ─── API de escaneo ───────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def start_scan():
    data    = request.get_json()
    target  = data.get("target", "").strip()
    ports   = data.get("ports", SOC_PORTS).strip()

    if not target:
        return jsonify({"error": "Debes ingresar un target"}), 400

    conn = get_db()
    cur  = conn.execute(
        "INSERT INTO scans (target, started_at, status) VALUES (?, ?, 'running')",
        (target, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    thread = threading.Thread(target=run_scan, args=(scan_id, target, ports))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "running"})


@app.route("/api/scan/<int:scan_id>/status")
def scan_status(scan_id):
    conn = get_db()
    scan = conn.execute(
        "SELECT id, status, hosts_found, open_ports, high_risk, medium_risk, low_risk, error "
        "FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    if not scan:
        return jsonify({"error": "No encontrado"}), 404
    return jsonify(dict(scan))


@app.route("/api/history")
def api_history():
    conn = get_db()
    scans = conn.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(s) for s in scans])


# ─── Worker de escaneo (corre en thread) ─────────────────────────────────────

def run_scan(scan_id, target, ports):
    try:
        results = scan_target(target, ports)

        if not results:
            raise Exception("El escaneo no retornó resultados")

        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_clean = target.replace("/", "_").replace(".", "-")
        base        = f"scan_{target_clean}_{ts}"
        html_path   = str(REPORTS_DIR / f"{base}.html")
        json_path   = str(REPORTS_DIR / f"{base}.json")

        generate_html_report(results, html_path)
        with open(json_path, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        high = sum(h["risk_summary"]["alto"]  for h in results["hosts"])
        med  = sum(h["risk_summary"]["medio"] for h in results["hosts"])
        low  = sum(h["risk_summary"]["bajo"]  for h in results["hosts"])

        conn = get_db()
        conn.execute("""
            UPDATE scans SET
                status      = 'done',
                finished_at = ?,
                hosts_found = ?,
                open_ports  = ?,
                high_risk   = ?,
                medium_risk = ?,
                low_risk    = ?,
                report_html = ?,
                report_json = ?
            WHERE id = ?
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            results["scan_info"]["hosts_found"],
            results["scan_info"]["total_open_ports"],
            high, med, low,
            html_path, json_path,
            scan_id
        ))
        conn.commit()
        conn.close()

    except Exception as e:
        conn = get_db()
        conn.execute(
            "UPDATE scans SET status='error', error=?, finished_at=? WHERE id=?",
            (str(e), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), scan_id)
        )
        conn.commit()
        conn.close()


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n SOC Network Scanner Web App")
    print(" Abre en el browser: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
