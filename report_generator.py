#!/usr/bin/env python3
"""
Genera reportes HTML profesionales a partir de los resultados del scanner.
"""

from jinja2 import Template
from pathlib import Path

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Scan Report — {{ info.target }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f1117; color: #e2e8f0; padding: 2rem; }
  .header { border-left: 4px solid #3b82f6; padding: 1rem 1.5rem;
            background: #1e2433; border-radius: 0 8px 8px 0; margin-bottom: 2rem; }
  .header h1 { font-size: 1.5rem; color: #60a5fa; }
  .header p  { color: #94a3b8; font-size: 0.9rem; margin-top: 4px; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
          gap: 1rem; margin-bottom: 2rem; }
  .meta-card { background: #1e2433; border-radius: 8px; padding: 1rem;
               border: 1px solid #2d3748; }
  .meta-card .label { font-size: 0.75rem; color: #64748b; text-transform: uppercase;
                      letter-spacing: .05em; }
  .meta-card .value { font-size: 1.4rem; font-weight: 600; margin-top: 4px; }
  .host-block { background: #1e2433; border-radius: 8px; margin-bottom: 1.5rem;
                border: 1px solid #2d3748; overflow: hidden; }
  .host-header { padding: 1rem 1.5rem; background: #252d3d;
                 border-bottom: 1px solid #2d3748; }
  .host-header h2 { font-size: 1rem; color: #60a5fa; }
  table { width: 100%; border-collapse: collapse; }
  th { padding: .6rem 1rem; text-align: left; font-size: .75rem;
       text-transform: uppercase; color: #64748b; background: #1a2030;
       border-bottom: 1px solid #2d3748; }
  td { padding: .7rem 1rem; font-size: .875rem; border-bottom: 1px solid #1a2030; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #252d3d; }
  .risk-alto   { color: #f87171; font-weight: 600; }
  .risk-medio  { color: #fbbf24; font-weight: 600; }
  .risk-bajo   { color: #34d399; font-weight: 600; }
  .risk-info   { color: #60a5fa; font-weight: 600; }
  .port-num { font-family: monospace; color: #a78bfa; }
  .summary { display: flex; gap: 1rem; padding: 1rem 1.5rem;
             background: #161c2a; flex-wrap: wrap; }
  .summary span { font-size: .8rem; padding: 3px 10px; border-radius: 20px; }
  .s-alto  { background: rgba(248,113,113,.15); color: #f87171; }
  .s-medio { background: rgba(251,191,36,.15);  color: #fbbf24; }
  .s-bajo  { background: rgba(52,211,153,.15);  color: #34d399; }
  .footer { text-align: center; color: #334155; font-size: .8rem; margin-top: 2rem; }
</style>
</head>
<body>

<div class="header">
  <h1>SOC Network Scan Report</h1>
  <p>Objetivo: {{ info.target }} &nbsp;|&nbsp; {{ info.start_time }} &nbsp;|&nbsp; Duración: {{ info.duration_seconds }}s</p>
</div>

<div class="meta">
  <div class="meta-card">
    <div class="label">Hosts encontrados</div>
    <div class="value" style="color:#60a5fa;">{{ info.hosts_found }}</div>
  </div>
  <div class="meta-card">
    <div class="label">Puertos abiertos</div>
    <div class="value" style="color:#a78bfa;">{{ info.total_open_ports }}</div>
  </div>
  <div class="meta-card">
    <div class="label">Puertos alto riesgo</div>
    <div class="value" style="color:#f87171;">
      {{ hosts | sum(attribute='risk_summary.alto') }}
    </div>
  </div>
  <div class="meta-card">
    <div class="label">Duración escaneo</div>
    <div class="value" style="color:#34d399;">{{ info.duration_seconds }}s</div>
  </div>
</div>

{% for host in hosts %}
<div class="host-block">
  <div class="host-header">
    <h2>{{ host.ip }} {% if host.hostname != 'N/A' %}({{ host.hostname }}){% endif %}</h2>
  </div>

  {% if host.open_ports %}
  <table>
    <thead>
      <tr>
        <th>Puerto</th>
        <th>Protocolo</th>
        <th>Servicio</th>
        <th>Versión</th>
        <th>Riesgo</th>
        <th>Descripción</th>
      </tr>
    </thead>
    <tbody>
      {% for p in host.open_ports %}
      <tr>
        <td class="port-num">{{ p.port }}</td>
        <td>{{ p.protocol }}</td>
        <td>{{ p.service }}</td>
        <td style="color:#94a3b8;">{{ p.product }}</td>
        <td class="risk-{{ p.risk }}">{{ p.risk | upper }}</td>
        <td style="color:#94a3b8; font-size:.8rem;">{{ p.risk_description }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  <div class="summary">
    <span class="s-alto">Alto: {{ host.risk_summary.alto }}</span>
    <span class="s-medio">Medio: {{ host.risk_summary.medio }}</span>
    <span class="s-bajo">Bajo: {{ host.risk_summary.bajo }}</span>
  </div>
  {% else %}
  <p style="padding:1rem;color:#64748b;">Sin puertos abiertos detectados.</p>
  {% endif %}
</div>
{% endfor %}

<div class="footer">
  Generado por SOC Network Scanner &nbsp;|&nbsp; {{ info.end_time }}
</div>

</body>
</html>
"""

def generate_html_report(results, output_path):
    template = Template(HTML_TEMPLATE)
    html = template.render(
        info=results["scan_info"],
        hosts=results["hosts"]
    )
    Path(output_path).write_text(html, encoding="utf-8")
