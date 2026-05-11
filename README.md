# SOC Network Scanner 🔍

Herramienta de reconocimiento de red orientada a operaciones SOC. Escanea hosts y rangos de red, detecta puertos abiertos, identifica servicios y clasifica el nivel de riesgo de cada puerto según criterios de seguridad. Genera reportes en JSON y HTML.

## Contexto SOC

En un SOC, el reconocimiento de red es el primer paso para entender la superficie de ataque de una organización. Esta herramienta automatiza ese proceso y genera reportes que pueden integrarse directamente en un flujo de gestión de incidentes.

## Funcionalidades

- Escaneo de IPs individuales o rangos CIDR completos
- Detección de servicios y versiones con nmap `-sV`
- Clasificación de riesgo por puerto (Alto / Medio / Bajo)
- Reporte HTML con tabla interactiva y resumen ejecutivo
- Reporte JSON para integración con otras herramientas SOC
- Salida en terminal con colores usando Rich

## Instalación

```bash
git clone git@github.com:tu-usuario/soc-network-scanner.git
cd soc-network-scanner
pip install -r requirements.txt
```

> Requiere nmap instalado en el sistema: `sudo apt install nmap` (Linux) o desde nmap.org (Windows)

## Uso

```bash
# Escanear una IP
python3 scanner.py --target 192.168.1.1

# Escanear un rango de red
python3 scanner.py --target 192.168.1.0/24

# Solo reporte JSON
python3 scanner.py --target 192.168.1.1 --format json

# Puertos personalizados
python3 scanner.py --target 10.0.0.1 --ports 22,80,443,3389
```

## Puertos monitoreados y niveles de riesgo

| Puerto | Servicio | Riesgo | Razón |
|--------|----------|--------|-------|
| 445 | SMB | Alto | Vector de ransomware (EternalBlue) |
| 3389 | RDP | Alto | Blanco frecuente de fuerza bruta |
| 23 | Telnet | Alto | Sin cifrado |
| 3306/1433 | MySQL/MSSQL | Alto | BBDD no debería ser pública |
| 22 | SSH | Medio | Verificar versión y autenticación |
| 80 | HTTP | Medio | Sin cifrado |
| 443 | HTTPS | Bajo | Tráfico cifrado |

## Output de ejemplo

```
╭─────────────────────────────────╮
│ Host: 192.168.1.1 (router.local) │
├───────┬──────────┬───────┬───────┤
│ 22    │ SSH      │ MEDIO │ ...   │
│ 80    │ HTTP     │ MEDIO │ ...   │
│ 443   │ HTTPS    │ BAJO  │ ...   │
╰───────┴──────────┴───────┴───────╯
Resumen — Alto: 0 | Medio: 2 | Bajo: 1
```

## Estructura del proyecto

```
soc-network-scanner/
├── scanner.py           # Script principal
├── report_generator.py  # Generador de reportes HTML
├── requirements.txt
├── reports/             # Output de escaneos (ignorado en git)
└── docs/
    └── methodology.md   # Metodología de análisis
```

## Disclaimer

Usar únicamente en redes propias o con autorización explícita. El escaneo no autorizado de redes es ilegal.

---
*Proyecto 1 del portafolio SOC — parte del [soc-lab-environment](../)*
