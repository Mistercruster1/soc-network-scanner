# Metodología de reconocimiento de red — SOC

## Objetivo

Identificar activos expuestos en la red, clasificar el riesgo de los servicios detectados y documentar hallazgos para su gestión como parte del proceso de gestión de superficie de ataque (Attack Surface Management).

## Fases

### 1. Descubrimiento de hosts
Identificar qué IPs están activas en el rango objetivo usando ICMP y TCP SYN probes.

### 2. Escaneo de puertos
Verificar puertos TCP más relevantes para operaciones SOC, priorizando los vectores de ataque más frecuentes en incidentes reales.

### 3. Identificación de servicios
Obtener banner y versión de cada servicio para detectar software desactualizado o mal configurado.

### 4. Clasificación de riesgo
Cada puerto se clasifica según:
- **Alto**: servicios sin cifrado, vectores de ransomware conocidos, BBDD expuestas
- **Medio**: servicios que requieren revisión de configuración
- **Bajo**: servicios normalmente seguros pero que requieren monitoreo

### 5. Documentación
Generar reporte con hallazgos, clasificación y recomendaciones para el equipo de respuesta.

## Referencias
- OWASP Attack Surface Analysis
- PTES (Penetration Testing Execution Standard)
- MITRE ATT&CK — Discovery Tactic (TA0007)
