# 🛡️ CyberToolkit

> Suite educativa de ciberseguridad con 10 herramientas operativas para aprendizaje práctico en entornos controlados.

---

## ⚠️ Aviso Legal y Ético

Este proyecto es **exclusivamente educativo**. Todas las herramientas están diseñadas para ser utilizadas en entornos propios y controlados (laboratorios, VMs, redes locales de prueba). El uso no autorizado sobre sistemas ajenos **es ilegal** y puede acarrear consecuencias civiles y penales graves. El autor no se responsabiliza del mal uso de este software.

**Antes de ejecutar cualquier herramienta:** asegurate de tener autorización explícita sobre el sistema o red que vas a analizar.

---

## 📋 Descripción

CyberToolkit es una suite de 10 herramientas de ciberseguridad accesibles desde un único menú interactivo de línea de comandos. Está pensada para estudiantes y profesionales que quieran aprender conceptos fundamentales de seguridad informática — redes, criptografía, forense digital, OSINT — programando y ejecutando herramientas reales.

**v1.0 — 10/10 herramientas implementadas y operativas.**

---

## 🗂️ Estructura del Proyecto

```
CyberToolkit/
├── README.md                    # Este archivo
├── requirements.txt             # Dependencias externas con versiones exactas
├── main.py                      # Punto de entrada — menú interactivo principal
├── utils.py                     # Funciones compartidas: colores, validaciones, banners
├── config.py                    # Constantes globales: puertos, diccionarios, configuración
└── tools/
    ├── __init__.py
    ├── port_scanner.py          # 1. Escáner de puertos TCP
    ├── password_checker.py      # 2. Verificador de fortaleza de contraseñas
    ├── hash_tool.py             # 3. Generador / verificador de hashes
    ├── url_analyzer.py          # 4. Analizador de URLs sospechosas
    ├── file_integrity.py        # 5. Monitor de integridad de archivos (HIDS)
    ├── packet_sniffer.py        # 6. Sniffer básico de paquetes [requiere root]
    ├── file_encryptor.py        # 7. Cifrador / descifrador AES-256-GCM
    ├── metadata_extractor.py    # 8. Extractor de metadatos EXIF / PDF / DOCX
    ├── password_generator.py    # 9. Generador de contraseñas y frases Diceware
    └── entropy_calc.py          # 10. Calculadora de entropía de archivos
```

---

## 🧰 Herramientas — v1.0

### Fase 1 — Sin dependencias externas

| # | Módulo | Conceptos clave |
|---|--------|-----------------|
| 2 | `password_checker.py` — Verificador de contraseñas | Entropía, hashing, fuerza bruta, diccionarios, PBKDF2 |
| 3 | `hash_tool.py` — Hashes MD5 / SHA-1 / SHA-256 / SHA-512 | Funciones hash, integridad, forense, colisiones |
| 9 | `password_generator.py` — Generador seguro + Diceware | `secrets`, entropía, aleatoriedad criptográfica |
| 10 | `entropy_calc.py` — Entropía de Shannon de archivos | Entropía, detección de malware, análisis estadístico |

### Fase 2 — Red y análisis de archivos

| # | Módulo | Conceptos clave |
|---|--------|-----------------|
| 1 | `port_scanner.py` — Escáner TCP con concurrencia | TCP, three-way handshake, sockets, `ThreadPoolExecutor` |
| 4 | `url_analyzer.py` — Analizador de URLs / phishing | HTTP, TLS, DNS, homógrafos, cabeceras de seguridad |
| 5 | `file_integrity.py` — Monitor HIDS con baseline JSON | HIDS, SHA-256, timestomping, persistencia de malware |
| 8 | `metadata_extractor.py` — EXIF / GPS / PDF / DOCX | OSINT, privacidad, forense, metadatos ocultos |

### Fase 3 — Criptografía y captura de tráfico

| # | Módulo | Conceptos clave |
|---|--------|-----------------|
| 7 | `file_encryptor.py` — AES-256-GCM + PBKDF2 | Cifrado simétrico, modos autenticados, derivación de clave |
| 6 | `packet_sniffer.py` — Sniffer TCP/UDP/DNS | Raw sockets, modo promiscuo, filtros BPF, texto plano |

---

## ⚙️ Instalación

### Prerrequisitos

- Python **3.10** o superior
- pip
- Privilegios de administrador/root para el sniffer de paquetes (herramienta 6)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/CyberToolkit.git
cd CyberToolkit

# 2. Crear y activar entorno virtual
python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 3. Instalar dependencias
pip install -r requirements.txt
```

### Instalación mínima (sin dependencias externas)

Las herramientas 2, 3, 9 y 10 funcionan únicamente con la librería estándar de Python:

```bash
python main.py   # herramientas 2, 3, 9 y 10 operativas de inmediato
```

---

## ▶️ Uso

```bash
# Uso estándar
python main.py

# Con privilegios root (necesario para el sniffer de paquetes)
sudo python main.py
```

Se mostrará el banner del proyecto y el menú interactivo. Seleccioná el número de la herramienta y seguí las instrucciones en pantalla. `Ctrl+C` en cualquier momento vuelve al menú principal sin cerrar el programa.

### Ejemplos rápidos por herramienta

```bash
# 1 — Escanear puertos de un host
# Seleccionar [1] → ingresar 192.168.1.1 → rango 1-1024

# 3 — Calcular SHA-256 de un archivo
# Seleccionar [3] → [1] → ruta del archivo → algoritmo SHA-256

# 5 — Crear baseline de integridad
# Seleccionar [5] → [1] → directorio a monitorear

# 6 — Sniffing de paquetes (requiere root)
sudo python main.py
# Seleccionar [6] → [1] → interfaz eth0 → filtro: tcp port 80

# 7 — Cifrar un archivo
# Seleccionar [7] → [1] → ruta del archivo → contraseña fuerte

# 8 — Extraer metadatos GPS de una foto
# Seleccionar [8] → [1] → ruta de la imagen .jpg
```

---

## 📦 Dependencias

```
colorama==0.4.6
requests==2.33.1
scapy==2.7.0
cryptography==46.0.6
Pillow==12.1.1
PyPDF2==3.0.1
python-docx==1.2.0
```

> Las herramientas 2, 3, 9 y 10 funcionan sin ninguna dependencia externa.

---

## 🗺️ Roadmap

---

### ✅ v1.0 — Completado

- [x] Infraestructura: `utils.py`, `config.py`, `main.py`, menú interactivo, manejo de `Ctrl+C`
- [x] **10 herramientas operativas** (ver tabla de herramientas)
- [x] Sistema de colores y UX consistente con `colorama`
- [x] Explicaciones didácticas integradas en cada herramienta
- [x] Detección automática de riesgos de privacidad (GPS, credenciales, software)

---

### 🔜 v1.1 — Mejoras de infraestructura

- [ ] **Exportación de resultados** — guardar salidas en `.txt`, `.json` y `.html` desde cualquier herramienta
- [ ] **Modo batch** — procesar múltiples IPs, archivos o URLs desde un fichero de entrada `.txt`
- [ ] **Logging de sesión** — registro automático de todas las acciones con timestamp en `~/.cybertoolkit/session.log`
- [ ] **Configuración por archivo** — `.cybertoolkitrc` para personalizar timeouts, límites y preferencias
- [ ] **Empaquetado con PyInstaller** — ejecutable único sin necesidad de Python instalado

---

### ✅ v2.0 — Herramientas avanzadas de reconocimiento (OSINT / Red)

- [x] **11. `subdomain_enum.py`** — Enumerador de subdominios
Descubrimiento de subdominios mediante fuerza bruta con diccionario, resolución DNS masiva y búsqueda en Certificate Transparency Logs (crt.sh). Detección de subdomain takeover (CNAME apuntando a servicio inexistente).
**Conceptos:** DNS, wildcard, zone transfer, CT Logs, takeover.

- [x] **12. `banner_grabber.py`** — Grabber de banners de servicios
Conecta a puertos abiertos y extrae el banner de identificación del servicio (versión de SSH, FTP, SMTP, HTTP Server header). Correlaciona versiones con CVEs conocidos usando una base local.
**Conceptos:** fingerprinting, service enumeration, version disclosure.

- [x] **13. `whois_osint.py`** — OSINT sobre dominios e IPs
Consultas WHOIS, geolocalización de IPs, ASN lookup, búsqueda en Shodan, detección de tecnologías web y análisis de cabeceras HTTP de seguridad.
**Conceptos:** OSINT, reconocimiento pasivo, threat intelligence.

- [x] **14. `wifi_scanner.py`** — Escáner de redes Wi-Fi
Escaneo de redes wireless cercanas con detección de cifrado (WEP/WPA/WPA2/WPA3), intensidad de señal, canal y fabricante por OUI. Alerta sobre redes con WEP o sin cifrado.
**Conceptos:** 802.11, SSID, BSSID, cifrado wireless, rogue AP.

---

### ✅ v2.1 — Herramientas avanzadas de criptoanálisis

- [x] **15. `hash_cracker.py`** — Crackeador de hashes por diccionario y reglas
Ataque de diccionario sobre hashes MD5/SHA-1/SHA-256/bcrypt con soporte de reglas de mutación (l33tspeak, sufijos numéricos, mayúsculas). Integración con listas de RockYou y SecLists. Estimación de tiempo restante en tiempo real.
**Conceptos:** ataque de diccionario, rainbow tables, reglas de hashcat, GPU vs CPU.

- [x] **16. `jwt_analyzer.py`** — Analizador y manipulador de JSON Web Tokens
Decodificación de JWT sin verificar, detección del algoritmo (`alg: none` attack, RS256→HS256 confusion), fuerza bruta de secretos débiles, forja de tokens con clave conocida.
**Conceptos:** JWT, claims, firma digital, vulnerabilidades de implementación.

- [x] **17. `tls_auditor.py`** — Auditor completo de configuración TLS/SSL
Verifica versiones soportadas (SSLv3, TLS 1.0/1.1 deprecados), cipher suites débiles, vulnerabilidades conocidas (BEAST, POODLE, Heartbleed, DROWN, ROBOT), validez del certificado, cadena de confianza y configuración HSTS/HPKP.
**Conceptos:** TLS, cipher suites, PKI, vulnerabilidades de protocolo, perfect forward secrecy.

- [x] **18. `steganography.py`** — Esteganografía en imágenes (LSB)
Oculta y extrae mensajes en imágenes usando LSB (Least Significant Bit) steganography. Detecta imágenes con posible contenido oculto mediante análisis estadístico del LSB y comparación de histogramas.
**Conceptos:** esteganografía, LSB, análisis de imagen, covert channels.

---

### ✅ v2.2 — Análisis de tráfico y protocolos

- [x] **19. `pcap_analyzer.py`** — Analizador de capturas PCAP/PCAPNG
Parseo de archivos `.pcap` exportados de Wireshark/tcpdump. Reconstrucción de sesiones TCP, extracción de archivos transferidos por HTTP, detección de credenciales en texto plano, análisis de patrones de tráfico y generación de reporte HTML.
**Conceptos:** PCAP, stream reassembly, carving, forense de red.

- [x] **20. `arp_monitor.py`** — Detector de ARP Spoofing / Poisoning
Monitorea la tabla ARP de la red local en tiempo real. Detecta inconsistencias MAC-IP, cambios inesperados de MAC y ataques de ARP poisoning que preceden a ataques MITM. Envía alertas y registra eventos.
**Conceptos:** ARP, MITM, poisoning, man-in-the-middle, LAN security.

- [x] **21. `dns_analyzer.py`** — Analizador avanzado de DNS
Detección de DNS tunneling (exfiltración de datos por DNS), análisis de subdominios anómalos de longitud extrema, consultas a dominios DGA (Domain Generation Algorithm), detección de Fast-Flux y DNS rebinding.
**Conceptos:** DNS tunneling, DGA, fast-flux, data exfiltration, C2 communication.

---

### ✅ v3.0 — Herramientas de ciberdefensa y detección

- [x] **22. `ids_lite.py`** — Sistema de detección de intrusiones ligero
Motor de reglas tipo Snort/Suricata simplificado. Analiza tráfico en tiempo real con reglas definidas en JSON (detección de port scan, login brute force, shellcode en payload, User-Agent anómalos, tráfico C2 conocido). Genera alertas con nivel de severidad.
**Conceptos:** IDS/IPS, firmas, reglas BPF, detección de anomalías, SIEM.

- [x] **23. `honeypot.py`** — Honeypot de servicios TCP
Levanta servicios falsos en puertos comunes (22/SSH, 80/HTTP, 3306/MySQL, 21/FTP) que registran cada intento de conexión, credenciales usadas y payloads enviados. Genera logs detallados de la actividad del atacante.
**Conceptos:** honeypot, deception technology, threat intelligence, IoC collection.

- [x] **24. `log_analyzer.py`** — Analizador de logs de seguridad
Parseo de logs de Apache/Nginx (access.log). Detección de patrones: fuerza bruta, escaneos web (SQLi, XSS), errores 4xx/5xx masivos. Identifica las IPs más atacantes y correlaciona los eventos detectados.
**Conceptos:** log parsing, SIEM, threat hunting, regex, incident response.

- [x] **25. `vuln_scanner.py`** — Escáner de vulnerabilidades básico
Combina port scanning, banner grabbing y correlación con CVE para identificar servicios vulnerables. Verifica misconfigurations comunes: acceso anónimo FTP, Redis/MongoDB sin auth, directorios web expuestos, headers de seguridad faltantes.
**Conceptos:** vulnerability assessment, CVE, CVSS, misconfigurations, attack surface.

- [x] **26. `firewall_tester.py`** — Tester de reglas de firewall
Prueba la efectividad de reglas de firewall enviando paquetes de prueba con técnicas de evasión: fragmentación IP, source port spoofing (puerto 53/80), flags TCP anómalos (FIN scan, XMAS scan, NULL scan), túneles ICMP.
**Conceptos:** firewall evasion, packet crafting, TCP flags, filtrado de paquetes.

---

### ✅ v3.1 — Análisis de vulnerabilidades web

- [x] **27. `web_crawler.py`** — Crawler de aplicaciones web
Mapeo completo de una aplicación web: descubrimiento de endpoints, formularios, parámetros GET/POST, archivos JavaScript, comentarios HTML con información sensible, directorios ocultos (robots.txt, sitemap.xml, .git expuesto).
**Conceptos:** web scraping, attack surface mapping, information disclosure.

- [x] **28. `sqli_detector.py`** — Detector de inyección SQL
Pruebas automatizadas de SQL Injection en parámetros GET/POST: error-based, boolean-based blind, time-based blind. Detección de WAF. Solo para aplicaciones propias o con autorización explícita.
**Conceptos:** SQLi, prepared statements, WAF, blind injection, OWASP Top 10.

- [x] **29. `xss_scanner.py`** — Escáner de Cross-Site Scripting
Inyección de payloads XSS en parámetros de formularios y URLs. Detección de reflected XSS, stored XSS y DOM-based XSS. Análisis de Content Security Policy para evaluar la efectividad de las mitigaciones.
**Conceptos:** XSS, CSP, DOM, input sanitization, OWASP Top 10.

- [x] **30. `cors_auditor.py`** — Auditor de políticas CORS
Analiza la configuración CORS de APIs y aplicaciones web. Detecta: `Access-Control-Allow-Origin: *` con credenciales, reflection de Origin arbitrario, null origin permitido, y misconfiguraciones que permiten CSRF cross-origin.
**Conceptos:** CORS, SOP, preflight, credenciales cross-origin, API security.

---

### ✅ v3.2 — Forense digital avanzado

- [x] **31. `disk_forensics.py`** — Análisis forense de imágenes de disco
Parseo de imágenes `.dd` / `.img`: identificación de particiones, sistemas de archivos, archivos eliminados recuperables (file carving por magic bytes), timeline de actividad, búsqueda de strings y patrones en espacio no asignado.
**Conceptos:** file carving, slack space, MFT, inodes, cadena de custodia.

- [x] **32. `memory_analyzer.py`** — Análisis básico de volcados de memoria (RAM)
Extracción de strings, URLs, credenciales en claro, procesos activos, conexiones de red y artefactos de malware desde un volcado de memoria `.raw` o `.mem`. Integración con perfiles de Volatility.
**Conceptos:** memory forensics, volatility, artefactos en RAM, proceso hollowing.

- [x] **33. `timeline_builder.py`** — Constructor de línea de tiempo forense
Correlaciona eventos de múltiples fuentes (logs del sistema, timestamps de archivos, registros de red, metadatos de documentos) y construye una línea de tiempo unificada exportable a CSV/HTML para análisis de incidentes.
**Conceptos:** timeline analysis, incident response, DFIR, correlación de artefactos.

---

### 🤖 v4.0 — Inteligencia de amenazas y automatización

#### 34. `threat_intel.py` — Consultas a fuentes de Threat Intelligence
Integración con APIs públicas: VirusTotal (archivos/URLs/IPs), AbuseIPDB (reputación de IPs), AlienVault OTX (indicadores de compromiso), Shodan (dispositivos expuestos) y Have I Been Pwned (emails comprometidos). Dashboard unificado de resultados.
**Conceptos:** CTI, IoC, TTP, STIX/TAXII, threat feeds.

#### 35. `c2_detector.py` — Detector de comunicaciones C2
Análisis de tráfico de red para identificar patrones de Command & Control: beaconing periódico, comunicación cifrada con dominios DGA, tráfico HTTPS con certificados autofirmados, túneles DNS/ICMP/HTTP. Base de firmas actualizable.
**Conceptos:** C2, beaconing, lateral movement, APT, kill chain.

#### 36. `report_generator.py` — Generador de reportes de seguridad
Consolida resultados de múltiples herramientas del toolkit y genera reportes profesionales en formato PDF/HTML con gráficos, tablas de hallazgos clasificados por severidad (CVSS), recomendaciones de remediación y resumen ejecutivo.
**Conceptos:** vulnerability management, risk scoring, CVSS, pentesting report.

---

### 🌐 v4.1 — Interfaz web y colaboración

#### Web UI con Flask
Interfaz web ligera que expone las herramientas del toolkit a través de un navegador. Panel de control con resultados en tiempo real via WebSockets, historial de sesiones, gestión de proyectos y exportación de reportes desde el navegador.

#### API REST
Endpoints REST para integrar el toolkit con otras herramientas de seguridad, SIEMs o pipelines de CI/CD (security testing en despliegues automáticos).

#### Plugin para Burp Suite
Extensión para Burp Suite Community que integra el analizador de URLs, el detector de XSS/SQLi y el auditor CORS directamente en el proxy de interceptación.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Antes de abrir un Pull Request:

1. Abrí un *issue* para discutir el cambio propuesto
2. Asegurate de que la herramienta siga las convenciones del proyecto:
   - Punto de entrada `run()` sin argumentos
   - Sin `sys.exit()` dentro de las herramientas
   - Salidas a través de `utils.py` (ok, error, warn, info, result)
   - Submenú propio con opción `[0]` para volver al menú principal
   - Sección de explicación didáctica integrada
3. Incluí tests básicos ejecutables directamente con `python tools/tu_herramienta.py`

---

## 📄 Licencia

MIT License — consulta el archivo `LICENSE` para más detalles.
