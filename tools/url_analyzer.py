"""
url_analyzer.py — Herramienta 4: Analizador de URLs sospechosas
Analiza una URL en busca de indicadores de phishing, malware y OSINT básico.

Conceptos didácticos:
  · Anatomía de una URL (esquema, host, path, query, fragmento)
  · Indicadores de phishing: TLDs sospechosos, homógrafos, subdominios excesivos
  · Cabeceras HTTP relevantes para seguridad (HSTS, CSP, X-Frame-Options...)
  · Cadenas de redirección y cómo los atacantes las usan para evasión
  · Análisis de certificados TLS básico
"""

import ipaddress
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause,
)
from config import (
    URL_MAX_LENGTH, URL_SUSPICIOUS_TLDS, URL_REQUEST_TIMEOUT,
    URL_MAX_REDIRECTS, HOMOGRAPH_CHARS,
)

# requests es opcional — si no está, el análisis HTTP se desactiva
try:
    import requests
    from requests.exceptions import (
        RequestException, SSLError, ConnectionError as ReqConnError,
        Timeout, TooManyRedirects,
    )
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ──────────────────────────────────────────────
#  Puntuación de riesgo
# ──────────────────────────────────────────────
class RiskScore:
    """
    Acumula indicadores de riesgo con su peso.
    Nivel final: LOW / MEDIUM / HIGH / CRITICAL
    """
    def __init__(self):
        self._score   = 0
        self._flags   = []   # lista de (peso, descripción)

    def add(self, weight: int, description: str) -> None:
        self._score += weight
        self._flags.append((weight, description))

    @property
    def score(self) -> int:
        return self._score

    @property
    def flags(self) -> list[tuple[int, str]]:
        return self._flags

    @property
    def level(self) -> str:
        if self._score >= 70:
            return "CRITICAL"
        elif self._score >= 40:
            return "HIGH"
        elif self._score >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    def level_colored(self) -> str:
        lvl = self.level
        if lvl == "CRITICAL": return red("CRITICAL ⚠")
        if lvl == "HIGH":     return red("HIGH")
        if lvl == "MEDIUM":   return yellow("MEDIUM")
        return green("LOW")


# ──────────────────────────────────────────────
#  Normalización y parseo de URL
# ──────────────────────────────────────────────
def _normalize_url(raw: str) -> str:
    """Agrega esquema http:// si falta."""
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "http://" + raw
    return raw


def _parse_url(url: str) -> dict | None:
    """
    Parsea una URL y devuelve un dict con sus componentes.
    Retorna None si la URL no es válida.
    """
    try:
        p = urlparse(url)
        if not p.netloc:
            return None

        host     = p.hostname or ""
        port     = p.port
        tld      = "." + host.split(".")[-1] if "." in host else ""
        subdoms  = host.split(".")[:-2] if host.count(".") >= 2 else []

        return {
            "scheme":      p.scheme.lower(),
            "host":        host,
            "port":        port,
            "path":        p.path,
            "query":       p.query,
            "fragment":    p.fragment,
            "tld":         tld,
            "subdomains":  subdoms,
            "full":        url,
            "params":      parse_qs(p.query),
        }
    except Exception:
        return None


# ──────────────────────────────────────────────
#  Análisis estático de la URL (sin red)
# ──────────────────────────────────────────────
def _analyze_static(url: str, parsed: dict, risk: RiskScore) -> list[str]:
    """
    Analiza la URL sin hacer peticiones HTTP.
    Devuelve lista de observaciones.
    """
    notes = []

    # 1. Esquema HTTP vs HTTPS
    if parsed["scheme"] == "http":
        risk.add(15, "Sin cifrado TLS (HTTP)")
        notes.append(f"{yellow('⚠')} Conexión sin cifrado — contraseñas y datos viajan en claro")
    else:
        notes.append(f"{green('✓')} HTTPS — conexión cifrada")

    # 2. Longitud total de la URL
    if len(url) > URL_MAX_LENGTH:
        risk.add(10, f"URL muy larga ({len(url)} chars > {URL_MAX_LENGTH})")
        notes.append(f"{yellow('⚠')} URL inusualmente larga: {len(url)} caracteres (umbral: {URL_MAX_LENGTH})")
    else:
        notes.append(f"{green('✓')} Longitud de URL normal: {len(url)} caracteres")

    # 3. TLD sospechoso
    if parsed["tld"].lower() in URL_SUSPICIOUS_TLDS:
        risk.add(20, f"TLD sospechoso: {parsed['tld']}")
        notes.append(f"{red('✗')} TLD de alto riesgo: {white(parsed['tld'])} — frecuente en phishing/spam")
    else:
        notes.append(f"{green('✓')} TLD sin alertas especiales: {parsed['tld']}")

    # 4. IP en lugar de dominio
    host = parsed["host"]
    try:
        ipaddress.ip_address(host)
        risk.add(25, "IP directa en lugar de dominio")
        notes.append(f"{red('✗')} Host es una IP directa: {white(host)} — inusual para sitios legítimos")
    except ValueError:
        notes.append(f"{green('✓')} Host es un dominio: {white(host)}")

    # 5. Caracteres homógrafos (ataque Unicode)
    suspicious_chars = [c for c in host if c in HOMOGRAPH_CHARS]
    if suspicious_chars:
        risk.add(35, f"Caracteres homógrafos en el dominio: {suspicious_chars}")
        notes.append(f"{red('✗')} Ataque homógrafo detectado: caracteres Unicode que imitan letras latinas")
        notes.append(f"    {dim('Chars sospechosos:')} {red(str(suspicious_chars))}")
    else:
        notes.append(f"{green('✓')} Sin caracteres Unicode sospechosos en el dominio")

    # 6. Cantidad de subdominios
    subdom_count = len(parsed["subdomains"])
    if subdom_count >= 4:
        risk.add(20, f"Exceso de subdominios: {subdom_count}")
        notes.append(f"{red('✗')} Demasiados subdominios ({subdom_count}): técnica para ocultar el dominio real")
    elif subdom_count >= 2:
        risk.add(5, f"Múltiples subdominios: {subdom_count}")
        notes.append(f"{yellow('⚠')} Subdominios múltiples ({subdom_count}): puede ser legítimo, revisá el dominio base")
    else:
        notes.append(f"{green('✓')} Estructura de subdominios normal")

    # 7. Palabras clave de phishing en la URL
    PHISHING_KEYWORDS = [
        "login", "signin", "account", "secure", "update", "verify",
        "confirm", "banking", "paypal", "apple", "google", "microsoft",
        "amazon", "netflix", "password", "credential", "wallet", "crypto",
    ]
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in url.lower()]
    if found_kw:
        risk.add(15 * min(len(found_kw), 3), f"Keywords de phishing: {found_kw}")
        notes.append(f"{yellow('⚠')} Palabras clave de phishing detectadas: {white(', '.join(found_kw))}")
    else:
        notes.append(f"{green('✓')} Sin palabras clave de phishing conocidas")

    # 8. Puerto no estándar
    port = parsed["port"]
    STANDARD_PORTS = {80, 443, None}
    if port and port not in STANDARD_PORTS:
        risk.add(10, f"Puerto no estándar: {port}")
        notes.append(f"{yellow('⚠')} Puerto inusual: {white(str(port))} — puede indicar servidor alternativo o C2")
    else:
        notes.append(f"{green('✓')} Puerto estándar")

    # 9. Parámetros con datos codificados (posible evasión)
    query = parsed["query"]
    if query:
        encoded = re.findall(r"%[0-9a-fA-F]{2}", query)
        if len(encoded) > 10:
            risk.add(10, "Query con muchos caracteres codificados")
            notes.append(f"{yellow('⚠')} Query string con {len(encoded)} chars codificados — posible evasión de filtros")

    # 10. @ en la URL (truco clásico)
    if "@" in url:
        risk.add(30, "Símbolo @ en la URL")
        notes.append(f"{red('✗')} Símbolo @ detectado — puede camuflar el dominio real: user@dominio-falso.com/...")

    # 11. Guiones excesivos en el dominio
    dash_count = host.count("-")
    if dash_count >= 4:
        risk.add(10, f"Muchos guiones en el dominio: {dash_count}")
        notes.append(f"{yellow('⚠')} Dominio con {dash_count} guiones — patrón común en sitios de phishing")

    # 12. Dominio muy largo
    if len(host) > 40:
        risk.add(10, f"Dominio muy largo: {len(host)} chars")
        notes.append(f"{yellow('⚠')} Dominio inusualmente largo ({len(host)} chars)")

    return notes


# ──────────────────────────────────────────────
#  Resolución DNS
# ──────────────────────────────────────────────
def _analyze_dns(host: str, risk: RiskScore) -> list[str]:
    """Resuelve el dominio y analiza la IP resultante."""
    notes = []

    try:
        ip = socket.gethostbyname(host)
        notes.append(f"{green('✓')} Resuelve a: {white(ip)}")

        # Detectar si resuelve a IP privada (posible SSRF o redirección interna)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                risk.add(20, f"Resuelve a IP privada: {ip}")
                notes.append(f"{red('✗')} IP privada detectada: {white(ip)} — posible SSRF o red interna")
            elif addr.is_loopback:
                risk.add(30, "Resuelve a loopback")
                notes.append(f"{red('✗')} Resuelve a loopback ({ip}) — posible SSRF")
        except ValueError:
            pass

    except socket.gaierror:
        risk.add(15, "Dominio no resuelve")
        notes.append(f"{red('✗')} No se pudo resolver el dominio — puede no existir o estar bloqueado")

    return notes


# ──────────────────────────────────────────────
#  Análisis TLS / certificado
# ──────────────────────────────────────────────
def _analyze_tls(host: str, port: int = 443, risk: RiskScore = None) -> list[str]:
    """Verifica el certificado TLS del servidor."""
    notes = []

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((host, port), timeout=URL_REQUEST_TIMEOUT),
            server_hostname=host,
        )
        cert = conn.getpeercert()
        conn.close()

        # Fecha de expiración
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left  = (expire_dt - datetime.utcnow()).days
            if days_left < 0:
                risk.add(40, "Certificado TLS expirado")
                notes.append(f"{red('✗')} Certificado TLS {red('EXPIRADO')} hace {abs(days_left)} días")
            elif days_left < 15:
                risk.add(10, f"Certificado expira en {days_left} días")
                notes.append(f"{yellow('⚠')} Certificado expira en {yellow(str(days_left))} días")
            else:
                notes.append(f"{green('✓')} Certificado válido — expira en {days_left} días ({expire_dt.strftime('%Y-%m-%d')})")

        # Emisor
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org    = issuer.get("organizationName", "desconocido")
        notes.append(f"{green('✓')} Emisor del certificado: {dim(org)}")

        # SAN (Subject Alternative Names)
        san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if san_list:
            notes.append(f"{dim('  SANs:')} {dim(', '.join(san_list[:5]))}")

    except ssl.SSLCertVerificationError as e:
        risk.add(40, "Certificado TLS inválido")
        notes.append(f"{red('✗')} Certificado TLS inválido: {dim(str(e)[:60])}")
    except ssl.SSLError as e:
        risk.add(20, "Error TLS")
        notes.append(f"{yellow('⚠')} Error TLS: {dim(str(e)[:60])}")
    except (socket.timeout, OSError):
        notes.append(f"{dim('·')} No se pudo conectar al puerto 443 para verificar TLS")

    return notes


# ──────────────────────────────────────────────
#  Análisis HTTP (cabeceras, redirecciones)
# ──────────────────────────────────────────────
def _analyze_http(url: str, risk: RiskScore) -> list[str]:
    """
    Hace una petición HEAD/GET y analiza las cabeceras HTTP de seguridad
    y la cadena de redirecciones.
    """
    if not _HAS_REQUESTS:
        return [f"{dim('·')} Análisis HTTP omitido (requests no instalado)"]

    notes = []

    try:
        session = requests.Session()
        session.max_redirects = URL_MAX_REDIRECTS
        session.headers.update({"User-Agent": "Mozilla/5.0 (CyberToolkit/1.0 educational)"})

        resp = session.get(
            url,
            timeout=URL_REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=True,
            stream=True,   # no descargar el body completo
        )
        resp.close()

        # Cadena de redirecciones
        redirect_chain = [r.url for r in resp.history]
        if redirect_chain:
            notes.append(f"{yellow('⚠')} Cadena de {len(redirect_chain)} redirección(es):")
            for i, rurl in enumerate(redirect_chain, 1):
                notes.append(f"    {dim(f'{i}.')} {dim(rurl[:70])}")
            notes.append(f"    {dim('→ Final:')} {white(resp.url[:70])}")

            # Redirección a dominio diferente
            from urllib.parse import urlparse as up
            orig_host  = up(url).hostname or ""
            final_host = up(resp.url).hostname or ""
            if orig_host and final_host and orig_host != final_host:
                risk.add(15, f"Redirección a dominio diferente: {final_host}")
                notes.append(f"{yellow('⚠')} Redirección a dominio distinto: {white(final_host)}")
        else:
            notes.append(f"{green('✓')} Sin redirecciones")

        # Código de estado
        sc = resp.status_code
        if sc == 200:
            notes.append(f"{green('✓')} Código HTTP: {sc} OK")
        elif sc in (301, 302, 307, 308):
            notes.append(f"{yellow('⚠')} Código HTTP: {sc} (redirección)")
        elif sc == 403:
            notes.append(f"{dim('·')} Código HTTP: {sc} Forbidden")
        elif sc == 404:
            notes.append(f"{dim('·')} Código HTTP: {sc} Not Found")
        elif sc >= 500:
            notes.append(f"{yellow('⚠')} Código HTTP: {sc} (error de servidor)")
        else:
            notes.append(f"{dim('·')} Código HTTP: {sc}")

        # Cabeceras de seguridad
        headers = {k.lower(): v for k, v in resp.headers.items()}
        notes.append("")
        notes.append(f"  {white('Cabeceras de seguridad HTTP:')}")

        SECURITY_HEADERS = {
            "strict-transport-security": (
                "HSTS",
                "Fuerza HTTPS en futuras visitas",
                True,
            ),
            "content-security-policy": (
                "CSP",
                "Restringe recursos cargables (previene XSS)",
                True,
            ),
            "x-frame-options": (
                "X-Frame-Options",
                "Previene clickjacking",
                True,
            ),
            "x-content-type-options": (
                "X-Content-Type-Options",
                "Previene MIME sniffing",
                True,
            ),
            "referrer-policy": (
                "Referrer-Policy",
                "Controla info de referrer filtrada",
                True,
            ),
            "permissions-policy": (
                "Permissions-Policy",
                "Restringe APIs del navegador",
                False,   # menos crítica
            ),
            "server": (
                "Server",
                "Revela versión del servidor (info leak)",
                False,
            ),
            "x-powered-by": (
                "X-Powered-By",
                "Revela tecnología del servidor (info leak)",
                False,
            ),
        }

        missing_critical = 0
        for header_key, (label, desc, critical) in SECURITY_HEADERS.items():
            if header_key in headers:
                val = headers[header_key][:60]
                if header_key in ("server", "x-powered-by"):
                    # Estas cabeceras siendo presentes es malo (info leak)
                    risk.add(5, f"Info leak en cabecera {label}: {val}")
                    notes.append(f"  {yellow('⚠')} {white(label):<24} {dim(val)} — {dim('info leak')}")
                else:
                    notes.append(f"  {green('✓')} {white(label):<24} {dim(val[:50])}")
            else:
                if critical:
                    missing_critical += 1
                    risk.add(5, f"Cabecera de seguridad ausente: {label}")
                    notes.append(f"  {red('✗')} {white(label):<24} {dim('ausente')} — {dim(desc)}")
                else:
                    notes.append(f"  {dim('·')} {white(label):<24} {dim('no presente')}")

        if missing_critical == 0:
            notes.append(f"\n  {green('✓')} Todas las cabeceras críticas de seguridad presentes")
        else:
            notes.append(f"\n  {yellow('⚠')} Faltan {missing_critical} cabecera(s) de seguridad críticas")

    except TooManyRedirects:
        risk.add(20, "Demasiadas redirecciones")
        notes.append(f"{red('✗')} Demasiadas redirecciones (>{URL_MAX_REDIRECTS}) — posible loop o evasión")
    except SSLError as e:
        risk.add(30, "Error SSL en la petición")
        notes.append(f"{red('✗')} Error SSL: {dim(str(e)[:70])}")
    except Timeout:
        notes.append(f"{yellow('⚠')} Timeout al conectar ({URL_REQUEST_TIMEOUT}s)")
    except ReqConnError:
        notes.append(f"{yellow('⚠')} No se pudo conectar al servidor")
    except RequestException as e:
        notes.append(f"{yellow('⚠')} Error HTTP: {dim(str(e)[:70])}")

    return notes


# ──────────────────────────────────────────────
#  Resumen visual de riesgo
# ──────────────────────────────────────────────
def _print_risk_summary(risk: RiskScore, url: str) -> None:
    """Muestra el resumen final con barra de riesgo y flags."""
    score = min(risk.score, 100)
    level = risk.level
    bar_w = 40
    fill  = int(score / 100 * bar_w)

    # Color de la barra según nivel
    if level == "CRITICAL":
        bar_color = red
    elif level == "HIGH":
        bar_color = red
    elif level == "MEDIUM":
        bar_color = yellow
    else:
        bar_color = green

    bar = bar_color("█" * fill) + dim("░" * (bar_w - fill))

    print()
    separator("═", 60)
    print(f"  {white('RESUMEN DE RIESGO')}")
    separator("─", 60)
    result("URL analizada",  dim(url[:65]))
    result("Puntuación",     f"{score}/100")
    result("Nivel de riesgo", risk.level_colored())
    print(f"\n  Riesgo: {bar} {score}%\n")
    separator("─", 60)

    if risk.flags:
        print(f"  {white('Indicadores detectados:')}")
        for weight, desc in sorted(risk.flags, key=lambda x: -x[0]):
            icon = red("✗") if weight >= 20 else yellow("⚠") if weight >= 10 else dim("·")
            print(f"  {icon} {dim(f'+{weight:2d}pt')}  {white(desc)}")
        separator("─", 60)

    # Recomendación final
    if level == "CRITICAL":
        print(f"\n  {red('⛔ URL de ALTO RIESGO. Evitá acceder a este sitio.')}")
        print(f"  {dim('   Probabilidad alta de phishing, malware o sitio fraudulento.')}")
    elif level == "HIGH":
        print(f"\n  {red('⚠  Riesgo ALTO. Procedé con extrema precaución.')}")
        print(f"  {dim('   Verificá el dominio real antes de ingresar datos.')}")
    elif level == "MEDIUM":
        print(f"\n  {yellow('⚠  Riesgo MEDIO. Revisá los indicadores antes de continuar.')}")
    else:
        print(f"\n  {green('✓  Riesgo BAJO. Sin indicadores críticos detectados.')}")
        print(f"  {dim('   Esto no garantiza que el sitio sea seguro — usá el criterio propio.')}")

    separator("═", 60)


# ──────────────────────────────────────────────
#  Modo 1: Análisis completo de URL
# ──────────────────────────────────────────────
def _mode_analyze() -> None:
    section_title("ANÁLISIS COMPLETO DE URL")

    raw = prompt("URL a analizar")
    if not raw:
        warn("No se ingresó ninguna URL.")
        return

    url    = _normalize_url(raw)
    parsed = _parse_url(url)
    if not parsed:
        error("URL inválida o no se pudo parsear.")
        return

    risk = RiskScore()

    # — Anatomía de la URL —
    print()
    separator("─", 60)
    print(f"  {white('ANATOMÍA DE LA URL')}")
    separator("─", 60)
    result("URL normalizada", dim(url))
    result("Esquema",         cyan(parsed["scheme"]))
    result("Host",            white(parsed["host"]))
    if parsed["port"]:
        result("Puerto",      yellow(str(parsed["port"])))
    if parsed["path"] and parsed["path"] != "/":
        result("Path",        dim(parsed["path"][:60]))
    if parsed["query"]:
        result("Query",       dim(parsed["query"][:60]))
    if parsed["subdomains"]:
        result("Subdominios", dim(", ".join(parsed["subdomains"])))
    result("TLD",             dim(parsed["tld"]))
    separator("─", 60)

    # — Análisis estático —
    print()
    print(f"  {white('ANÁLISIS ESTÁTICO (sin conexión):')}")
    separator("─", 60)
    static_notes = _analyze_static(url, parsed, risk)
    for note in static_notes:
        print(f"  {note}")

    # — DNS —
    print()
    print(f"  {white('RESOLUCIÓN DNS:')}")
    separator("─", 60)
    dns_notes = _analyze_dns(parsed["host"], risk)
    for note in dns_notes:
        print(f"  {note}")

    # — TLS —
    if parsed["scheme"] == "https":
        print()
        print(f"  {white('CERTIFICADO TLS:')}")
        separator("─", 60)
        tls_notes = _analyze_tls(parsed["host"], parsed["port"] or 443, risk)
        for note in tls_notes:
            print(f"  {note}")

    # — HTTP (opcional) —
    print()
    do_http = ask_yes_no("¿Hacer petición HTTP para analizar cabeceras?", default=True)
    if do_http:
        print()
        print(f"  {white('ANÁLISIS HTTP:')}")
        separator("─", 60)
        info("Conectando al servidor...")
        http_notes = _analyze_http(url, risk)
        for note in http_notes:
            print(f"  {note}")

    # — Resumen —
    _print_risk_summary(risk, url)


# ──────────────────────────────────────────────
#  Modo 2: Análisis rápido (solo estático + DNS)
# ──────────────────────────────────────────────
def _mode_quick() -> None:
    section_title("ANÁLISIS RÁPIDO DE URL")

    raw = prompt("URL a analizar")
    if not raw:
        warn("No se ingresó ninguna URL.")
        return

    url    = _normalize_url(raw)
    parsed = _parse_url(url)
    if not parsed:
        error("URL inválida.")
        return

    risk  = RiskScore()
    notes = _analyze_static(url, parsed, risk)
    dns   = _analyze_dns(parsed["host"], risk)

    print()
    separator("─", 60)
    for n in notes + dns:
        print(f"  {n}")

    _print_risk_summary(risk, url)


# ──────────────────────────────────────────────
#  Modo 3: Comparar dos URLs
# ──────────────────────────────────────────────
def _mode_compare() -> None:
    section_title("COMPARAR DOS URLs")

    raw_a = prompt("Primera URL")
    raw_b = prompt("Segunda URL")

    if not raw_a or not raw_b:
        warn("Se necesitan dos URLs.")
        return

    url_a, url_b = _normalize_url(raw_a), _normalize_url(raw_b)
    pa,    pb    = _parse_url(url_a), _parse_url(url_b)

    if not pa or not pb:
        error("Una o ambas URLs son inválidas.")
        return

    risk_a, risk_b = RiskScore(), RiskScore()
    _analyze_static(url_a, pa, risk_a)
    _analyze_dns(pa["host"], risk_a)
    _analyze_static(url_b, pb, risk_b)
    _analyze_dns(pb["host"], risk_b)

    print()
    separator("═", 60)
    print(f"  {white('COMPARACIÓN')}")
    separator("─", 60)
    print(f"  {'Campo':<20} {'URL A':<20} {'URL B'}")
    separator("─", 60)

    def _cmp(label, val_a, val_b):
        print(f"  {dim(label):<20} {white(str(val_a)):<20} {white(str(val_b))}")

    _cmp("Esquema",      pa["scheme"],    pb["scheme"])
    _cmp("Host",         pa["host"],      pb["host"])
    _cmp("TLD",          pa["tld"],       pb["tld"])
    _cmp("Subdominios",  len(pa["subdomains"]), len(pb["subdomains"]))
    _cmp("Longitud URL", len(url_a),      len(url_b))
    _cmp("Puntuación",   risk_a.score,    risk_b.score)
    _cmp("Nivel riesgo", risk_a.level,    risk_b.level)

    separator("─", 60)
    if risk_a.score < risk_b.score:
        ok(f"URL A tiene menor riesgo ({risk_a.score} vs {risk_b.score} pts)")
    elif risk_b.score < risk_a.score:
        ok(f"URL B tiene menor riesgo ({risk_b.score} vs {risk_a.score} pts)")
    else:
        info("Ambas URLs tienen el mismo nivel de riesgo.")


# ──────────────────────────────────────────────
#  Modo 4: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("ANATOMÍA DE UNA URL Y TÉCNICAS DE PHISHING")

    print(f"""
  {white('Anatomía de una URL')}
  {dim('─' * 56)}

  {cyan('https://usuario:pass@sub.dominio.com:8080/ruta?q=valor#frag')}
  {dim(' └──────┘ └──────────┘ └──┘ └────────┘ └──┘ └───┘ └─────┘ └───┘')}
  {dim(' esquema  credenciales sub   dominio   tld  port  path  query frag')}


  {white('Técnicas de phishing más comunes en URLs')}
  {dim('─' * 56)}

  {red('1. Dominios similares (typosquatting)')}
     {dim('·')} paypa{red('I')}.com  (i mayúscula en lugar de L)
     {dim('·')} {red('rn')}icrosoft.com  (rn parece m)
     {dim('·')} go{red('0')}gle.com  (cero en lugar de o)

  {red('2. Ataque homógrafo (Unicode)')}
     {dim('·')} pаypal.com  (la «а» es cirílica, no latina)
     {dim('·')} visualmente idéntico, dominio totalmente distinto

  {red('3. Subdominios falsos')}
     {dim('·')} paypal.com.{red('dominio-atacante.com')}
     {dim('·')} El dominio REAL es lo que está antes del TLD

  {red('4. Truco del arroba (@)')}
     {dim('·')} http://paypal.com@{red('dominio-malo.com')}/login
     {dim('·')} El navegador ignora todo antes del @

  {red('5. TLDs gratuitos y de abuso')}
     {dim('·')} .tk .ml .ga .cf .gq — registrables gratis, muy usados en spam

  {red('6. URLs largas y ofuscadas')}
     {dim('·')} Muchos parámetros codificados para confundir al usuario
     {dim('·')} Redirecciones en cadena para evadir filtros

  {white('Cabeceras HTTP de seguridad importantes')}
  {dim('─' * 56)}

  {cyan('HSTS')}            Fuerza HTTPS en el navegador por N segundos
  {cyan('CSP')}             Whitelist de orígenes de scripts/estilos (anti-XSS)
  {cyan('X-Frame-Options')} Evita que otro sitio cargue el tuyo en un iframe
  {cyan('X-Content-Type')}  Evita que el navegador reinterprete el MIME type
  {cyan('Referrer-Policy')} Controla qué URL se envía como referrer
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Análisis completo de URL",                _mode_analyze),
    ("2", "Análisis rápido (estático + DNS)",         _mode_quick),
    ("3", "Comparar dos URLs",                        _mode_compare),
    ("4", "Técnicas de phishing y anatomía de URLs",  _mode_explain),
]

def _print_submenu() -> None:
    print()
    info("¿Qué querés hacer?")
    separator("─", 58)
    for key, label, _ in _SUBMENU:
        print(f"  {cyan(f'[{key}]')} {white(label)}")
    print(f"  {red('[0]')} {dim('Volver al menú principal')}")
    separator("─", 58)


# ──────────────────────────────────────────────
#  Punto de entrada
# ──────────────────────────────────────────────
def run() -> None:
    """Punto de entrada llamado desde main.py."""
    while True:
        section_title("HERRAMIENTA 4 — ANALIZADOR DE URLs SOSPECHOSAS")
        _print_submenu()

        choice = prompt("Opción", default="0")

        if choice == "0":
            break

        matched = False
        for key, _, func in _SUBMENU:
            if choice == key:
                matched = True
                try:
                    func()
                except KeyboardInterrupt:
                    print()
                    warn("Operación cancelada.")
                break

        if not matched:
            error("Opción no válida. Ingresá un número del 0 al 4.")

        pause()


if __name__ == "__main__":
    run()
