"""
file_encryptor.py — Herramienta 7: Cifrador / descifrador de archivos AES-256-GCM
Cifra y descifra archivos con AES-256 en modo GCM usando derivación de clave PBKDF2.

Conceptos didácticos:
  · AES-256: estándar de cifrado simétrico con clave de 256 bits
  · GCM (Galois/Counter Mode): modo autenticado — detecta manipulación del ciphertext
  · PBKDF2: función de derivación de clave desde contraseña (Password-Based Key Derivation)
  · Salt: valor aleatorio que evita ataques de rainbow table
  · Nonce/IV: número de uso único que hace que el mismo texto cifre distinto cada vez
  · AAD (Additional Authenticated Data): datos autenticados pero no cifrados
"""

import os
import sys
import struct
import secrets
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause, validate_file, format_size,
)
from config import (
    ENCRYPTOR_PBKDF2_ITERS,
    ENCRYPTOR_SALT_SIZE,
    ENCRYPTOR_NONCE_SIZE,
    ENCRYPTOR_KEY_SIZE,
    ENCRYPTOR_EXT,
    FILE_READ_CHUNK,
)

# ── Dependencia obligatoria ──────────────────
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ──────────────────────────────────────────────
#  Formato del archivo cifrado (.enc)
# ──────────────────────────────────────────────
#
#  ┌─────────────────────────────────────────────────────┐
#  │  MAGIC    4 bytes  b"CTKE"  (CyberToolKit Encrypted) │
#  │  VERSION  1 byte   0x01                              │
#  │  ITERS    4 bytes  uint32 big-endian (PBKDF2 rounds) │
#  │  SALT    16 bytes  aleatorio                         │
#  │  NONCE   12 bytes  aleatorio (AES-GCM IV)            │
#  │  CIPHERTEXT + TAG  (datos cifrados + 16 bytes GCM)   │
#  └─────────────────────────────────────────────────────┘
#
#  El TAG de autenticación GCM va embebido al final del ciphertext
#  (comportamiento estándar de AESGCM de la librería cryptography).

MAGIC   = b"CTKE"
VERSION = 0x01
HEADER_SIZE = 4 + 1 + 4 + ENCRYPTOR_SALT_SIZE + ENCRYPTOR_NONCE_SIZE  # = 37 bytes


# ──────────────────────────────────────────────
#  Derivación de clave desde contraseña
# ──────────────────────────────────────────────
def _derive_key(password: str, salt: bytes, iterations: int = ENCRYPTOR_PBKDF2_ITERS) -> bytes:
    """
    Deriva una clave AES-256 (32 bytes) desde una contraseña usando PBKDF2-HMAC-SHA256.

    PBKDF2 aplica la función hash N veces (iterations) para que sea
    computacionalmente costoso adivinar la contraseña por fuerza bruta.
    NIST SP 800-132 recomienda ≥ 600.000 iteraciones en 2023.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENCRYPTOR_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


# ──────────────────────────────────────────────
#  Cifrado
# ──────────────────────────────────────────────
def encrypt_file(src_path: str, dst_path: str, password: str) -> bool:
    """
    Cifra src_path → dst_path usando AES-256-GCM.
    Devuelve True si tuvo éxito, False si falló.
    """
    if not _HAS_CRYPTO:
        error("cryptography no instalado. Ejecutá: pip install cryptography")
        return False

    # Leer el archivo original
    try:
        with open(src_path, "rb") as f:
            plaintext = f.read()
    except OSError as e:
        error(f"No se pudo leer el archivo: {e}")
        return False

    # Generar salt y nonce aleatorios
    salt  = secrets.token_bytes(ENCRYPTOR_SALT_SIZE)
    nonce = secrets.token_bytes(ENCRYPTOR_NONCE_SIZE)

    # Derivar clave
    info(f"Derivando clave con PBKDF2 ({ENCRYPTOR_PBKDF2_ITERS:,} iteraciones)...")
    key = _derive_key(password, salt)

    # Cifrar con AES-256-GCM
    # El nombre del archivo original va como AAD (autenticado, no cifrado)
    aesgcm    = AESGCM(key)
    filename  = os.path.basename(src_path).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, filename)

    # Construir header
    header = (
        MAGIC
        + bytes([VERSION])
        + struct.pack(">I", ENCRYPTOR_PBKDF2_ITERS)
        + salt
        + nonce
    )

    # Escribir archivo cifrado
    try:
        with open(dst_path, "wb") as f:
            f.write(header)
            f.write(ciphertext)
    except OSError as e:
        error(f"No se pudo escribir el archivo cifrado: {e}")
        return False

    return True


# ──────────────────────────────────────────────
#  Descifrado
# ──────────────────────────────────────────────
def decrypt_file(src_path: str, dst_path: str, password: str) -> bool:
    """
    Descifra src_path → dst_path.
    Devuelve True si tuvo éxito, False si falló (contraseña incorrecta o archivo corrupto).
    """
    if not _HAS_CRYPTO:
        error("cryptography no instalado. Ejecutá: pip install cryptography")
        return False

    try:
        with open(src_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        error(f"No se pudo leer el archivo: {e}")
        return False

    # Validar tamaño mínimo
    if len(raw) < HEADER_SIZE + 16:  # header + al menos 16 bytes de TAG
        error("El archivo es demasiado pequeño o no es un archivo .enc válido.")
        return False

    # Parsear header
    magic   = raw[:4]
    version = raw[4]
    iters   = struct.unpack(">I", raw[5:9])[0]
    salt    = raw[9: 9 + ENCRYPTOR_SALT_SIZE]
    nonce   = raw[9 + ENCRYPTOR_SALT_SIZE: HEADER_SIZE]
    ciphertext = raw[HEADER_SIZE:]

    # Validar magic y versión
    if magic != MAGIC:
        error("Este archivo no es un .enc generado por CyberToolkit.")
        return False
    if version != VERSION:
        error(f"Versión de formato no soportada: {version}. Se esperaba {VERSION}.")
        return False

    # Derivar clave con las mismas iteraciones que se usaron al cifrar
    info(f"Derivando clave con PBKDF2 ({iters:,} iteraciones)...")
    key = _derive_key(password, salt, iterations=iters)

    # Descifrar con verificación del TAG de autenticidad
    aesgcm   = AESGCM(key)
    filename = os.path.basename(src_path.removesuffix(ENCRYPTOR_EXT)).encode("utf-8")

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, filename)
    except InvalidTag:
        error("Contraseña incorrecta o archivo corrompido/manipulado.")
        warn("El TAG de autenticación GCM falló — los datos no son de confianza.")
        return False
    except Exception as e:
        error(f"Error al descifrar: {e}")
        return False

    # Escribir plaintext
    try:
        with open(dst_path, "wb") as f:
            f.write(plaintext)
    except OSError as e:
        error(f"No se pudo escribir el archivo descifrado: {e}")
        return False

    return True


# ──────────────────────────────────────────────
#  Entrada de contraseña segura (con confirmación)
# ──────────────────────────────────────────────
def _ask_password_new() -> str | None:
    """Pide contraseña con doble confirmación. Devuelve None si cancela."""
    import getpass
    try:
        pw1 = getpass.getpass(f"  {cyan('❯')} Contraseña de cifrado: ")
        if not pw1:
            warn("La contraseña no puede estar vacía.")
            return None
        pw2 = getpass.getpass(f"  {cyan('❯')} Confirmá la contraseña: ")
        if pw1 != pw2:
            error("Las contraseñas no coinciden.")
            return None
        return pw1
    except (EOFError, KeyboardInterrupt):
        return None


def _ask_password_existing() -> str | None:
    """Pide contraseña para descifrar. Devuelve None si cancela."""
    import getpass
    try:
        pw = getpass.getpass(f"  {cyan('❯')} Contraseña: ")
        return pw if pw else None
    except (EOFError, KeyboardInterrupt):
        return None


# ──────────────────────────────────────────────
#  Modo 1: Cifrar un archivo
# ──────────────────────────────────────────────
def _mode_encrypt() -> None:
    section_title("CIFRAR ARCHIVO — AES-256-GCM")

    if not _HAS_CRYPTO:
        error("Dependencia faltante: pip install cryptography")
        return

    path = prompt("Ruta del archivo a cifrar")
    if not path or not validate_file(path):
        error("El archivo no existe o no es legible.")
        return

    # Rechazar cifrar un .enc (doble cifrado confuso)
    if path.endswith(ENCRYPTOR_EXT):
        warn("El archivo ya tiene extensión .enc. ¿Querés cifrarlo de nuevo?")
        if not ask_yes_no("¿Continuar igualmente?", default=False):
            return

    # Destino
    default_dst = path + ENCRYPTOR_EXT
    dst = prompt("Ruta de salida", default=default_dst)
    if not dst:
        dst = default_dst

    if os.path.exists(dst):
        warn(f"El archivo destino ya existe: '{dst}'")
        if not ask_yes_no("¿Sobrescribir?", default=False):
            return

    # Contraseña
    print()
    info("Ingresá una contraseña fuerte. No se mostrará en pantalla.")
    password = _ask_password_new()
    if not password:
        warn("Operación cancelada.")
        return

    # Validar longitud mínima
    if len(password) < 8:
        warn("La contraseña es muy corta (< 8 caracteres). Se recomienda al menos 12.")
        if not ask_yes_no("¿Continuar igualmente?", default=False):
            return

    # Cifrar
    src_size = os.path.getsize(path)
    info(f"Cifrando '{os.path.basename(path)}' ({format_size(src_size)})...")

    success = encrypt_file(path, dst, password)

    if success:
        dst_size = os.path.getsize(dst)
        print()
        separator("─", 60)
        result("Archivo original",  f"{os.path.basename(path)} ({format_size(src_size)})")
        result("Archivo cifrado",   f"{os.path.basename(dst)} ({format_size(dst_size)})")
        result("Algoritmo",         "AES-256-GCM")
        result("KDF",               f"PBKDF2-HMAC-SHA256 ({ENCRYPTOR_PBKDF2_ITERS:,} iter.)")
        result("Salt",              f"{ENCRYPTOR_SALT_SIZE} bytes aleatorios")
        result("Nonce",             f"{ENCRYPTOR_NONCE_SIZE} bytes aleatorios")
        result("TAG de autent.",    "16 bytes GCM (autenticación + integridad)")
        separator("─", 60)
        ok(f"Archivo cifrado exitosamente → {dst}")
        print()
        warn("Guardá la contraseña de forma segura. Sin ella es imposible recuperar los datos.")

        # Ofrecer borrar el original
        if ask_yes_no("¿Eliminar el archivo original?", default=False):
            try:
                os.remove(path)
                ok(f"Archivo original eliminado: '{path}'")
            except OSError as e:
                error(f"No se pudo eliminar el archivo original: {e}")
    else:
        # Limpiar archivo de salida si falló parcialmente
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except OSError:
                pass


# ──────────────────────────────────────────────
#  Modo 2: Descifrar un archivo
# ──────────────────────────────────────────────
def _mode_decrypt() -> None:
    section_title("DESCIFRAR ARCHIVO — AES-256-GCM")

    if not _HAS_CRYPTO:
        error("Dependencia faltante: pip install cryptography")
        return

    path = prompt("Ruta del archivo cifrado (.enc)")
    if not path or not validate_file(path):
        error("El archivo no existe o no es legible.")
        return

    if not path.endswith(ENCRYPTOR_EXT):
        warn(f"El archivo no tiene extensión '{ENCRYPTOR_EXT}'. Puede que no sea un archivo cifrado por CyberToolkit.")
        if not ask_yes_no("¿Intentar descifrar igualmente?", default=False):
            return

    # Destino: quitar .enc si está
    if path.endswith(ENCRYPTOR_EXT):
        default_dst = path[:-len(ENCRYPTOR_EXT)]
    else:
        default_dst = path + ".dec"

    dst = prompt("Ruta de salida", default=default_dst)
    if not dst:
        dst = default_dst

    if os.path.exists(dst):
        warn(f"El archivo destino ya existe: '{dst}'")
        if not ask_yes_no("¿Sobrescribir?", default=False):
            return

    # Contraseña
    print()
    info("Ingresá la contraseña usada al cifrar.")
    password = _ask_password_existing()
    if not password:
        warn("Operación cancelada.")
        return

    # Descifrar
    src_size = os.path.getsize(path)
    info(f"Descifrando '{os.path.basename(path)}' ({format_size(src_size)})...")

    success = decrypt_file(path, dst, password)

    if success:
        dst_size = os.path.getsize(dst)
        print()
        separator("─", 60)
        result("Archivo cifrado",     f"{os.path.basename(path)} ({format_size(src_size)})")
        result("Archivo descifrado",  f"{os.path.basename(dst)} ({format_size(dst_size)})")
        result("Autenticación GCM",   green("✓ Verificada — datos íntegros"))
        separator("─", 60)
        ok(f"Archivo descifrado exitosamente → {dst}")
    else:
        # Limpiar archivo de salida si falló
        if os.path.exists(dst):
            try:
                os.remove(dst)
            except OSError:
                pass


# ──────────────────────────────────────────────
#  Modo 3: Inspeccionar encabezado de un .enc
# ──────────────────────────────────────────────
def _mode_inspect() -> None:
    section_title("INSPECCIONAR ARCHIVO .ENC")

    path = prompt("Ruta del archivo .enc")
    if not path or not validate_file(path):
        error("El archivo no existe o no es legible.")
        return

    try:
        with open(path, "rb") as f:
            raw = f.read(HEADER_SIZE + 32)  # header + primeros bytes del ciphertext
    except OSError as e:
        error(f"No se pudo leer el archivo: {e}")
        return

    if len(raw) < HEADER_SIZE:
        error("El archivo es demasiado pequeño para ser un .enc válido.")
        return

    magic   = raw[:4]
    version = raw[4]
    iters   = struct.unpack(">I", raw[5:9])[0]
    salt    = raw[9: 9 + ENCRYPTOR_SALT_SIZE]
    nonce   = raw[9 + ENCRYPTOR_SALT_SIZE: HEADER_SIZE]
    total   = os.path.getsize(path)
    payload = total - HEADER_SIZE

    print()
    separator("─", 60)
    print(f"  {white('CABECERA DEL ARCHIVO CIFRADO')}")
    separator("─", 60)
    result("Magic bytes",       magic.decode("ascii", errors="?") + f"  {dim(magic.hex())}")
    result("Versión",           str(version))
    result("Algoritmo",         "AES-256-GCM")
    result("KDF",               f"PBKDF2-HMAC-SHA256")
    result("Iteraciones KDF",   f"{iters:,}")
    result("Salt (hex)",        salt.hex())
    result("Nonce/IV (hex)",    nonce.hex())
    result("Tamaño total",      format_size(total))
    result("Payload cifrado",   f"{format_size(payload)} (incluye 16 bytes de TAG GCM)")
    result("Overhead aprox.",   format_size(HEADER_SIZE + 16))
    separator("─", 60)

    if magic != MAGIC:
        warn("Magic bytes incorrectos — este archivo no fue generado por CyberToolkit.")
    else:
        ok("Archivo .enc válido. Formato reconocido correctamente.")

    print()
    info("Nota: el contenido cifrado es completamente opaco sin la contraseña correcta.")


# ──────────────────────────────────────────────
#  Modo 4: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("CRIPTOGRAFÍA SIMÉTRICA — AES-256-GCM + PBKDF2")

    print(f"""
  {white('¿Qué es AES?')}
  {dim('─' * 56)}

  AES (Advanced Encryption Standard) es el estándar de cifrado
  simétrico adoptado por el NIST en 2001 tras un concurso público.
  "Simétrico" significa que la misma clave cifra y descifra.

  {cyan('Tamaños de clave:')}
  {dim('·')} AES-128 → clave de 128 bits → {green('seguro')}
  {dim('·')} AES-192 → clave de 192 bits → {green('muy seguro')}
  {dim('·')} AES-256 → clave de 256 bits → {green('máxima seguridad')}  ← usamos este

  Para AES-256, la fuerza bruta requiere explorar 2²⁵⁶ claves.
  Con toda la energía del planeta, sería imposible en el universo.


  {white('¿Qué es GCM (Galois/Counter Mode)?')}
  {dim('─' * 56)}

  GCM convierte AES en un cifrado {white('autenticado')} (AEAD):
  no solo cifra — también garantiza que nadie modificó el ciphertext.

  {cyan('Cómo funciona:')}

  ┌──────────┐   AES-CTR   ┌──────────────┐
  │ Plaintext│ ──────────► │  Ciphertext  │
  └──────────┘             └──────────────┘
       │                          │
       │         GHASH            ▼
       └──────────────────► {red('TAG (16 bytes)')}
                            (Authentication Tag)

  {dim('·')} Si el ciphertext se modifica, el TAG falla → {red('error')}
  {dim('·')} Detecta: corrupción accidental Y manipulación deliberada
  {dim('·')} Requiere un {white('Nonce (IV)')} único por cada cifrado
  {dim('·')} {red('Reutilizar el mismo nonce rompe la seguridad de GCM')}


  {white('¿Qué es PBKDF2?')}
  {dim('─' * 56)}

  Password-Based Key Derivation Function 2.
  Convierte una contraseña (débil) en una clave criptográfica (fuerte).

  {cyan('El problema:')}
  No podemos usar la contraseña directamente como clave AES
  porque las contraseñas tienen poca entropía.

  {cyan('La solución PBKDF2:')}
  clave = SHA256(SHA256(SHA256(... password + salt ...)))
                 ← N iteraciones →

  {dim('·')} {white('Salt')}: valor aleatorio que evita rainbow tables
  {dim('·')} {white('Iteraciones')}: hace que cada intento tarde ~1 segundo
  {dim('·')} Con {ENCRYPTOR_PBKDF2_ITERS:,} iteraciones (NIST 2023):
    - CPU moderna: puede probar ~{1_000_000_000 // ENCRYPTOR_PBKDF2_ITERS:,} contraseñas/segundo
    - vs. MD5 sin PBKDF2: ~1.000.000.000 contraseñas/segundo


  {white('Diagrama del proceso completo de cifrado:')}
  {dim('─' * 56)}

  Contraseña + Salt ──► {cyan('PBKDF2')} ──► Clave AES-256 (32 bytes)
                                               │
  Plaintext ──────────────────────────────────►│
                                        {cyan('AES-256-GCM')}
  Nonce (12 bytes aleatorio) ─────────────────►│
                                               │
                              ┌────────────────┘
                              ▼
                    Ciphertext + TAG GCM
                              │
                    ┌─────────┘
                    ▼
  ┌───────────────────────────────────────────────┐
  │ CTKE │ v │ iters │  salt  │ nonce │ ciphertext│
  └───────────────────────────────────────────────┘
    4B    1B   4B      16B      12B     variable


  {white('Formato del archivo .enc en este toolkit:')}
  {dim('─' * 56)}

  {"Campo":<16} {"Tamaño":<10} {"Descripción"}
  {dim("─" * 50)}
  {"MAGIC":<16} {"4 bytes":<10} {dim("b'CTKE' — identificador del formato")}
  {"VERSION":<16} {"1 byte":<10} {dim("versión del formato (actualmente 0x01)")}
  {"ITERS":<16} {"4 bytes":<10} {dim("iteraciones PBKDF2 usadas")}
  {"SALT":<16} {"16 bytes":<10} {dim("salt aleatorio para PBKDF2")}
  {"NONCE":<16} {"12 bytes":<10} {dim("nonce aleatorio para AES-GCM")}
  {"CIPHERTEXT":<16} {"variable":<10} {dim("datos cifrados + 16 bytes TAG GCM")}
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Cifrar un archivo",                              _mode_encrypt),
    ("2", "Descifrar un archivo",                           _mode_decrypt),
    ("3", "Inspeccionar cabecera de archivo .enc",          _mode_inspect),
    ("4", "Explicación: AES-256-GCM y PBKDF2",             _mode_explain),
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
        section_title("HERRAMIENTA 7 — CIFRADOR / DESCIFRADOR AES-256-GCM")
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
