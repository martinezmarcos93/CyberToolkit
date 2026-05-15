"""
hash_cracker.py — Herramienta 15: Crackeador de Hashes
Ataque de diccionario sobre hashes MD5, SHA-1, SHA-256.
(Para fines puramente educativos).
"""

import sys
import os
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Asegura que el directorio raíz esté en el path al ejecutar directamente
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red,
    prompt, pause
)

try:
    import bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False


# Pequeño diccionario por defecto integrado si no se provee uno
_DEFAULT_DICT = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "admin", "admin123"
]

def _mutate_word(word: str) -> list[str]:
    """Aplica reglas básicas de mutación a una palabra base."""
    mutations = set([word])
    # Capitalizar
    mutations.add(word.capitalize())
    # Mayúsculas
    mutations.add(word.upper())
    # L33t básico
    l33t = word.translate(str.maketrans("aeiou", "4310u"))
    mutations.add(l33t)
    # Sufijos comunes
    mutations.add(word + "1")
    mutations.add(word + "123")
    mutations.add(word + "2023")
    mutations.add(word + "2024")
    return list(mutations)

def _crack_worker(hashes_to_crack: dict[str, str], words: list[str], hash_type: str) -> tuple[str, str] | None:
    """Worker que procesa un bloque de palabras contra un hash."""
    for word in words:
        mutated_words = _mutate_word(word)
        for mw in mutated_words:
            if hash_type == "md5":
                h = hashlib.md5(mw.encode()).hexdigest()
            elif hash_type == "sha1":
                h = hashlib.sha1(mw.encode()).hexdigest()
            elif hash_type == "sha256":
                h = hashlib.sha256(mw.encode()).hexdigest()
            elif hash_type == "bcrypt" and _HAS_BCRYPT:
                # Bcrypt es lento y cada hash en la base tiene su propia salt
                # hashes_to_crack es {hash_original: hash_original}
                # Esto es más complejo en batch, pero para 1 hash:
                for h_target in hashes_to_crack:
                    try:
                        if bcrypt.checkpw(mw.encode(), h_target.encode()):
                            return h_target, mw
                    except Exception:
                        pass
                continue
            else:
                return None
                
            if h in hashes_to_crack:
                return h, mw
    return None

def _mode_crack() -> None:
    section_title("CRACKEADOR DE HASHES (DICCIONARIO)")

    target_hash = prompt("Ingresá el hash a romper").strip().lower()
    if not target_hash:
        warn("No se ingresó ningún hash.")
        return

    # Determinar tipo por longitud
    hash_type = "unknown"
    hl = len(target_hash)
    if hl == 32: hash_type = "md5"
    elif hl == 40: hash_type = "sha1"
    elif hl == 64: hash_type = "sha256"
    elif target_hash.startswith("$2") and hl == 60: 
        hash_type = "bcrypt"
        if not _HAS_BCRYPT:
            error("Se detectó bcrypt pero no está instalado el módulo 'bcrypt' (pip install bcrypt).")
            return
            
    if hash_type == "unknown":
        warn(f"Longitud de hash {hl} desconocida o formato inválido.")
        ht = prompt("Especificá el tipo (md5/sha1/sha256/bcrypt) [md5]", default="md5").lower()
        if ht in ["md5", "sha1", "sha256", "bcrypt"]:
            hash_type = ht
        else:
            error("Tipo no soportado.")
            return

    info(f"Tipo de hash detectado/seleccionado: {cyan(hash_type.upper())}")

    dict_path = prompt("Ruta al diccionario (enter para diccionario rápido)", default="")
    
    words_list = []
    if dict_path and os.path.exists(dict_path):
        try:
            with open(dict_path, "r", encoding="utf-8", errors="ignore") as f:
                # Leer líneas ignorando espacios
                words_list = [l.strip() for l in f if l.strip()]
        except Exception as e:
            error(f"Error al leer archivo: {e}")
            return
    else:
        if dict_path:
            warn(f"No se encontró '{dict_path}'. Usando diccionario interno rápido.")
        words_list = _DEFAULT_DICT

    total_base = len(words_list)
    print()
    info(f"Cargadas {total_base} palabras base. (Con mutaciones serán aprox ~{total_base * 8} intentos).")
    
    # Dividir palabras en chunks para threads
    chunk_size = max(1, total_base // 8)
    chunks = [words_list[i:i + chunk_size] for i in range(0, len(words_list), chunk_size)]
    
    print()
    info(f"Iniciando ataque de fuerza bruta con diccionario sobre 1 hash...")
    
    start_time = time.time()
    found_pass = None
    
    hashes_dict = {target_hash: target_hash}
    
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_crack_worker, hashes_dict, chunk, hash_type): i for i, chunk in enumerate(chunks)}
        
        # Pseudo barra de progreso simple
        done = 0
        for future in as_completed(futures):
            done += 1
            print(f"\r  {dim(f'[{done}/{len(chunks)}] Progreso...')}", end="", flush=True)
            res = future.result()
            if res:
                found_pass = res[1]
                # Podríamos cancelar los otros, pero por ahora esperamos a que terminen o el script acaba
                break

    print("\r" + " " * 40 + "\r", end="")
    elapsed = time.time() - start_time
    
    separator("─", 60)
    if found_pass:
        print(f"  {green('✓ ¡HASH ROTO!')}")
        print(f"  {white('Hash:')} {dim(target_hash)}")
        print(f"  {white('Texto plano:')} {red(found_pass)}")
    else:
        warn("No se encontró la contraseña en el diccionario.")
        
    separator("─", 60)
    result("Tiempo transcurrido", f"{elapsed:.2f} segundos")
    print()


def _mode_explain() -> None:
    section_title("¿CÓMO FUNCIONA EL CRACKEO DE HASHES?")

    print(f"""
  {white('1. ¿Qué es un Hash?')}
  {dim('─' * 56)}
  Es una función matemática unidireccional (no reversible). 
  Convierte una contraseña en una cadena de caracteres fijos.
  Ejemplo MD5 de "admin": {cyan('21232f297a57a5a743894a0e4a801fc3')}

  {white('2. Ataque de Diccionario')}
  {dim('─' * 56)}
  Consiste en hashear millones de palabras comunes (diccionarios como RockYou)
  y comparar el resultado con el hash objetivo. Si coinciden, hemos 
  "roto" (cracked) el hash.

  {white('3. Rainbow Tables')}
  {dim('─' * 56)}
  Son bases de datos masivas pre-computadas que contienen el hash de 
  todas las contraseñas posibles. Hacen que el crackeo sea casi instantáneo
  a cambio de ocupar muchísimo espacio en disco (Terabytes).

  {white('4. Solución: El "Salt" y funciones lentas')}
  {dim('─' * 56)}
  Para evitar esto, se le agrega un {yellow('Salt')} (cadena aleatoria) a la 
  contraseña antes de hashearla. Así las Rainbow Tables no sirven.
  Además se usan algoritmos {yellow('lentos a propósito')} como {red('bcrypt')} o {red('Argon2')}
  para que el atacante no pueda procesar millones de hashes por segundo.
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Ejecutar Crackeador (Diccionario)",    _mode_crack),
    ("2", "¿Cómo funciona y cómo prevenirlo?",    _mode_explain),
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
        section_title("HERRAMIENTA 15 — CRACKEADOR DE HASHES")
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
            error("Opción no válida. Ingresá un número del 0 al 2.")

        pause()


if __name__ == "__main__":
    run()
