"""
file_integrity.py — Herramienta 5: Monitor de integridad de archivos
Genera una baseline de hashes de una carpeta y detecta cambios en ejecuciones posteriores.

Conceptos didácticos:
  · HIDS (Host-based Intrusion Detection System)
  · Baseline de integridad: qué es y por qué importa
  · Persistencia de malware: cómo modifica archivos del sistema
  · Hashing como mecanismo de detección de cambios (no de contenido)
  · Formato JSON para almacenamiento de evidencia forense
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause, validate_dir, format_size,
)
from config import (
    INTEGRITY_DB_FILENAME,
    INTEGRITY_HASH_ALGO,
    INTEGRITY_IGNORE_EXTS,
    FILE_READ_CHUNK,
)


# ──────────────────────────────────────────────
#  Hashing de archivos
# ──────────────────────────────────────────────
def _hash_file(path: str, algo: str = INTEGRITY_HASH_ALGO) -> str | None:
    """
    Calcula el hash de un archivo en modo streaming.
    Retorna el hexdigest o None si falla.
    """
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            while chunk := f.read(FILE_READ_CHUNK):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _file_metadata(path: str) -> dict:
    """Recopila metadatos básicos de un archivo para la baseline."""
    try:
        st = os.stat(path)
        return {
            "size":     st.st_size,
            "mtime":    st.st_mtime,
            "mtime_hr": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        }
    except OSError:
        return {"size": 0, "mtime": 0.0, "mtime_hr": "unknown"}


# ──────────────────────────────────────────────
#  Construcción de la baseline
# ──────────────────────────────────────────────
def _build_baseline(
    target_dir: str,
    algo: str = INTEGRITY_HASH_ALGO,
    ignore_exts: set[str] = INTEGRITY_IGNORE_EXTS,
    recursive: bool = True,
) -> dict:
    """
    Recorre el directorio y construye un dict con hash + metadatos
    para cada archivo encontrado.

    Estructura del dict devuelto:
    {
        "ruta/relativa/archivo.txt": {
            "hash":     "abc123...",
            "algo":     "sha256",
            "size":     1024,
            "mtime":    1700000000.0,
            "mtime_hr": "2024-01-01 12:00:00",
        },
        ...
    }
    """
    baseline = {}
    skipped  = 0
    errors   = 0

    walker = Path(target_dir)
    all_files = list(walker.rglob("*") if recursive else walker.glob("*"))
    all_files = [f for f in all_files if f.is_file()]

    total = len(all_files)
    info(f"Procesando {total} archivo(s)...")
    print()

    for i, file_path in enumerate(all_files, 1):
        # Extensión ignorada
        if file_path.suffix.lower() in ignore_exts:
            skipped += 1
            continue

        rel_path = str(file_path.relative_to(target_dir))

        # Progreso
        pct     = i / total * 100
        bar_len = int(pct / 5)
        bar     = green("█" * bar_len) + dim("░" * (20 - bar_len))
        print(
            f"\r  {bar} {dim(f'{pct:5.1f}%')} {dim(f'[{i}/{total}]')} "
            f"{dim(rel_path[:40]):<42}",
            end="",
            flush=True,
        )

        digest = _hash_file(str(file_path), algo)
        if digest is None:
            errors += 1
            continue

        meta = _file_metadata(str(file_path))
        baseline[rel_path] = {
            "hash":     digest,
            "algo":     algo,
            **meta,
        }

    print()  # nueva línea tras barra
    return baseline, total, skipped, errors


# ──────────────────────────────────────────────
#  Persistencia de la baseline (JSON)
# ──────────────────────────────────────────────
def _baseline_path(target_dir: str, custom_name: str = "") -> str:
    """Devuelve la ruta completa del archivo de baseline."""
    filename = custom_name if custom_name else INTEGRITY_DB_FILENAME
    return os.path.join(target_dir, filename)


def _save_baseline(
    baseline: dict,
    target_dir: str,
    algo: str,
    out_path: str,
) -> bool:
    """Guarda la baseline en formato JSON con metadatos de cabecera."""
    payload = {
        "_meta": {
            "created_at":  datetime.now().isoformat(),
            "target_dir":  target_dir,
            "algo":        algo,
            "file_count":  len(baseline),
            "tool":        "CyberToolkit — file_integrity v1.0",
        },
        "files": baseline,
    }
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return True
    except OSError as e:
        error(f"No se pudo guardar la baseline: {e}")
        return False


def _load_baseline(db_path: str) -> tuple[dict | None, dict | None]:
    """
    Carga una baseline desde JSON.
    Devuelve (files_dict, meta_dict) o (None, None) si falla.
    """
    if not os.path.isfile(db_path):
        return None, None
    try:
        with open(db_path, encoding="utf-8") as f:
            data = json.load(f)
        meta  = data.get("_meta", {})
        files = data.get("files", {})
        return files, meta
    except (json.JSONDecodeError, OSError) as e:
        error(f"No se pudo leer la baseline '{db_path}': {e}")
        return None, None


# ──────────────────────────────────────────────
#  Comparación de baselines
# ──────────────────────────────────────────────
def _compare_baselines(
    old: dict,
    new: dict,
) -> dict:
    """
    Compara dos baselines y clasifica los cambios en:
      · added    — archivos nuevos
      · removed  — archivos eliminados
      · modified — hash diferente (contenido cambiado)
      · touched  — mismo hash pero mtime diferente (metadatos cambiados)
      · unchanged — sin cambios
    """
    old_keys = set(old.keys())
    new_keys = set(new.keys())

    added   = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    modified  = []
    touched   = []
    unchanged = []

    for key in sorted(old_keys & new_keys):
        o, n = old[key], new[key]
        if o["hash"] != n["hash"]:
            modified.append((key, o, n))
        elif o.get("mtime", 0) != n.get("mtime", 0):
            touched.append((key, o, n))
        else:
            unchanged.append(key)

    return {
        "added":     added,
        "removed":   removed,
        "modified":  modified,
        "touched":   touched,
        "unchanged": unchanged,
    }


# ──────────────────────────────────────────────
#  Reporte de diferencias
# ──────────────────────────────────────────────
def _print_diff_report(diff: dict, elapsed: float) -> None:
    """Muestra el reporte completo de cambios detectados."""
    added     = diff["added"]
    removed   = diff["removed"]
    modified  = diff["modified"]
    touched   = diff["touched"]
    unchanged = diff["unchanged"]

    total_changes = len(added) + len(removed) + len(modified)

    separator("═", 62)
    print(f"  {white('REPORTE DE INTEGRIDAD')}")
    separator("─", 62)
    print(
        f"  {green(f'{len(unchanged)} sin cambios')}  ·  "
        f"{red(f'{len(modified)} modificados')}  ·  "
        f"{yellow(f'{len(added)} nuevos')}  ·  "
        f"{magenta(f'{len(removed)} eliminados')}  ·  "
        f"{dim(f'{len(touched)} tocados')}  ·  "
        f"{dim(f'{elapsed:.2f}s')}"
    )
    separator("─", 62)

    # ── Archivos modificados (más críticos) ──
    if modified:
        print(f"\n  {red('✗ ARCHIVOS MODIFICADOS')} {dim(f'({len(modified)})')}")
        separator("─", 62)
        for path, old, new in modified:
            print(f"  {red('►')} {white(path)}")
            print(f"    {dim('Hash anterior:')} {dim(old['hash'][:48])}")
            print(f"    {dim('Hash actual:  ')} {red(new['hash'][:48])}")
            old_size = format_size(old.get("size", 0))
            new_size = format_size(new.get("size", 0))
            if old.get("size") != new.get("size"):
                print(f"    {dim('Tamaño:')} {dim(old_size)} → {yellow(new_size)}")
            print(f"    {dim('Modificado:')} {dim(new.get('mtime_hr', '?'))}")
            print()

    # ── Archivos nuevos ──
    if added:
        print(f"  {yellow('+ ARCHIVOS NUEVOS')} {dim(f'({len(added)})')}")
        separator("─", 62)
        for path in added:
            print(f"  {yellow('+')} {white(path)}")
        print()

    # ── Archivos eliminados ──
    if removed:
        print(f"  {magenta('- ARCHIVOS ELIMINADOS')} {dim(f'({len(removed)})')}")
        separator("─", 62)
        for path in removed:
            print(f"  {magenta('-')} {dim(path)}")
        print()

    # ── Archivos tocados (mtime distinto, hash igual) ──
    if touched:
        print(f"  {cyan('~ METADATOS CAMBIADOS')} {dim(f'({len(touched)})')} {dim('(mismo hash)')}")
        separator("─", 62)
        for path, old, new in touched:
            print(f"  {cyan('~')} {dim(path)}")
            print(f"    {dim('mtime anterior:')} {dim(old.get('mtime_hr','?'))}")
            print(f"    {dim('mtime actual:  ')} {cyan(new.get('mtime_hr','?'))}")
        print()

    separator("═", 62)

    # Veredicto
    if total_changes == 0 and not touched:
        print(f"\n  {green('✓ INTEGRIDAD VERIFICADA')} — Ningún archivo fue alterado.")
    elif total_changes == 0:
        print(f"\n  {cyan('~ Contenido intacto')} — Solo se detectaron cambios de metadatos.")
    else:
        print(f"\n  {red('⚠ CAMBIOS DETECTADOS')} — {total_changes} archivo(s) alterados.")
        if modified:
            warn("Archivos modificados pueden indicar: actualización de software,")
            warn("intervención humana o infección por malware.")
            info("Revisá cada archivo modificado para determinar si el cambio es esperado.")

    separator("═", 62)


# ──────────────────────────────────────────────
#  Modo 1: Crear baseline
# ──────────────────────────────────────────────
def _mode_create() -> None:
    section_title("CREAR BASELINE DE INTEGRIDAD")

    target = prompt("Directorio a monitorear")
    if not target:
        warn("No se ingresó ningún directorio.")
        return
    if not validate_dir(target):
        error(f"El directorio '{target}' no existe o no es accesible.")
        return

    target = os.path.abspath(target)

    # Opciones
    recursive = ask_yes_no("¿Incluir subdirectorios recursivamente?", default=True)

    algos = {"1": "sha256", "2": "sha512", "3": "md5"}
    print()
    info("Algoritmo de hash:")
    print(f"  {cyan('[1]')} {white('SHA-256')} {dim('— recomendado')}")
    print(f"  {cyan('[2]')} {white('SHA-512')} {dim('— más lento, más seguro')}")
    print(f"  {cyan('[3]')} {white('MD5')}     {dim('— rápido, solo integridad básica')}")
    algo_choice = prompt("Opción", default="1")
    algo = algos.get(algo_choice, "sha256")

    # Nombre del archivo de baseline
    default_db = os.path.join(target, INTEGRITY_DB_FILENAME)
    custom_out = prompt("Ruta de salida de la baseline", default=default_db)
    if not custom_out:
        custom_out = default_db

    # Construir
    print()
    separator("─", 62)
    info(f"Directorio: {white(target)}")
    info(f"Algoritmo:  {white(algo.upper())}")
    info(f"Salida:     {white(custom_out)}")
    separator("─", 62)

    if not ask_yes_no("¿Iniciar la generación de la baseline?", default=True):
        warn("Operación cancelada.")
        return

    start = time.time()
    baseline, total, skipped, errors = _build_baseline(target, algo, INTEGRITY_IGNORE_EXTS, recursive)
    elapsed = time.time() - start

    # Guardar
    if _save_baseline(baseline, target, algo, custom_out):
        print()
        separator("─", 62)
        result("Archivos procesados", str(total))
        result("Archivos en baseline", str(len(baseline)))
        result("Omitidos (ext)",      str(skipped))
        result("Errores de lectura",  str(errors) if errors else dim("ninguno"))
        result("Tiempo",             f"{elapsed:.2f}s")
        result("Baseline guardada",  white(custom_out))
        separator("─", 62)
        ok("Baseline creada exitosamente.")
        print()
        info("Guardá este archivo en un lugar seguro.")
        info("Usá 'Verificar integridad' para comparar el estado futuro contra esta baseline.")
    else:
        error("No se pudo guardar la baseline.")


# ──────────────────────────────────────────────
#  Modo 2: Verificar integridad
# ──────────────────────────────────────────────
def _mode_verify() -> None:
    section_title("VERIFICAR INTEGRIDAD")

    # Cargar baseline existente
    db_path = prompt("Ruta del archivo de baseline (.json)")
    if not db_path or not os.path.isfile(db_path):
        error("Archivo de baseline no encontrado.")
        return

    old_baseline, meta = _load_baseline(db_path)
    if old_baseline is None:
        return

    # Info de la baseline
    print()
    separator("─", 62)
    print(f"  {white('BASELINE CARGADA:')}")
    result("Creada",      meta.get("created_at", "?")[:19])
    result("Directorio",  meta.get("target_dir", "?"))
    result("Algoritmo",   meta.get("algo", "?").upper())
    result("Archivos",    str(meta.get("file_count", "?")))
    separator("─", 62)

    # Directorio actual a verificar
    target = meta.get("target_dir", "")
    override = ask_yes_no(
        f"¿Verificar el directorio original ({os.path.basename(target)})?",
        default=True
    )
    if not override:
        target = prompt("Directorio a verificar")

    if not target or not validate_dir(target):
        error("Directorio no válido.")
        return

    target = os.path.abspath(target)
    algo   = meta.get("algo", INTEGRITY_HASH_ALGO)

    print()
    info(f"Generando baseline actual de '{white(target)}'...")
    start = time.time()
    new_baseline, _, _, _ = _build_baseline(target, algo, INTEGRITY_IGNORE_EXTS, recursive=True)
    elapsed = time.time() - start

    # Comparar
    info("Comparando con la baseline guardada...")
    diff = _compare_baselines(old_baseline, new_baseline)

    _print_diff_report(diff, elapsed)

    # Ofrecer guardar reporte
    if any(diff[k] for k in ("added", "removed", "modified")):
        print()
        if ask_yes_no("¿Guardar reporte de cambios en un archivo de texto?", default=False):
            _save_text_report(diff, db_path, target, elapsed)


def _save_text_report(diff: dict, db_path: str, target: str, elapsed: float) -> None:
    """Guarda un reporte de texto plano de los cambios detectados."""
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path  = os.path.join(os.path.dirname(db_path), f"integrity_report_{ts}.txt")

    lines = [
        "=" * 62,
        "REPORTE DE INTEGRIDAD — CyberToolkit",
        "=" * 62,
        f"Fecha:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Directorio: {target}",
        f"Baseline:   {db_path}",
        f"Tiempo:     {elapsed:.2f}s",
        "",
    ]

    if diff["modified"]:
        lines += [f"ARCHIVOS MODIFICADOS ({len(diff['modified'])}):", "-" * 40]
        for path, old, new in diff["modified"]:
            lines += [
                f"  {path}",
                f"    Hash anterior: {old['hash']}",
                f"    Hash actual:   {new['hash']}",
                f"    Modificado:    {new.get('mtime_hr', '?')}",
                "",
            ]

    if diff["added"]:
        lines += [f"ARCHIVOS NUEVOS ({len(diff['added'])}):", "-" * 40]
        for path in diff["added"]:
            lines.append(f"  {path}")
        lines.append("")

    if diff["removed"]:
        lines += [f"ARCHIVOS ELIMINADOS ({len(diff['removed'])}):", "-" * 40]
        for path in diff["removed"]:
            lines.append(f"  {path}")
        lines.append("")

    lines += [
        "=" * 62,
        f"Total cambios: {len(diff['modified']) + len(diff['added']) + len(diff['removed'])}",
        "=" * 62,
    ]

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        ok(f"Reporte guardado en: {white(out_path)}")
    except OSError as e:
        error(f"No se pudo guardar el reporte: {e}")


# ──────────────────────────────────────────────
#  Modo 3: Inspeccionar baseline
# ──────────────────────────────────────────────
def _mode_inspect() -> None:
    section_title("INSPECCIONAR BASELINE")

    db_path = prompt("Ruta del archivo de baseline (.json)")
    if not db_path or not os.path.isfile(db_path):
        error("Archivo no encontrado.")
        return

    files, meta = _load_baseline(db_path)
    if files is None:
        return

    # Cabecera
    separator("─", 62)
    print(f"  {white('METADATOS DE LA BASELINE:')}")
    separator("─", 62)
    for k, v in meta.items():
        result(k, dim(str(v)))
    separator("─", 62)

    # Estadísticas
    total_size = sum(f.get("size", 0) for f in files.values())
    exts       = {}
    for path in files:
        ext = Path(path).suffix.lower() or "(sin ext)"
        exts[ext] = exts.get(ext, 0) + 1

    print()
    result("Total de archivos", str(len(files)))
    result("Tamaño total",      format_size(total_size))
    separator("─", 62)

    # Top 10 extensiones
    print(f"  {white('Top extensiones:')}")
    for ext, count in sorted(exts.items(), key=lambda x: -x[1])[:10]:
        bar = cyan("█" * min(count, 30))
        print(f"  {dim(f'{ext:<12}')} {bar} {dim(str(count))}")

    separator("─", 62)

    # Listar archivos con paginación simple
    if ask_yes_no("¿Listar todos los archivos de la baseline?", default=False):
        print()
        for i, (path, data) in enumerate(sorted(files.items()), 1):
            size = format_size(data.get("size", 0))
            print(f"  {dim(f'{i:4d}.')} {white(path):<50} {dim(size)}")
            if i % 30 == 0:
                if not ask_yes_no(f"  {dim(f'[{i}/{len(files)}]')} ¿Continuar?", default=True):
                    break


# ──────────────────────────────────────────────
#  Modo 4: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("¿QUÉ ES UN MONITOR DE INTEGRIDAD?")

    print(f"""
  {white('Concepto: HIDS (Host-based Intrusion Detection System)')}
  {dim('─' * 56)}

  Un monitor de integridad es la forma más básica de HIDS.
  La idea es simple:

    {cyan('1. BASELINE')}  — fotografía del estado conocido y seguro
    {cyan('2. MONITOREO')} — comparar el estado actual con la foto
    {cyan('3. ALERTA')}    — reportar cualquier diferencia

  Si un atacante modifica un binario del sistema, un script
  de inicio o un archivo de configuración, el hash cambia.
  El monitor lo detecta.


  {white('¿Por qué usar hashes y no solo fechas de modificación?')}
  {dim('─' * 56)}

  {red('Problema con mtime:')}
  {dim('·')} Un atacante puede restaurar el mtime original con touch(1)
  {dim('·')} Algunos malware hacen timestomping explícitamente
  {dim('·')} El mtime cambia con backups, copias, etc.

  {green('Ventaja del hash:')}
  {dim('·')} SHA-256 es determinista: mismo contenido = mismo hash siempre
  {dim('·')} Cambiar un solo bit produce un hash completamente distinto
  {dim('·')} Imposible manipular el contenido sin cambiar el hash


  {white('Casos reales de uso')}
  {dim('─' * 56)}

  {cyan('Tripwire')}     — HIDS clásico de Unix (1992), pionero del concepto
  {cyan('AIDE')}         — Advanced Intrusion Detection Environment (Linux)
  {cyan('OSSEC')}        — HIDS open-source con alertas en tiempo real
  {cyan('Wazuh')}        — OSSEC moderno con SIEM integrado
  {cyan('Windows FIM')}  — File Integrity Monitoring en Defender/Sysmon


  {white('Qué archivos monitorear en un sistema real')}
  {dim('─' * 56)}

  {red('Alta prioridad:')}
  {dim('·')} /bin, /sbin, /usr/bin — binarios del sistema
  {dim('·')} /etc — configuración del sistema (SSH, sudoers, cron)
  {dim('·')} /boot — kernel e initrd

  {yellow('Media prioridad:')}
  {dim('·')} Archivos de configuración de aplicaciones críticas
  {dim('·')} Scripts de inicio y servicios systemd
  {dim('·')} Archivos de autenticación (PAM, shadow)

  {green('Guardar la baseline en:')}
  {dim('·')} Dispositivo de solo lectura (USB, NFS montado RO)
  {dim('·')} Servidor externo con acceso de escritura bloqueado
  {dim('·')} Si está en el mismo disco, un atacante puede alterarla
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Crear baseline de integridad",         _mode_create),
    ("2", "Verificar integridad (comparar)",       _mode_verify),
    ("3", "Inspeccionar archivo de baseline",      _mode_inspect),
    ("4", "¿Qué es un monitor de integridad?",    _mode_explain),
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
        section_title("HERRAMIENTA 5 — MONITOR DE INTEGRIDAD DE ARCHIVOS")
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
