"""
metadata_extractor.py — Herramienta 8: Extractor de metadatos
Extrae metadatos ocultos de imágenes (EXIF/GPS), PDFs y documentos Word.

Conceptos didácticos:
  · Metadatos: información sobre la información
  · EXIF: Exchangeable Image File Format — datos embebidos en fotos
  · GPS en fotos: cómo las imágenes revelan ubicaciones sin saberlo
  · Metadatos de documentos: autor, software, historial de revisiones
  · Privacidad: qué se filtra al compartir archivos sin limpiar
"""

import os
import struct
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import (
    ok, error, warn, info, result,
    section_title, separator, dim, cyan, green, yellow, white, red, magenta,
    prompt, ask_yes_no, pause, validate_file, format_size,
)

# ── Dependencias opcionales ──────────────────
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

try:
    import PyPDF2
    _HAS_PYPDF2 = True
except ImportError:
    _HAS_PYPDF2 = False

try:
    import docx as _docx
    _HAS_DOCX = True
except ImportError:
    _HAS_DOCX = False


# ──────────────────────────────────────────────
#  Helpers de riesgo de privacidad
# ──────────────────────────────────────────────
class PrivacyRisk:
    """Acumula campos sensibles encontrados en los metadatos."""

    def __init__(self):
        self._items = []   # (nivel, campo, valor)

    def add(self, level: str, field: str, value: str) -> None:
        """level: 'HIGH' | 'MEDIUM' | 'LOW'"""
        self._items.append((level, field, value))

    @property
    def items(self):
        return self._items

    @property
    def max_level(self) -> str:
        if any(l == "HIGH"   for l, _, _ in self._items): return "HIGH"
        if any(l == "MEDIUM" for l, _, _ in self._items): return "MEDIUM"
        return "LOW" if self._items else "NONE"

    def level_colored(self) -> str:
        lvl = self.max_level
        if lvl == "HIGH":   return red("ALTO ⚠")
        if lvl == "MEDIUM": return yellow("MEDIO")
        if lvl == "LOW":    return green("BAJO")
        return dim("ninguno")


def _privacy_summary(risk: PrivacyRisk) -> None:
    """Imprime el resumen de riesgo de privacidad."""
    if not risk.items:
        ok("Sin metadatos sensibles detectados.")
        return

    print()
    separator("─", 60)
    print(f"  {white('RIESGO DE PRIVACIDAD:')} {risk.level_colored()}")
    separator("─", 60)

    for level, field, value in risk.items:
        if level == "HIGH":
            icon = red("✗")
        elif level == "MEDIUM":
            icon = yellow("⚠")
        else:
            icon = cyan("·")
        print(f"  {icon} {white(field):<28} {dim(str(value)[:55])}")

    separator("─", 60)

    if risk.max_level == "HIGH":
        print(f"\n  {red('⛔ Datos sensibles de alto riesgo encontrados.')}")
        warn("Este archivo NO debería compartirse sin limpiar sus metadatos.")
        info("Usá ExifTool, mat2 o 'Guardar como' desde el programa original.")
    elif risk.max_level == "MEDIUM":
        print(f"\n  {yellow('⚠  Metadatos identificadores presentes.')}")
        info("Considerá limpiarlos antes de publicar el archivo.")
    else:
        ok("Metadatos de bajo impacto. Revisá si son necesarios.")


# ──────────────────────────────────────────────
#  Conversión GPS (grados/minutos/segundos → decimal)
# ──────────────────────────────────────────────
def _gps_to_decimal(values) -> float | None:
    """
    Convierte coordenadas GPS en formato DMS (grados, minutos, segundos)
    a grados decimales.
    DMS: ((grados_num, grados_den), (min_num, min_den), (seg_num, seg_den))
    """
    try:
        def _ratio(r):
            if hasattr(r, "numerator"):   # IFDRational de Pillow
                return r.numerator / r.denominator
            if isinstance(r, tuple):
                return r[0] / r[1]
            return float(r)

        deg = _ratio(values[0])
        mn  = _ratio(values[1])
        sec = _ratio(values[2])
        return deg + (mn / 60.0) + (sec / 3600.0)
    except Exception:
        return None


def _extract_gps(gps_info: dict) -> dict:
    """Decodifica el bloque GPS de EXIF y devuelve un dict con lat/lon/alt."""
    decoded = {}
    for key, val in gps_info.items():
        tag_name = GPSTAGS.get(key, str(key))
        decoded[tag_name] = val

    result_dict = {}

    lat_vals = decoded.get("GPSLatitude")
    lat_ref  = decoded.get("GPSLatitudeRef", "N")
    lon_vals = decoded.get("GPSLongitude")
    lon_ref  = decoded.get("GPSLongitudeRef", "E")

    if lat_vals and lon_vals:
        lat = _gps_to_decimal(lat_vals)
        lon = _gps_to_decimal(lon_vals)

        if lat is not None and lon is not None:
            if lat_ref == "S": lat = -lat
            if lon_ref == "W": lon = -lon
            result_dict["latitud"]       = f"{lat:.6f}°"
            result_dict["longitud"]      = f"{lon:.6f}°"
            result_dict["maps_url"]      = f"https://maps.google.com/?q={lat:.6f},{lon:.6f}"
            result_dict["_lat_decimal"]  = lat
            result_dict["_lon_decimal"]  = lon

    alt_val = decoded.get("GPSAltitude")
    alt_ref = decoded.get("GPSAltitudeRef", 0)
    if alt_val is not None:
        try:
            alt = float(alt_val) if not isinstance(alt_val, tuple) else alt_val[0] / alt_val[1]
            if alt_ref == 1: alt = -alt
            result_dict["altitud"] = f"{alt:.1f} m"
        except Exception:
            pass

    ts_date = decoded.get("GPSDateStamp", "")
    ts_time = decoded.get("GPSTimeStamp")
    if ts_date or ts_time:
        result_dict["timestamp_gps"] = f"{ts_date} {ts_time}"

    return result_dict


# ──────────────────────────────────────────────
#  Extracción EXIF de imágenes
# ──────────────────────────────────────────────
_EXIF_SENSITIVE = {
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal",
    "DateTimeDigitized", "Artist", "Copyright", "ImageDescription",
    "UserComment", "CameraOwnerName", "BodySerialNumber",
    "LensSerialNumber", "GPSInfo",
}

_EXIF_INTERESTING = {
    "ExifImageWidth", "ExifImageHeight", "ImageWidth", "ImageLength",
    "Orientation", "XResolution", "YResolution", "Flash",
    "FocalLength", "ExposureTime", "FNumber", "ISOSpeedRatings",
    "WhiteBalance", "DigitalZoomRatio", "SceneCaptureType",
    "LightSource", "MeteringMode",
}


def _extract_image_metadata(path: str) -> dict:
    """
    Extrae metadatos EXIF completos de una imagen usando Pillow.
    Devuelve un dict clasificado: basic, camera, gps, sensitive.
    """
    if not _HAS_PIL:
        return {"_error": "Pillow no instalado (pip install Pillow)"}

    try:
        img  = Image.open(path)
        data = {
            "_format":  img.format,
            "_mode":    img.mode,
            "_size":    f"{img.width} × {img.height} px",
        }

        exif_raw = img._getexif()
        if not exif_raw:
            data["_no_exif"] = True
            return data

        camera   = {}
        dates    = {}
        gps_raw  = {}
        extra    = {}
        other    = {}

        for tag_id, value in exif_raw.items():
            tag_name = TAGS.get(tag_id, str(tag_id))

            # Saltar bytes crudos y MakerNote (suelen ser ilegibles)
            if isinstance(value, bytes) and len(value) > 64:
                continue
            if tag_name in ("MakerNote", "PrintImageMatching"):
                continue

            # Convertir IFDRational a float para serialización
            try:
                if hasattr(value, "numerator"):
                    value = float(value)
                elif isinstance(value, tuple) and len(value) == 2:
                    value = f"{value[0]}/{value[1]}"
            except Exception:
                value = str(value)

            if tag_name == "GPSInfo":
                gps_raw = value if isinstance(value, dict) else {}
            elif tag_name in ("Make", "Model", "LensModel",
                              "CameraOwnerName", "BodySerialNumber", "LensSerialNumber"):
                camera[tag_name] = value
            elif "DateTime" in tag_name or "Date" in tag_name:
                dates[tag_name] = value
            elif tag_name in _EXIF_INTERESTING:
                extra[tag_name] = value
            elif tag_name in _EXIF_SENSITIVE:
                other[tag_name] = value
            else:
                other[tag_name] = value

        data["camera"] = camera
        data["dates"]  = dates
        data["extra"]  = extra
        data["other"]  = other

        # GPS
        if gps_raw:
            data["gps"] = _extract_gps(gps_raw)

        return data

    except Exception as e:
        return {"_error": str(e)}


def _print_image_metadata(path: str, data: dict, risk: PrivacyRisk) -> None:
    """Imprime los metadatos de imagen con formato."""
    separator("═", 60)
    print(f"  {white('IMAGEN:')} {dim(os.path.basename(path))}")
    separator("─", 60)

    result("Formato",  data.get("_format", "?"))
    result("Modo",     data.get("_mode", "?"))
    result("Tamaño",   data.get("_size", "?"))
    result("Archivo",  format_size(os.path.getsize(path)))

    if data.get("_no_exif"):
        print()
        ok("Este archivo no contiene datos EXIF.")
        return

    if "_error" in data:
        error(f"Error al leer EXIF: {data['_error']}")
        return

    # Cámara
    camera = data.get("camera", {})
    if camera:
        print()
        print(f"  {white('CÁMARA / DISPOSITIVO:')}")
        separator("─", 60)
        for k, v in camera.items():
            result(k, dim(str(v)))
            risk.add("MEDIUM", k, str(v))

    # Fechas
    dates = data.get("dates", {})
    if dates:
        print()
        print(f"  {white('FECHAS:')}")
        separator("─", 60)
        for k, v in dates.items():
            result(k, dim(str(v)))
            risk.add("LOW", k, str(v))

    # Ajustes de cámara
    extra = data.get("extra", {})
    if extra:
        print()
        print(f"  {white('AJUSTES DE CÁMARA:')}")
        separator("─", 60)
        for k, v in extra.items():
            result(k, dim(str(v)))

    # GPS — el más sensible
    gps = data.get("gps", {})
    if gps:
        print()
        print(f"  {red('⚠  DATOS GPS ENCONTRADOS:')}")
        separator("─", 60)
        for k, v in gps.items():
            if k.startswith("_"): continue
            if k == "maps_url":
                result(k, green(str(v)))
            else:
                result(k, red(str(v)))

        risk.add("HIGH", "GPS — Ubicación exacta", gps.get("maps_url", "presente"))
        print()
        warn("Esta imagen contiene coordenadas GPS.")
        info("Cualquiera que la reciba puede saber dónde fue tomada.")


# ──────────────────────────────────────────────
#  Extracción de metadatos PDF
# ──────────────────────────────────────────────
_PDF_SENSITIVE_FIELDS = {
    "/Author", "/Creator", "/Producer",
    "/Subject", "/Keywords",
}

def _extract_pdf_metadata(path: str) -> dict:
    """Extrae metadatos del documento PDF."""
    if not _HAS_PYPDF2:
        return {"_error": "PyPDF2 no instalado (pip install PyPDF2)"}

    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            meta   = reader.metadata or {}
            pages  = len(reader.pages)

            clean = {}
            for key, val in meta.items():
                clean[str(key)] = str(val) if val else ""

            return {
                "pages":    pages,
                "fields":   clean,
                "encrypted": reader.is_encrypted,
            }

    except Exception as e:
        return {"_error": str(e)}


def _print_pdf_metadata(path: str, data: dict, risk: PrivacyRisk) -> None:
    """Imprime los metadatos de un PDF."""
    separator("═", 60)
    print(f"  {white('PDF:')} {dim(os.path.basename(path))}")
    separator("─", 60)

    if "_error" in data:
        error(f"Error al leer PDF: {data['_error']}")
        return

    result("Páginas",   str(data.get("pages", "?")))
    result("Cifrado",   red("SÍ") if data.get("encrypted") else green("NO"))
    result("Tamaño",    format_size(os.path.getsize(path)))

    fields = data.get("fields", {})
    if not fields:
        print()
        ok("Sin metadatos de documento encontrados.")
        return

    print()
    print(f"  {white('METADATOS DEL DOCUMENTO:')}")
    separator("─", 60)

    LABEL_MAP = {
        "/Title":        "Título",
        "/Author":       "Autor",
        "/Subject":      "Asunto",
        "/Keywords":     "Palabras clave",
        "/Creator":      "Software creador",
        "/Producer":     "Software productor",
        "/CreationDate": "Fecha de creación",
        "/ModDate":      "Fecha de modificación",
        "/Trapped":      "Trapped",
    }

    for key, val in fields.items():
        if not val:
            continue
        label = LABEL_MAP.get(key, key.lstrip("/"))

        # Formatear fechas PDF (formato: D:20240101120000+00'00')
        if key in ("/CreationDate", "/ModDate") and val.startswith("D:"):
            try:
                dt_str = val[2:16]
                dt     = datetime.strptime(dt_str, "%Y%m%d%H%M%S")
                val    = dt.strftime("%Y-%m-%d %H:%M:%S") + dim(f"  (raw: {val[:20]})")
            except Exception:
                pass

        result(label, dim(str(val)[:70]))

        if key in _PDF_SENSITIVE_FIELDS and val:
            risk.add("MEDIUM", label, val)

    # Detectar software específico (puede revelar versión vulnerable)
    creator  = fields.get("/Creator", "")
    producer = fields.get("/Producer", "")
    if any(sw in (creator + producer).lower() for sw in
           ["word", "libreoffice", "writer", "acrobat", "photoshop"]):
        print()
        info(f"Software detectado: {dim(f'{creator} / {producer}'.strip(' /'))}")
        risk.add("LOW", "Software identificado", f"{creator} {producer}")


# ──────────────────────────────────────────────
#  Extracción de metadatos Word (.docx)
# ──────────────────────────────────────────────
def _extract_docx_metadata(path: str) -> dict:
    """Extrae metadatos de un documento Word (.docx)."""
    if not _HAS_DOCX:
        return {"_error": "python-docx no instalado (pip install python-docx)"}

    try:
        doc   = _docx.Document(path)
        props = doc.core_properties

        return {
            "author":           props.author or "",
            "last_modified_by": props.last_modified_by or "",
            "created":          props.created.isoformat() if props.created else "",
            "modified":         props.modified.isoformat() if props.modified else "",
            "title":            props.title or "",
            "subject":          props.subject or "",
            "description":      props.description or "",
            "keywords":         props.keywords or "",
            "category":         props.category or "",
            "content_status":   props.content_status or "",
            "revision":         props.revision,
            "version":          props.version or "",
            "language":         props.language or "",
        }

    except Exception as e:
        return {"_error": str(e)}


def _print_docx_metadata(path: str, data: dict, risk: PrivacyRisk) -> None:
    """Imprime los metadatos de un documento Word."""
    separator("═", 60)
    print(f"  {white('WORD (.docx):')} {dim(os.path.basename(path))}")
    separator("─", 60)

    if "_error" in data:
        error(f"Error al leer .docx: {data['_error']}")
        return

    result("Tamaño", format_size(os.path.getsize(path)))

    FIELDS = [
        ("title",           "Título",                "LOW"),
        ("subject",         "Asunto",                "LOW"),
        ("author",          "Autor",                 "MEDIUM"),
        ("last_modified_by","Último editor",         "MEDIUM"),
        ("created",         "Fecha de creación",     "LOW"),
        ("modified",        "Última modificación",   "LOW"),
        ("revision",        "Revisión nº",           "LOW"),
        ("keywords",        "Palabras clave",        "LOW"),
        ("description",     "Descripción",           "LOW"),
        ("category",        "Categoría",             "LOW"),
        ("language",        "Idioma",                "LOW"),
        ("version",         "Versión",               "LOW"),
    ]

    print()
    print(f"  {white('METADATOS DEL DOCUMENTO:')}")
    separator("─", 60)

    has_data = False
    for key, label, level in FIELDS:
        val = data.get(key)
        if val is None or val == "" or val == 0:
            continue
        has_data = True
        result(label, dim(str(val)[:70]))
        if level in ("HIGH", "MEDIUM") and val:
            risk.add(level, label, str(val))

    if not has_data:
        ok("Sin metadatos de documento encontrados.")
        return

    # Alerta de historial de autores
    author   = data.get("author", "")
    last_mod = data.get("last_modified_by", "")
    if author and last_mod and author != last_mod:
        print()
        warn(f"El documento fue creado por '{author}' y editado por '{last_mod}'.")
        info("Esto puede revelar nombres de personas u organizaciones internas.")
        risk.add("MEDIUM", "Múltiples autores detectados", f"{author} / {last_mod}")


# ──────────────────────────────────────────────
#  Dispatcher por extensión
# ──────────────────────────────────────────────
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".bmp", ".webp", ".heic", ".heif"}
PDF_EXTS   = {".pdf"}
WORD_EXTS  = {".docx"}

def _detect_type(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext in IMAGE_EXTS: return "image"
    if ext in PDF_EXTS:   return "pdf"
    if ext in WORD_EXTS:  return "docx"
    return "unknown"


def _analyze_file(path: str) -> None:
    """Despacha el análisis al extractor correcto y muestra el resumen de privacidad."""
    ftype = _detect_type(path)
    risk  = PrivacyRisk()

    if ftype == "image":
        if not _HAS_PIL:
            error("Pillow no instalado. Ejecutá: pip install Pillow")
            return
        data = _extract_image_metadata(path)
        _print_image_metadata(path, data, risk)

    elif ftype == "pdf":
        if not _HAS_PYPDF2:
            error("PyPDF2 no instalado. Ejecutá: pip install PyPDF2")
            return
        data = _extract_pdf_metadata(path)
        _print_pdf_metadata(path, data, risk)

    elif ftype == "docx":
        if not _HAS_DOCX:
            error("python-docx no instalado. Ejecutá: pip install python-docx")
            return
        data = _extract_docx_metadata(path)
        _print_docx_metadata(path, data, risk)

    else:
        warn(f"Formato no soportado: '{Path(path).suffix}'")
        info(f"Formatos soportados: {', '.join(sorted(IMAGE_EXTS | PDF_EXTS | WORD_EXTS))}")
        return

    # Resumen de privacidad siempre al final
    _privacy_summary(risk)


# ──────────────────────────────────────────────
#  Modo 1: Analizar un archivo
# ──────────────────────────────────────────────
def _mode_analyze() -> None:
    section_title("EXTRAER METADATOS DE ARCHIVO")

    path = prompt("Ruta del archivo")
    if not path:
        warn("No se ingresó ninguna ruta.")
        return
    if not validate_file(path):
        error(f"El archivo '{path}' no existe o no es legible.")
        return

    _analyze_file(path)


# ──────────────────────────────────────────────
#  Modo 2: Analizar múltiples archivos
# ──────────────────────────────────────────────
def _mode_batch() -> None:
    section_title("ANÁLISIS EN LOTE")

    info("Ingresá las rutas de los archivos a analizar (Enter en blanco para terminar).")
    paths = []
    while True:
        p = prompt(f"Archivo {len(paths) + 1}")
        if not p:
            break
        if not validate_file(p):
            warn(f"'{p}' no existe o no es legible. Omitido.")
            continue
        paths.append(p)
        if len(paths) >= 10:
            warn("Máximo 10 archivos por lote.")
            break

    if not paths:
        warn("No se ingresó ningún archivo válido.")
        return

    # Resumen rápido de todos los archivos antes de analizar
    print()
    separator("─", 60)
    print(f"  {white(f'{len(paths)} archivo(s) a analizar:')}")
    for i, p in enumerate(paths, 1):
        print(f"  {dim(f'{i}.')} {dim(os.path.basename(p)):<40} {dim(format_size(os.path.getsize(p)))}")
    separator("─", 60)

    if not ask_yes_no("¿Continuar con el análisis?", default=True):
        return

    for i, path in enumerate(paths, 1):
        print()
        print(f"\n  {cyan(f'[{i}/{len(paths)}]')} {white(os.path.basename(path))}")
        _analyze_file(path)
        print()


# ──────────────────────────────────────────────
#  Modo 3: Escanear directorio
# ──────────────────────────────────────────────
def _mode_scan_dir() -> None:
    section_title("ESCANEAR DIRECTORIO")

    dir_path = prompt("Directorio a escanear")
    if not dir_path or not os.path.isdir(dir_path):
        error("Directorio no válido.")
        return

    all_exts   = IMAGE_EXTS | PDF_EXTS | WORD_EXTS
    found      = []
    for root, _, files in os.walk(dir_path):
        for fname in files:
            if Path(fname).suffix.lower() in all_exts:
                found.append(os.path.join(root, fname))

    if not found:
        warn(f"No se encontraron archivos soportados en '{dir_path}'.")
        info(f"Tipos buscados: {', '.join(sorted(all_exts))}")
        return

    print()
    result("Archivos encontrados", str(len(found)))
    separator("─", 60)

    # Tabla de archivos encontrados
    for i, p in enumerate(found[:20], 1):
        rel  = os.path.relpath(p, dir_path)
        ftype = _detect_type(p)
        icon  = "🖼 " if ftype == "image" else "📄 " if ftype == "pdf" else "📝 "
        print(f"  {dim(f'{i:3d}.')} {icon}{dim(rel):<45} {dim(format_size(os.path.getsize(p)))}")

    if len(found) > 20:
        warn(f"Mostrando los primeros 20 de {len(found)} archivos.")

    separator("─", 60)

    # Analizar solo los que tengan datos GPS (modo privacidad)
    gps_mode = ask_yes_no("¿Modo GPS: analizar solo archivos con coordenadas?", default=False)

    if gps_mode:
        info("Buscando imágenes con datos GPS...")
        gps_found = []
        for path in found:
            if _detect_type(path) != "image" or not _HAS_PIL:
                continue
            data = _extract_image_metadata(path)
            if data.get("gps"):
                gps_found.append((path, data["gps"]))

        if not gps_found:
            ok("Ninguna imagen contiene datos GPS.")
        else:
            print()
            print(f"  {red(f'⚠  {len(gps_found)} imagen(es) con GPS encontradas:')}")
            separator("─", 60)
            for path, gps in gps_found:
                print(f"\n  {red('►')} {white(os.path.basename(path))}")
                for k, v in gps.items():
                    if k.startswith("_"): continue
                    if k == "maps_url":
                        result(k, green(str(v)))
                    else:
                        result(k, red(str(v)))
    else:
        # Analizar todos (hasta 10)
        limit = min(len(found), 10)
        if len(found) > 10:
            warn(f"Analizando los primeros {limit} de {len(found)} archivos.")

        for path in found[:limit]:
            print()
            _analyze_file(path)


# ──────────────────────────────────────────────
#  Modo 4: Explicación didáctica
# ──────────────────────────────────────────────
def _mode_explain() -> None:
    section_title("METADATOS: DATOS OCULTOS EN TUS ARCHIVOS")

    print(f"""
  {white('¿Qué son los metadatos?')}
  {dim('─' * 56)}

  Los metadatos son datos sobre los datos.
  Un archivo tiene contenido visible (la foto, el texto)
  y metadatos invisibles embebidos que describen ese contenido.

  {cyan('Ejemplos de metadatos peligrosos:')}
  {dim('·')} Una foto tomada con el móvil incluye {red('coordenadas GPS exactas')}
  {dim('·')} Un Word guardado incluye el {red('nombre de usuario')} del sistema
  {dim('·')} Un PDF puede revelar el {red('software y versión')} usados para crearlo
  {dim('·')} Un archivo de audio puede tener el {red('nombre del artista y estudio')}


  {white('EXIF — Exchangeable Image File Format')}
  {dim('─' * 56)}

  Estándar creado en 1995 para almacenar metadatos en imágenes.
  Todo teléfono y cámara digital escribe EXIF por defecto.

  {cyan('Bloques principales:')}
  {dim('·')} {white('IFD0')}        — Fabricante, modelo, software, fechas
  {dim('·')} {white('ExifIFD')}     — Configuración de cámara (ISO, apertura, exposición)
  {dim('·')} {white('GPS IFD')}     — Latitud, longitud, altitud, timestamp
  {dim('·')} {white('MakerNote')}   — Datos propietarios del fabricante (suelen ser binarios)

  {red('GPS IFD — el más peligroso:')}
  {dim('·')} Latitud y longitud en grados/minutos/segundos
  {dim('·')} Precisión típica: ±5 metros con GPS activo
  {dim('·')} Permite reconstruir {red('dónde vivís, trabajás o viajás')}


  {white('Casos reales de exposición por metadatos')}
  {dim('─' * 56)}

  {red('2012 — John McAfee')}
  {dim('·')} Estaba prófugo en Guatemala
  {dim('·')} Un periodista publicó una foto con él
  {dim('·')} La foto tenía GPS en los EXIF
  {dim('·')} Las autoridades localizaron su escondite en horas

  {red('2012 — Anonymous (Higinio Ochoa)')}
  {dim('·')} Publicó una foto de su novia para burlarse del FBI
  {dim('·')} La foto tenía coordenadas GPS
  {dim('·')} Fue arrestado días después

  {red('Periodistas y activistas')}
  {dim('·')} Fotos de fuentes o reuniones secretas con GPS activo
  {dim('·')} Documentos Word con nombre de autor real en metadatos


  {white('¿Cómo eliminar metadatos?')}
  {dim('─' * 56)}

  {cyan('Linux / macOS:')}
  {dim('·')} {white('exiftool -all= archivo.jpg')}   — elimina todos los EXIF
  {dim('·')} {white('mat2 archivo.pdf')}              — limpia PDFs y más formatos
  {dim('·')} {white('convert -strip in.jpg out.jpg')} — ImageMagick

  {cyan('Windows:')}
  {dim('·')} Click derecho → Propiedades → Detalles → Quitar propiedades
  {dim('·')} ExifTool GUI

  {cyan('Online (con precaución):')}
  {dim('·')} Verexif.com — no subas archivos privados a servicios externos

  {cyan('Redes Sociales:')}
  {dim('·')} Facebook, Instagram y Twitter {green('eliminan EXIF')} al subir
  {dim('·')} WhatsApp {yellow('comprime')} la imagen pero puede conservar parcialmente
  {dim('·')} Telegram {red('puede conservar EXIF')} si no comprime la imagen
    """)


# ──────────────────────────────────────────────
#  Submenú
# ──────────────────────────────────────────────
_SUBMENU = [
    ("1", "Analizar un archivo",                         _mode_analyze),
    ("2", "Análisis en lote (varios archivos)",          _mode_batch),
    ("3", "Escanear directorio",                         _mode_scan_dir),
    ("4", "¿Qué son los metadatos y por qué importan?", _mode_explain),
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
        section_title("HERRAMIENTA 8 — EXTRACTOR DE METADATOS")
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
