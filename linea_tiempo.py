#!/usr/bin/env python3
"""
linea_tiempo.py - Une evidencias de distintas fuentes en una sola línea de tiempo forense.

Cada fuente se declara con --fuente TIPO:RUTA[,opción=valor...]

  whatsapp:msgstore.db[,wa=wa.db]            mensajes de WhatsApp (esquema moderno o viejo)
  fotos:DCIM/[,tz=ZONA]                      EXIF (DateTimeOriginal + OffsetTimeOriginal, GPS, modelo)
                                             y fecha del nombre del archivo; marca discrepancias
  bodyfile:fls.body                          tiempos MACB del sistema de archivos (fls -m de Sleuth Kit)
  authlog:auth.log[,anio=2026][,tz=ZONA]     accesos SSH, fallos agrupados, sudo y cambios de cuentas
  volatility:pslist.csv                      `vol -r csv` de windows.pslist / pstree / netscan
  csv:archivo.csv,fecha=COL[,detalle=COL+COL][,formato=%d/%m/%Y %H:%M][,tz=ZONA][,tipo=TEXTO]
                                             cualquier CSV (extracto bancario, eventos del acta, etc.)

Opciones de cualquier fuente:
  tz=ZONA        zona de las horas que vienen SIN zona: UTC, -03:00 o America/Argentina/Salta
  desfase=+95s   el reloj del equipo estaba adelantado 95 s (como lo mide adb_triage.py);
                 se corrige restándolo. Acepta s, m, h: -2m, +1h30m
  nombre=TEXTO   cómo aparece la fuente en el informe

Ejemplo:
  python linea_tiempo.py --zona America/Argentina/Salta -o salida \\
      --fuente whatsapp:evidencia/msgstore.db,wa=evidencia/wa.db,desfase=+95s \\
      --fuente fotos:evidencia/DCIM,tz=America/Argentina/Salta,desfase=+95s \\
      --fuente "csv:banco.csv,fecha=Fecha,formato=%d/%m/%Y %H:%M:%S,tz=-03:00,detalle=Concepto+Importe"

Salida: linea_tiempo.csv y linea_tiempo.html en la carpeta -o. Las fuentes se abren en modo
lectura y se hashean antes y después: si algo cambió durante el análisis, el informe lo dice.
"""
import argparse
import csv
import hashlib
import html
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0"
UTC = timezone.utc
MESES = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
DIAS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
MINIMO_RAZONABLE = datetime(1995, 1, 1, tzinfo=UTC)


class ErrorFuente(Exception):
    pass


@dataclass
class Evento:
    utc: datetime
    tipo: str
    detalle: str
    referencia: str = ""
    original: str = ""          # el valor tal como figura en la fuente, sin convertir
    marcas: list = field(default_factory=list)
    fuente: str = ""
    reloj_propio: bool = True   # False si la hora la puso OTRO equipo (no se le aplica el desfase)


@dataclass
class Fuente:
    tipo: str
    ruta: Path
    opciones: dict
    nombre: str = ""
    hash_antes: str = ""
    hash_despues: str = ""
    eventos: int = 0
    notas: list = field(default_factory=list)


# ---------------------------------------------------------------- zonas, desfase y fechas

def zona(texto):
    """UTC, ±HH:MM o un nombre IANA (America/Argentina/Salta)."""
    texto = (texto or "UTC").strip()
    if texto.upper() in ("UTC", "Z"):
        return UTC
    m = re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})?", texto)
    if m:
        delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        return timezone(-delta if m.group(1) == "-" else delta)
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(texto)
    except Exception as e:  # en Windows hace falta el paquete tzdata
        raise ErrorFuente(f"zona desconocida '{texto}' ({e}). En Windows: pip install tzdata") from None


def desfase(texto):
    """'+95s', '-2m', '+1h30m', '95' -> timedelta. Positivo = el reloj del equipo estaba adelantado."""
    if not texto:
        return timedelta(0)
    m = re.fullmatch(r"([+-]?)((?:\d+[hms]?)+)", texto.strip())
    if not m:
        raise ErrorFuente(f"desfase inválido: {texto}")
    total = 0
    for n, u in re.findall(r"(\d+)([hms]?)", m.group(2)):
        total += int(n) * {"h": 3600, "m": 60, "s": 1, "": 1}[u]
    return timedelta(seconds=-total if m.group(1) == "-" else total)


def con_zona(dt, tz):
    """Si la fecha no trae zona, se interpreta en tz. Devuelve UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.astimezone(UTC)


def desde_epoch(segundos):
    return datetime.fromtimestamp(segundos, UTC)


# ---------------------------------------------------------------- integridad de las fuentes

def sha256_archivo(ruta):
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def huella(ruta):
    """SHA-256 de un archivo, o de la lista (ruta relativa + SHA-256) de todos los archivos de una carpeta."""
    ruta = Path(ruta)
    if ruta.is_file():
        return sha256_archivo(ruta)
    h = hashlib.sha256()
    for p in sorted(x for x in ruta.rglob("*") if x.is_file()):
        h.update(f"{p.relative_to(ruta).as_posix()}  {sha256_archivo(p)}\n".encode())
    return h.hexdigest()


# ---------------------------------------------------------------- WhatsApp

def leer_whatsapp(f):
    """Copia la base (y su -wal/-shm) a una carpeta temporal y lee la copia: el original no se toca.
    Abrir el original con immutable=1 sería peor: ignora el WAL y se pierden los mensajes recientes."""
    # Los timestamps de WhatsApp son UTC en milisegundos: no hace falta zona.
    with tempfile.TemporaryDirectory() as tmp:
        copia = Path(tmp) / "msgstore.db"
        shutil.copy2(f.ruta, copia)
        for sufijo in ("-wal", "-shm"):
            extra = Path(str(f.ruta) + sufijo)
            if extra.exists():
                shutil.copy2(extra, str(copia) + sufijo)
                if sufijo == "-wal" and extra.stat().st_size:
                    f.notas.append(f"tiene {extra.name} ({extra.stat().st_size} bytes): se leyó junto con la base")
        nombres = {}
        if f.opciones.get("wa"):
            # "with sqlite3.connect()" NO cierra la conexión (solo hace commit): closing() sí
            with closing(sqlite3.connect(f"file:{Path(f.opciones['wa']).as_posix()}?mode=ro", uri=True)) as wa:
                nombres = {j: n for j, n in wa.execute("SELECT jid, display_name FROM wa_contacts") if n}
        con = sqlite3.connect(copia)
        try:
            tablas = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if {"message", "chat", "jid"} <= tablas:
                filas = con.execute("""
                    SELECT m._id, j.raw_string, m.from_me, m.timestamp, m.message_type, m.text_data
                    FROM message m JOIN chat c ON c._id = m.chat_row_id JOIN jid j ON j._id = c.jid_row_id
                    WHERE m.timestamp > 0 ORDER BY m.timestamp, m._id""").fetchall()
            elif "messages" in tablas:
                f.notas.append("esquema viejo (tabla messages)")
                filas = con.execute("""
                    SELECT _id, key_remote_jid, key_from_me, timestamp, media_wa_type, data
                    FROM messages WHERE timestamp > 0 ORDER BY timestamp, _id""").fetchall()
            else:
                raise ErrorFuente("no parece una base msgstore.db de WhatsApp (faltan las tablas message/messages)")
        finally:
            con.close()
    for _id, jid, from_me, ts, tipo_msg, texto in filas:
        contacto = nombres.get(jid, jid.split("@")[0] if jid else "?")
        if jid and jid in nombres:
            contacto = f"{nombres[jid]} ({jid.split('@')[0]})"
        contenido = texto if texto is not None else f"[adjunto, message_type={tipo_msg}]"
        yield Evento(desde_epoch(ts / 1000),
                     "WhatsApp enviado" if from_me else "WhatsApp recibido",
                     f"{'→' if from_me else '←'} {contacto}: {contenido}",
                     f"message._id={_id}", str(ts))


# ---------------------------------------------------------------- fotos

PATRONES_NOMBRE = [
    # (regex, ¿el nombre está en UTC?, ¿tiene hora?)
    (re.compile(r"PXL_(\d{8})_(\d{6})"), True, True),                  # Google Pixel: hora UTC
    (re.compile(r"(?:IMG|VID|Screenshot)[_-](\d{8})[_-](\d{6})"), False, True),
    (re.compile(r"(?:IMG|VID|AUD|PTT)-(\d{8})-WA\d+"), False, False),  # WhatsApp: solo la fecha de recepción
]
EXTENSIONES_FOTO = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp"}


def fecha_de_nombre(nombre, tz):
    for regex, es_utc, con_hora in PATRONES_NOMBRE:
        m = regex.search(nombre)
        if not m:
            continue
        try:
            if con_hora:
                dt = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
                return con_zona(dt, UTC if es_utc else tz), True
            return datetime.strptime(m.group(1), "%Y%m%d").date(), False
        except ValueError:
            return None, False
    return None, False


def _racional(x):
    try:
        return float(x)
    except TypeError:
        return x[0] / x[1]


def leer_exif(ruta):
    """Devuelve (fecha_naive, offset_texto, modelo, (lat, lon)) leyendo con Pillow."""
    from PIL import Image
    with Image.open(ruta) as im:
        exif = im.getexif()
        sub = exif.get_ifd(0x8769)
        gps = exif.get_ifd(0x8825)
        fecha = sub.get(0x9003) or exif.get(0x0132)       # DateTimeOriginal, si no DateTime
        offset = sub.get(0x9011)                          # OffsetTimeOriginal ("-03:00")
        marca = str(exif.get(0x010F) or "").strip("\x00 ")
        modelo = str(exif.get(0x0110) or "").strip("\x00 ")
        if marca and not modelo.lower().startswith(marca.lower()):
            modelo = f"{marca} {modelo}".strip()
        coords = None
        if gps.get(2) and gps.get(4):
            def grados(v, ref):
                g = _racional(v[0]) + _racional(v[1]) / 60 + _racional(v[2]) / 3600
                return -g if ref in ("S", "W") else g
            coords = (round(grados(gps[2], gps.get(1)), 6), round(grados(gps[4], gps.get(3)), 6))
    dt = None
    if fecha:
        try:
            dt = datetime.strptime(str(fecha).strip("\x00 "), "%Y:%m:%d %H:%M:%S")
        except ValueError:
            pass
    return dt, offset, modelo, coords


def leer_fotos(f):
    tz = zona(f.opciones.get("tz"))
    raiz = f.ruta
    archivos = [raiz] if raiz.is_file() else sorted(p for p in raiz.rglob("*") if p.suffix.lower() in EXTENSIONES_FOTO)
    sin_fecha = []
    for p in archivos:
        ref = p.name if raiz.is_file() else p.relative_to(raiz).as_posix()
        corto = sha256_archivo(p)[:16]
        try:
            exif_dt, offset, modelo, coords = leer_exif(p)
        except Exception as e:
            f.notas.append(f"{ref}: no se pudo leer ({e.__class__.__name__})")
            exif_dt, offset, modelo, coords = None, None, "", None
        nombre_dt, nombre_con_hora = fecha_de_nombre(p.name, tz)

        extra = []
        if modelo:
            extra.append(modelo)
        extra.append(f"GPS {coords[0]}, {coords[1]}" if coords else "sin GPS")
        marcas = []
        exif_utc = None
        if exif_dt:
            if offset:
                exif_utc = con_zona(exif_dt, zona(offset))
            else:
                exif_utc = con_zona(exif_dt, tz)
                marcas.append("ZONA SUPUESTA")
        referencia = f"{ref} · sha256 {corto}…"

        if exif_utc and nombre_dt and nombre_con_hora and abs(exif_utc - nombre_dt) > timedelta(seconds=60):
            for cuando, origen in ((exif_utc, "según EXIF"), (nombre_dt, "según el NOMBRE")):
                yield Evento(cuando, "Foto", f"{p.name} {origen} · " + " · ".join(extra), referencia,
                             f"EXIF {exif_dt} {offset or ''} / nombre {p.name}".strip(),
                             marcas + ["DISCREPANCIA"])
        elif exif_utc:
            detalle = f"{p.name} · " + " · ".join(extra)
            recibida = nombre_dt is not None and not nombre_con_hora   # IMG-AAAAMMDD-WAnnnn: vino por WhatsApp
            if recibida:
                detalle += f" · recibida por WhatsApp el {nombre_dt:%d/%m/%Y}: el EXIF lo escribió el equipo de origen"
                if abs((exif_utc.date() - nombre_dt).days) > 1:
                    marcas.append("DISCREPANCIA")
            yield Evento(exif_utc, "Foto", detalle, referencia, f"EXIF {exif_dt} {offset or ''}".strip(), marcas,
                         reloj_propio=not recibida)
        elif nombre_dt and nombre_con_hora:
            yield Evento(nombre_dt, "Imagen (fecha del nombre)", f"{p.name} · sin EXIF · " + " · ".join(extra[-1:]),
                         referencia, p.name, ["SIN EXIF"])
        else:
            sin_fecha.append(ref)
    if sin_fecha:
        f.notas.append(f"{len(sin_fecha)} imágenes sin fecha en EXIF ni en el nombre: {', '.join(sin_fecha[:5])}")


# ---------------------------------------------------------------- bodyfile (Sleuth Kit)

def leer_bodyfile(f):
    """Formato TSK 3: MD5|nombre|inodo|modo|UID|GID|tamaño|atime|mtime|ctime|crtime (epoch UTC)."""
    with open(f.ruta, encoding="utf-8", errors="replace") as fh:
        for n, linea in enumerate(fh, 1):
            partes = linea.rstrip("\n").split("|")
            if len(partes) != 11:
                continue
            _, nombre, inodo, modo, _, _, tam, *tiempos = partes
            por_momento = {}
            a, m, c, b = (int(x) if x.lstrip("-").isdigit() else 0 for x in tiempos)
            for letra, valor in (("m", m), ("a", a), ("c", c), ("b", b)):
                if valor > 0:
                    por_momento.setdefault(valor, set()).add(letra)
            borrado = "(deleted" in nombre
            for valor, letras in sorted(por_momento.items()):
                macb = "".join(x if x in letras else "." for x in "macb")
                yield Evento(desde_epoch(valor), f"Archivo {macb}",
                             f"{nombre} ({tam} bytes, {modo})", f"inodo {inodo} · línea {n}", str(valor),
                             ["BORRADO"] if borrado else [])


# ---------------------------------------------------------------- auth.log

RE_CLASICO = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d\d:\d\d:\d\d) (\S+) ([^\s\[:]+)(?:\[\d+\])?: (.*)$")
RE_ISO = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?) (\S+) ([^\s\[:]+)(?:\[\d+\])?: (.*)$")


def clasificar_auth(proceso, msg):
    m = re.search(r"Accepted (\S+) for (\S+) from (\S+)", msg)
    if m:
        return "SSH acceso", f"{m.group(2)} entró con {m.group(1)} desde {m.group(3)}", ("ok", m.group(3))
    m = re.search(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)", msg)
    if m:
        return "SSH fallo", m.group(1), ("fallo", m.group(2))
    if proceso == "sudo":
        m = re.search(r"^\s*(\S+) : .*?COMMAND=(.*)$", msg)
        if m:
            return "sudo", f"{m.group(1)} ejecutó: {m.group(2)}", None
    if proceso in ("useradd", "usermod", "userdel", "groupadd", "gpasswd", "passwd", "chpasswd"):
        return "Cuentas", f"{proceso}: {msg}", None
    if proceso == "su" and "session opened" in msg:
        return "su", msg, None
    return None


def leer_authlog(f):
    tz = zona(f.opciones.get("tz"))
    anio = int(f.opciones.get("anio") or datetime.now().year)
    mes_anterior = 0
    usa_clasico = False
    rafaga = None  # fallos SSH seguidos de la misma IP se agrupan en un solo evento

    def cerrar(r):
        usuarios = ", ".join(sorted(r["usuarios"])[:6]) + ("…" if len(r["usuarios"]) > 6 else "")
        dur = r["fin"] - r["inicio"]
        return Evento(r["inicio"], "SSH fallos",
                      f"{r['n']} intentos fallidos desde {r['ip']} en {int(dur.total_seconds())} s · usuarios: {usuarios}",
                      f"líneas {r['linea0']}-{r['linea1']}", r["original"], ["FUERZA BRUTA"] if r["n"] >= 10 else [])

    with open(f.ruta, encoding="utf-8", errors="replace") as fh:
        for n, linea in enumerate(fh, 1):
            linea = linea.rstrip("\n")
            m = RE_ISO.match(linea)
            if m:
                original, _, proceso, msg = m.groups()
                cuando = con_zona(datetime.fromisoformat(original.replace("Z", "+00:00")), tz)
            else:
                m = RE_CLASICO.match(linea)
                if not m or m.group(1) not in MESES:
                    continue
                usa_clasico = True
                mes = MESES[m.group(1)]
                if mes < mes_anterior:          # pasó de diciembre a enero: el log no trae el año
                    anio += 1
                mes_anterior = mes
                original = f"{m.group(1)} {m.group(2)} {m.group(3)}"
                cuando = con_zona(datetime.strptime(f"{anio}-{mes}-{m.group(2)} {m.group(3)}", "%Y-%m-%d %H:%M:%S"), tz)
                proceso, msg = m.group(5), m.group(6)
            c = clasificar_auth(proceso, msg)
            if not c:
                continue
            tipo, detalle, extra = c
            if extra and extra[0] == "fallo":
                ip = extra[1]
                if rafaga and rafaga["ip"] == ip and cuando - rafaga["fin"] <= timedelta(minutes=5):
                    rafaga.update(n=rafaga["n"] + 1, fin=cuando, linea1=n)
                    rafaga["usuarios"].add(detalle)
                    continue
                if rafaga:
                    yield cerrar(rafaga)
                rafaga = dict(ip=ip, n=1, inicio=cuando, fin=cuando, usuarios={detalle}, linea0=n, linea1=n, original=original)
                continue
            if rafaga:
                yield cerrar(rafaga)
                rafaga = None
            yield Evento(cuando, tipo, detalle, f"línea {n}", original)
    if rafaga:
        yield cerrar(rafaga)
    if usa_clasico and "anio" not in f.opciones:
        f.notas.append(f"año supuesto {datetime.now().year}: el formato clásico de syslog no lo trae (indicarlo con anio=)")


# ---------------------------------------------------------------- Volatility 3

def fecha_vol(texto):
    texto = (texto or "").strip()
    if not texto or texto in ("N/A", "-"):
        return None
    texto = texto.replace(" UTC", "+00:00")
    try:
        return datetime.fromisoformat(texto).astimezone(UTC)
    except ValueError:
        return None


def leer_volatility(f):
    with open(f.ruta, encoding="utf-8-sig", newline="") as fh:
        filas = list(csv.DictReader(fh))
    if not filas:
        return
    cols = set(filas[0])
    if "CreateTime" in cols:
        f.notas.append("procesos (pslist/pstree)")
        for r in filas:
            nombre = f"{r.get('ImageFileName', '?')} (PID {r.get('PID')}, PPID {r.get('PPID')})"
            ruta = r.get("Cmd") or r.get("Path") or ""
            ruta = "" if ruta in ("-", "N/A") else f" · {ruta.replace(chr(92) * 2, chr(92))}"
            for col, tipo in (("CreateTime", "Proceso creado"), ("ExitTime", "Proceso terminado")):
                t = fecha_vol(r.get(col))
                if t:
                    yield Evento(t, tipo, nombre + (ruta if tipo == "Proceso creado" else ""),
                                 f"offset {r.get('Offset(V)', r.get('Offset', ''))}", r.get(col))
    elif "Created" in cols and "ForeignAddr" in cols:
        f.notas.append("conexiones (netscan)")
        for r in filas:
            t = fecha_vol(r.get("Created"))
            if not t:
                continue
            if r.get("State") == "LISTENING" or r.get("ForeignAddr") in ("0.0.0.0", "::", "*"):
                tipo, detalle = "Puerto en escucha", f"{r['Proto']} {r['LocalAddr']}:{r['LocalPort']}"
            else:
                tipo = "Conexión"
                detalle = f"{r['Proto']} {r['LocalAddr']}:{r['LocalPort']} ↔ {r['ForeignAddr']}:{r['ForeignPort']} {r.get('State', '')}"
            yield Evento(t, tipo, f"{detalle} · {r.get('Owner', '?')} (PID {r.get('PID')})",
                         f"offset {r.get('Offset', '')}", r.get("Created"))
    else:
        raise ErrorFuente("CSV de Volatility no reconocido: se esperan columnas CreateTime (pslist/pstree) "
                          "o Created + ForeignAddr (netscan)")


# ---------------------------------------------------------------- CSV genérico

def leer_csv(f):
    tz = zona(f.opciones.get("tz"))
    col_fecha = f.opciones.get("fecha", "fecha")
    cols_detalle = (f.opciones.get("detalle") or "detalle").split("+")
    formato = f.opciones.get("formato")
    with open(f.ruta, encoding="utf-8-sig", newline="") as fh:
        lector = csv.DictReader(fh, delimiter=f.opciones.get("separador", ","))
        faltan = [c for c in [col_fecha, *cols_detalle] if c not in (lector.fieldnames or [])]
        if faltan:
            raise ErrorFuente(f"faltan columnas {faltan}; el CSV tiene {lector.fieldnames}")
        for n, r in enumerate(lector, 2):
            texto = (r[col_fecha] or "").strip()
            if not texto:
                continue
            try:
                dt = datetime.strptime(texto, formato) if formato else datetime.fromisoformat(texto)
            except ValueError:
                raise ErrorFuente(f"fila {n}: no se pudo leer la fecha '{texto}'"
                                  + (f" con el formato {formato}" if formato else " (indicar formato=)")) from None
            tipo = f.opciones.get("tipo") or r.get("tipo") or "Registro"
            detalle = " · ".join(r[c].strip() for c in cols_detalle if r.get(c))
            ref = r.get(f.opciones.get("referencia", "referencia")) or f"fila {n}"
            yield Evento(con_zona(dt, tz), tipo, detalle, ref, texto)


LECTORES = {"whatsapp": leer_whatsapp, "fotos": leer_fotos, "bodyfile": leer_bodyfile,
            "authlog": leer_authlog, "volatility": leer_volatility, "csv": leer_csv}


# ---------------------------------------------------------------- armado

def parsear_fuente(texto):
    tipo, sep, resto = texto.partition(":")
    if not sep or tipo not in LECTORES:
        raise ErrorFuente(f"fuente inválida '{texto}': usar TIPO:RUTA con TIPO en {', '.join(LECTORES)}")
    partes = resto.split(",")
    ruta, opciones = partes[0], {}
    for p in partes[1:]:
        clave, igual, valor = p.partition("=")
        if not igual:
            raise ErrorFuente(f"opción inválida '{p}' en {texto} (se espera clave=valor)")
        opciones[clave.strip()] = valor
    ruta = Path(ruta)
    if not ruta.exists():
        raise ErrorFuente(f"no existe {ruta}")
    return Fuente(tipo, ruta, opciones, opciones.get("nombre") or f"{tipo}:{ruta.name}")


def procesar(fuentes, adquisicion=None):
    """Lee todas las fuentes, aplica el desfase de cada una, ordena y marca fechas imposibles."""
    limite = adquisicion or datetime.now(UTC)
    eventos = []
    for orden, f in enumerate(fuentes):
        f.hash_antes = huella(f.ruta)
        corr = desfase(f.opciones.get("desfase"))
        if corr:
            s = abs(int(corr.total_seconds()))
            f.notas.append(f"reloj del equipo {'adelantado' if corr > timedelta(0) else 'atrasado'} {s} s: "
                           f"se {'restaron' if corr > timedelta(0) else 'sumaron'} {s} s a sus horas")
        for e in LECTORES[f.tipo](f):
            e.fuente = f.nombre
            if corr and e.reloj_propio:
                e.utc -= corr
                e.marcas.append("DESFASE CORREGIDO")
            if e.utc < MINIMO_RAZONABLE or e.utc > limite:
                e.marcas.append("FECHA IMPOSIBLE")
            eventos.append((e.utc, orden, len(eventos), e))
            f.eventos += 1
        f.hash_despues = huella(f.ruta)
    eventos.sort(key=lambda x: x[:3])
    return [e for *_, e in eventos]


# ---------------------------------------------------------------- salida

def celda_segura(valor):
    """Evita la inyección de fórmulas al abrir el CSV en Excel: el texto viene de la evidencia
    (por ejemplo, un mensaje de WhatsApp que empiece con '=HYPERLINK(...)')."""
    valor = str(valor)
    return "'" + valor if valor[:1] in ("=", "+", "-", "@", "\t", "\r") else valor


def escribir_csv(eventos, ruta, tz):
    with open(ruta, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["fecha_utc", "fecha_local", "fuente", "tipo", "detalle", "referencia", "marcas", "valor_original"])
        for e in eventos:
            w.writerow([e.utc.strftime("%Y-%m-%d %H:%M:%S"), e.utc.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %z"),
                        celda_segura(e.fuente), celda_segura(e.tipo), celda_segura(e.detalle),
                        celda_segura(e.referencia), " | ".join(e.marcas), celda_segura(e.original)])


COLORES = {"DISCREPANCIA": "#b45309", "FECHA IMPOSIBLE": "#b91c1c", "BORRADO": "#7c3aed",
           "FUERZA BRUTA": "#b91c1c", "DESFASE CORREGIDO": "#0369a1", "ZONA SUPUESTA": "#6b7280",
           "SIN EXIF": "#6b7280"}


def escribir_html(eventos, fuentes, ruta, tz, nombre_zona, titulo):
    e_ = html.escape
    p = [f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e_(titulo)}</title><style>
body{{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#111;background:#fff}}
h1{{font-size:20px}} h2{{font-size:16px;margin-top:28px}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #e5e7eb;padding:5px 8px;text-align:left;vertical-align:top}}
th{{background:#f3f4f6}} .dia td{{background:#111827;color:#fff;font-weight:600}}
.h{{white-space:nowrap;font-variant-numeric:tabular-nums}} .m{{display:inline-block;color:#fff;border-radius:4px;padding:0 5px;margin:1px 2px;font-size:11px}}
.f{{color:#4b5563;font-size:12px}} code{{font-size:12px;word-break:break-all}} .t{{overflow-x:auto}} td{{overflow-wrap:anywhere}} .alerta{{background:#fef2f2;color:#991b1b;padding:8px;border-radius:6px}}
</style></head><body><h1>{e_(titulo)}</h1>
<p>{len(eventos)} eventos de {len(fuentes)} fuentes · horas en <b>{e_(nombre_zona)}</b> · generado {datetime.now(UTC):%Y-%m-%d %H:%M} UTC con linea_tiempo.py {VERSION}</p>
<h2>Fuentes</h2><div class="t"><table><tr><th>Fuente</th><th>Eventos</th><th>Integridad (SHA-256)</th><th>Notas</th></tr>"""]
    for f in fuentes:
        ok = f.hash_antes == f.hash_despues
        integ = f"<code>{e_(f.hash_antes)}</code>" + ("" if ok else '<div class="alerta">¡La fuente CAMBIÓ durante el análisis!</div>')
        notas = "<br>".join(e_(n) for n in f.notas) or "—"
        opciones = ", ".join(f"{k}={v}" for k, v in f.opciones.items() if k != "nombre")
        p.append(f"<tr><td><b>{e_(f.nombre)}</b><div class='f'>{e_(f.tipo)} · {e_(str(f.ruta))}"
                 f"{(' · ' + e_(opciones)) if opciones else ''}</div></td><td>{f.eventos}</td><td>{integ}</td><td>{notas}</td></tr>")
    p.append("</table></div><h2>Línea de tiempo</h2><div class=\"t\"><table><tr><th>Hora</th><th>Fuente</th><th>Tipo</th><th>Detalle</th></tr>")
    dia = None
    for ev in eventos:
        local = ev.utc.astimezone(tz)
        d = f"{DIAS[local.weekday()]} {local:%d/%m/%Y}"
        if d != dia:
            p.append(f'<tr class="dia"><td colspan="4">{e_(d)}</td></tr>')
            dia = d
        marcas = "".join(f'<span class="m" style="background:{COLORES.get(m, "#374151")}">{e_(m)}</span>' for m in ev.marcas)
        p.append(f'<tr><td class="h">{local:%H:%M:%S}<div class="f">{ev.utc:%H:%M:%S} UTC</div></td>'
                 f"<td>{e_(ev.fuente)}</td><td>{e_(ev.tipo)}<br>{marcas}</td>"
                 f'<td>{e_(ev.detalle)}<div class="f">{e_(ev.referencia)} · original: {e_(ev.original)}</div></td></tr>')
    p.append("</table></div></body></html>")
    Path(ruta).write_text("\n".join(p), encoding="utf-8")


def imprimir(eventos, fuentes, tz):
    for f in fuentes:
        estado = "OK" if f.hash_antes == f.hash_despues else "¡CAMBIÓ!"
        print(f"[{f.nombre}] {f.eventos} eventos · sha256 {f.hash_antes[:16]}… {estado}")
        for n in f.notas:
            print(f"    - {n}")
    dia = None
    for e in eventos:
        local = e.utc.astimezone(tz)
        d = f"{DIAS[local.weekday()]} {local:%d/%m/%Y}"
        if d != dia:
            print(f"\n=== {d} ===")
            dia = d
        marcas = f"  [{', '.join(e.marcas)}]" if e.marcas else ""
        print(f"{local:%H:%M:%S}  {e.tipo:<26} {e.detalle[:100]}{marcas}")


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fuente", action="append", required=True, metavar="TIPO:RUTA[,op=valor]")
    ap.add_argument("--zona", default="UTC", help="zona para mostrar las horas (default UTC)")
    ap.add_argument("--desde", help="mostrar desde (AAAA-MM-DD[ HH:MM], en --zona)")
    ap.add_argument("--hasta", help="mostrar hasta (AAAA-MM-DD[ HH:MM], en --zona)")
    ap.add_argument("--adquisicion", help="fecha de la adquisición (AAAA-MM-DD HH:MM, en --zona): "
                                          "lo posterior se marca FECHA IMPOSIBLE. Default: ahora")
    ap.add_argument("--titulo", default="Línea de tiempo forense")
    ap.add_argument("-o", "--salida", type=Path, default=Path("salida_linea_tiempo"))
    ap.add_argument("-q", "--silencioso", action="store_true", help="no imprimir la línea de tiempo")
    a = ap.parse_args(argv)
    try:
        tz = zona(a.zona)
        fuentes = [parsear_fuente(x) for x in a.fuente]
        adq = con_zona(datetime.fromisoformat(a.adquisicion), tz) if a.adquisicion else None
        eventos = procesar(fuentes, adq)
    except (ErrorFuente, sqlite3.Error, OSError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    if a.desde:
        eventos = [e for e in eventos if e.utc >= con_zona(datetime.fromisoformat(a.desde), tz)]
    if a.hasta:
        eventos = [e for e in eventos if e.utc <= con_zona(datetime.fromisoformat(a.hasta), tz)]
    a.salida.mkdir(parents=True, exist_ok=True)
    escribir_csv(eventos, a.salida / "linea_tiempo.csv", tz)
    escribir_html(eventos, fuentes, a.salida / "linea_tiempo.html", tz, a.zona, a.titulo)
    if not a.silencioso:
        imprimir(eventos, fuentes, tz)
    marcados = sum(1 for e in eventos if e.marcas and set(e.marcas) - {"DESFASE CORREGIDO", "ZONA SUPUESTA"})
    print(f"\n{len(eventos)} eventos ({marcados} con marcas para revisar) -> {a.salida / 'linea_tiempo.html'}")
    cambiadas = [f.nombre for f in fuentes if f.hash_antes != f.hash_despues]
    if cambiadas:
        print(f"ATENCIÓN: estas fuentes cambiaron durante el análisis: {', '.join(cambiadas)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
