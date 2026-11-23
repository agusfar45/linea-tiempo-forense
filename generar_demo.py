#!/usr/bin/env python3
"""
generar_demo.py - Arma la evidencia FICTICIA del caso de demostración: estafa en la venta de una notebook.

Personas, números, CBU y fotos son inventados. El caso combina cinco fuentes con relojes distintos:
  - msgstore.db + wa.db   chat de WhatsApp de la víctima (timestamps UTC en ms)
  - DCIM/                 fotos y capturas del teléfono (hora local, sin zona en el EXIF)
  - fls.body              tiempos del sistema de archivos del teléfono (bodyfile de Sleuth Kit)
  - banco.csv             extracto del home banking (hora del servidor del banco, UTC-3)
  - acta.csv              eventos del expediente, cargados a mano

El reloj del teléfono estaba 3 minutos ATRASADO (desfase -180 s, medido con adb_triage.py al
secuestrarlo). Sin corregirlo, la captura del comprobante queda ANTES de la transferencia.

Uso: python generar_demo.py [carpeta]   (default: demo/evidencia)
"""
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image, ImageDraw
from PIL.TiffImagePlugin import IFDRational

ART = timezone(timedelta(hours=-3))
DESFASE_TELEFONO = timedelta(seconds=-180)   # el teléfono marcaba 3 min menos que la hora real
VENDEDOR = "5493875550142@s.whatsapp.net"


def real(texto):
    """Hora real (Argentina) -> datetime con zona."""
    return datetime.strptime(texto, "%d/%m/%Y %H:%M:%S").replace(tzinfo=ART)


def reloj_telefono(texto):
    """Lo que el teléfono anotó para un momento real dado (su reloj estaba atrasado)."""
    return real(texto) + DESFASE_TELEFONO


MENSAJES = [  # (hora real, from_me, texto o None si es una imagen)
    ("02/11/2026 18:40:10", 1, "Hola! Vi tu publicación de la notebook. ¿Sigue disponible?"),
    ("02/11/2026 18:42:31", 0, "Hola, sí. Está impecable, casi sin uso. Te mando fotos"),
    ("02/11/2026 18:43:05", 0, None),
    ("02/11/2026 18:49:52", 1, "Está linda. ¿Cuánto pedís?"),
    ("02/11/2026 18:51:14", 0, "$650.000. Si me transferís mañana temprano te la reservo, hay otro interesado"),
    ("02/11/2026 18:53:40", 1, "Dale, mañana te transfiero"),
    ("03/11/2026 10:12:40", 1, "Listo, transfiero ahora. Pasame el CBU"),
    ("03/11/2026 10:13:22", 0, "CBU 0000003100099999999999 a nombre de M. Gómez"),
    ("03/11/2026 10:16:02", 1, None),
    ("03/11/2026 10:18:47", 0, "Recibido 👍 mañana la despacho por correo"),
    ("04/11/2026 09:30:15", 1, "Hola, ¿me pasás el código de seguimiento?"),
    ("04/11/2026 20:02:51", 1, "??"),
    ("05/11/2026 11:15:03", 1, "Te estoy llamando y no atendés. Voy a hacer la denuncia"),
]


def crear_whatsapp(dir_):
    db = sqlite3.connect(dir_ / "msgstore.db")
    db.executescript("""
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER);
        CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT,
                              timestamp INTEGER, received_timestamp INTEGER, message_type INTEGER, text_data TEXT);
    """)
    db.execute("INSERT INTO jid VALUES (1, ?)", (VENDEDOR,))
    db.execute("INSERT INTO chat VALUES (1, 1)")
    for i, (hora, from_me, texto) in enumerate(MENSAJES, 1):
        ms = int(real(hora).timestamp() * 1000)
        db.execute("INSERT INTO message VALUES (?,?,?,?,?,?,?,?)",
                   (i, 1, from_me, f"3EB0{i:012X}", ms, ms + 900, 0 if texto else 1, texto))
    db.commit()
    db.close()
    wa = sqlite3.connect(dir_ / "wa.db")
    wa.execute("CREATE TABLE wa_contacts (jid TEXT, display_name TEXT)")
    wa.execute("INSERT INTO wa_contacts VALUES (?, ?)", (VENDEDOR, "Marcos notebook"))
    wa.commit()
    wa.close()


def rac(x):
    return IFDRational(round(x * 10000), 10000)


def foto(ruta, texto, color, exif_fecha=None, offset=None, marca=None, modelo=None, gps=None):
    im = Image.new("RGB", (480, 320), color)
    d = ImageDraw.Draw(im)
    d.rectangle((20, 20, 460, 300), outline="white", width=4)
    d.text((40, 140), texto, fill="white")
    exif = Image.Exif()
    if marca:
        exif[0x010F], exif[0x0110] = marca, modelo
    if exif_fecha:
        sub = exif.get_ifd(0x8769)
        sub[0x9003] = exif_fecha
        if offset:
            sub[0x9011] = offset
    if gps:
        lat, lon = gps
        g = exif.get_ifd(0x8825)
        for ref, valor, tags in (("NS", lat, (1, 2)), ("EW", lon, (3, 4))):
            v = abs(valor)
            g[tags[0]] = ref[0] if valor >= 0 else ref[1]
            g[tags[1]] = (rac(int(v)), rac(int(v * 60) % 60), rac((v * 3600) % 60))
    ruta.parent.mkdir(parents=True, exist_ok=True)
    im.save(ruta, "JPEG", quality=85, exif=exif)


def crear_fotos(dir_):
    dcim = dir_ / "DCIM"
    # 1) La foto que mandó el "vendedor": EXIF de mayo de 2023, cámara réflex, GPS en Madrid.
    #    Es una foto vieja sacada de internet, no la notebook que dice tener.
    foto(dcim / "WhatsApp Images" / "IMG-20261102-WA0007.jpg", "notebook (foto del vendedor)", (40, 60, 90),
         "2023:05:14 15:20:11", "+02:00", "Canon", "Canon EOS 250D", (40.4168, -3.7038))
    # 2) Captura del comprobante: sin EXIF, la hora sale del nombre (reloj del teléfono, atrasado)
    t = reloj_telefono("03/11/2026 10:15:31")
    foto(dcim / "Screenshots" / f"Screenshot_{t:%Y%m%d_%H%M%S}.jpg", "Comprobante de transferencia $650.000",
         (20, 110, 60))
    # 3) Foto de la víctima al buzón vacío: EXIF sin zona (como la mayoría de los Android) y GPS en Salta
    t = reloj_telefono("06/11/2026 09:41:07")
    foto(dcim / "Camera" / f"IMG_{t:%Y%m%d_%H%M%S}.jpg", "buzón vacío", (90, 70, 40),
         f"{t:%Y:%m:%d %H:%M:%S}", None, "samsung", "SM-A546E", (-24.7859, -65.4117))


def crear_bodyfile(dir_):
    def ep(texto):
        return int(reloj_telefono(texto).timestamp())
    filas = [
        # nombre, inodo, tamaño, atime, mtime, ctime, crtime (todo en hora del teléfono)
        ("/data/media/0/DCIM/WhatsApp Images/IMG-20261102-WA0007.jpg", 81234, 48211,
         ep("02/11/2026 18:43:09"), ep("02/11/2026 18:43:08"), ep("02/11/2026 18:43:08"), ep("02/11/2026 18:43:08")),
        ("/data/media/0/Download/comprobante_650000.pdf (deleted)", 81301, 120442,
         ep("03/11/2026 10:15:40"), ep("03/11/2026 10:15:12"), ep("05/11/2026 11:20:33"), ep("03/11/2026 10:15:12")),
        ("/data/media/0/DCIM/Screenshots/" + f"Screenshot_{reloj_telefono('03/11/2026 10:15:31'):%Y%m%d_%H%M%S}.jpg",
         81302, 30120, ep("03/11/2026 10:16:00"), ep("03/11/2026 10:15:31"), ep("03/11/2026 10:15:31"),
         ep("03/11/2026 10:15:31")),
    ]
    with open(dir_ / "fls.body", "w", encoding="utf-8", newline="\n") as f:
        for nombre, inodo, tam, a, m, c, b in filas:
            f.write(f"0|{nombre}|{inodo}|r/rrw-rw----|10225|1023|{tam}|{a}|{m}|{c}|{b}\n")


def crear_csvs(dir_):
    (dir_ / "banco.csv").write_text(
        "Fecha;Concepto;Importe;Saldo\n"
        "01/11/2026 09:02:11;Acreditación de haberes;+812.400,00;1.104.233,10\n"
        "03/11/2026 10:14:50;Transferencia a CBU 0000003100099999999999 (M. GOMEZ);-650.000,00;454.233,10\n"
        "05/11/2026 12:40:02;Reclamo 77812: desconocimiento de transferencia;0,00;454.233,10\n",
        encoding="utf-8", newline="\n")
    (dir_ / "acta.csv").write_text(
        "fecha,tipo,detalle,referencia\n"
        "2026-11-05 18:30:00,Expediente,Denuncia de la víctima en la Unidad Fiscal,Denuncia 4411/26\n"
        "2026-11-07 16:20:00,Expediente,Secuestro del teléfono; se pone en modo avión,Acta 123/26\n"
        "2026-11-07 16:35:00,Expediente,adb_triage.py: reloj del teléfono -180 s respecto de la PC,acta_extraccion.md\n",
        encoding="utf-8", newline="\n")


def main():
    dir_ = Path(sys.argv[1] if len(sys.argv) > 1 else "demo/evidencia")
    if dir_.exists() and any(dir_.iterdir()):
        sys.exit(f"{dir_} no está vacía: borrala o elegí otra carpeta")
    dir_.mkdir(parents=True, exist_ok=True)
    crear_whatsapp(dir_)
    crear_fotos(dir_)
    crear_bodyfile(dir_)
    crear_csvs(dir_)
    for p in sorted(dir_.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(dir_).as_posix():<55} {p.stat().st_size:>7} bytes")


if __name__ == "__main__":
    main()
