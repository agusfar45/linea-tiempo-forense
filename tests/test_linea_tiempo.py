"""Pruebas de linea_tiempo.py: python -m unittest -v (desde la raíz del repo)."""
import contextlib
import csv
import io
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
import linea_tiempo as lt  # noqa: E402

UTC = timezone.utc


def correr(*args):
    """Ejecuta main() capturando la salida. Devuelve (código, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        codigo = lt.main(list(args))
    return codigo, out.getvalue(), err.getvalue()


def leer_salida(carpeta):
    with open(Path(carpeta) / "linea_tiempo.csv", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def fuente(tipo, ruta, **op):
    return lt.Fuente(tipo, Path(ruta), op, op.get("nombre", tipo))


class TestZonasYDesfase(unittest.TestCase):
    def test_zonas(self):
        self.assertEqual(lt.zona("UTC"), UTC)
        self.assertEqual(lt.zona("-03:00").utcoffset(None), timedelta(hours=-3))
        self.assertEqual(lt.zona("+0530").utcoffset(None), timedelta(hours=5, minutes=30))
        salta = lt.zona("America/Argentina/Salta")
        self.assertEqual(datetime(2026, 11, 3, tzinfo=salta).utcoffset(), timedelta(hours=-3))
        with self.assertRaises(lt.ErrorFuente):
            lt.zona("Marte/Olympus")

    def test_desfase(self):
        self.assertEqual(lt.desfase("+95s"), timedelta(seconds=95))
        self.assertEqual(lt.desfase("-2m"), timedelta(seconds=-120))
        self.assertEqual(lt.desfase("+1h30m"), timedelta(seconds=5400))
        self.assertEqual(lt.desfase("95"), timedelta(seconds=95))
        self.assertEqual(lt.desfase(None), timedelta(0))
        with self.assertRaises(lt.ErrorFuente):
            lt.desfase("un ratito")


class TestDemo(unittest.TestCase):
    """El caso de demostración completo, con las 5 fuentes."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.ev = Path(cls.tmp.name) / "evidencia"
        subprocess.run([sys.executable, str(RAIZ / "generar_demo.py"), str(cls.ev)], check=True, capture_output=True)
        cls.hashes_antes = {p: lt.sha256_archivo(p) for p in cls.ev.rglob("*") if p.is_file()}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def correr_demo(self, desfase="-180s"):
        sal = Path(self.tmp.name) / f"salida{desfase}"
        e = self.ev
        codigo, out, err = correr(
            "--zona", "America/Argentina/Salta", "--adquisicion", "2026-11-07 17:00", "-o", str(sal), "-q",
            "--fuente", f"whatsapp:{e / 'msgstore.db'},wa={e / 'wa.db'},nombre=WhatsApp",
            "--fuente", f"fotos:{e / 'DCIM'},tz=America/Argentina/Salta,desfase={desfase},nombre=Fotos",
            "--fuente", f"bodyfile:{e / 'fls.body'},desfase={desfase},nombre=FS",
            "--fuente", f"csv:{e / 'banco.csv'},separador=;,fecha=Fecha,formato=%d/%m/%Y %H:%M:%S,tz=-03:00,"
                        "detalle=Concepto+Importe,tipo=Banco,nombre=Banco",
            "--fuente", f"csv:{e / 'acta.csv'},tz=America/Argentina/Salta,nombre=Expediente")
        self.assertEqual(codigo, 0, err)
        return leer_salida(sal), sal

    def indice(self, filas, texto):
        return next(i for i, f in enumerate(filas) if texto in f["detalle"])

    def test_orden_con_desfase_corregido(self):
        filas, _ = self.correr_demo()
        cbu = self.indice(filas, "CBU 0000003100099999999999 a nombre")
        transferencia = self.indice(filas, "Transferencia a CBU")
        captura = self.indice(filas, "Screenshot_")
        self.assertLess(cbu, transferencia)
        self.assertLess(transferencia, captura, "la captura del comprobante tiene que quedar DESPUÉS de la transferencia")
        self.assertEqual(filas[captura]["fecha_local"], "2026-11-03 10:15:31 -0300")

    def test_sin_corregir_el_orden_es_imposible(self):
        filas, _ = self.correr_demo(desfase="0")
        self.assertLess(self.indice(filas, "Screenshot_"), self.indice(filas, "Transferencia a CBU"))

    def test_foto_recibida_discrepancia_sin_desfase(self):
        filas, _ = self.correr_demo()
        f = filas[self.indice(filas, "IMG-20261102-WA0007.jpg ·")]
        self.assertIn("DISCREPANCIA", f["marcas"])
        self.assertNotIn("DESFASE", f["marcas"], "el EXIF lo escribió otra cámara: no se corrige con el reloj del teléfono")
        self.assertEqual(f["fecha_utc"], "2023-05-14 13:20:11")       # 15:20:11 +02:00
        self.assertIn("Canon EOS 250D", f["detalle"])
        self.assertIn("GPS 40.4168, -3.7038", f["detalle"])

    def test_exif_sin_zona_se_marca(self):
        filas, _ = self.correr_demo()
        f = filas[self.indice(filas, "IMG_20261106")]
        self.assertIn("ZONA SUPUESTA", f["marcas"])
        self.assertIn("GPS -24.7859, -65.4117", f["detalle"])

    def test_bodyfile_borrado_y_macb(self):
        filas, _ = self.correr_demo()
        pdf = [f for f in filas if "comprobante_650000.pdf" in f["detalle"]]
        self.assertEqual([f["tipo"] for f in pdf], ["Archivo m..b", "Archivo .a..", "Archivo ..c."])
        self.assertTrue(all("BORRADO" in f["marcas"] for f in pdf))

    def test_evidencia_no_se_modifica(self):
        self.correr_demo()
        despues = {p: lt.sha256_archivo(p) for p in self.ev.rglob("*") if p.is_file()}
        self.assertEqual(self.hashes_antes, despues)

    def test_informe_html(self):
        _, sal = self.correr_demo()
        texto = (sal / "linea_tiempo.html").read_text(encoding="utf-8")
        self.assertIn("reloj del equipo atrasado 180 s", texto)
        self.assertIn("DISCREPANCIA", texto)
        self.assertNotIn("CAMBIÓ durante", texto)


class TestWhatsApp(unittest.TestCase):
    def test_lee_mensajes_que_solo_estan_en_el_wal(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "msgstore.db"
            con = sqlite3.connect(db)
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA wal_autocheckpoint=0")
            con.executescript("""
                CREATE TABLE jid (_id INTEGER PRIMARY KEY, raw_string TEXT);
                CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER);
                CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER,
                                      timestamp INTEGER, message_type INTEGER, text_data TEXT);
                INSERT INTO jid VALUES (1, '5490000000000@s.whatsapp.net');
                INSERT INTO chat VALUES (1, 1);
                INSERT INTO message VALUES (1, 1, 0, 1793700000000, 0, 'mensaje reciente, todavía en el WAL');
            """)
            con.commit()
            try:
                self.assertGreater(Path(str(db) + "-wal").stat().st_size, 0)
                hash_antes = lt.sha256_archivo(db)
                f = fuente("whatsapp", db)
                ev = list(lt.leer_whatsapp(f))
                self.assertEqual(len(ev), 1)
                self.assertIn("todavía en el WAL", ev[0].detalle)
                self.assertEqual(ev[0].utc, datetime.fromtimestamp(1793700000, UTC))
                self.assertTrue(any("-wal" in n for n in f.notas))
                self.assertEqual(hash_antes, lt.sha256_archivo(db))
            finally:
                con.close()

    def test_esquema_viejo(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "msgstore.db"
            with sqlite3.connect(db) as con:
                con.execute("CREATE TABLE messages (_id INTEGER PRIMARY KEY, key_remote_jid TEXT, key_from_me INTEGER,"
                            " timestamp INTEGER, media_wa_type INTEGER, data TEXT)")
                con.execute("INSERT INTO messages VALUES (1, '5491111111111@s.whatsapp.net', 1, 1500000000000, 0, 'hola')")
            con.close()
            ev = list(lt.leer_whatsapp(fuente("whatsapp", db)))
            self.assertEqual(ev[0].tipo, "WhatsApp enviado")
            self.assertIn("5491111111111: hola", ev[0].detalle)

    def test_base_que_no_es_de_whatsapp(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "otra.db"
            with sqlite3.connect(db) as con:
                con.execute("CREATE TABLE t (x)")
            con.close()
            with self.assertRaises(lt.ErrorFuente):
                list(lt.leer_whatsapp(fuente("whatsapp", db)))


class TestAuthLog(unittest.TestCase):
    def escribir(self, tmp, texto):
        p = Path(tmp) / "auth.log"
        p.write_text(texto, encoding="utf-8")
        return p

    def test_formato_clasico(self):
        lineas = [f"Dec 31 23:58:{i:02d} srv sshd[100]: Failed password for invalid user u{i} from 203.0.113.9 port 4{i} ssh2"
                  for i in range(12)]
        lineas += [
            "Dec 31 23:59:30 srv sshd[200]: Accepted password for backup from 203.0.113.9 port 5000 ssh2",
            "Jan  1 00:01:02 srv sudo:   backup : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd soporte2",
            "Jan  1 00:01:03 srv useradd[300]: new user: name=soporte2, UID=1002, GID=1002",
            "Jan  1 00:02:00 srv CRON[400]: pam_unix(cron:session): session opened for user root",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            f = fuente("authlog", self.escribir(tmp, "\n".join(lineas) + "\n"), anio="2025", tz="-03:00")
            ev = list(lt.leer_authlog(f))
        self.assertEqual([e.tipo for e in ev], ["SSH fallos", "SSH acceso", "sudo", "Cuentas"])
        self.assertIn("12 intentos fallidos desde 203.0.113.9", ev[0].detalle)
        self.assertIn("FUERZA BRUTA", ev[0].marcas)
        self.assertEqual(ev[0].utc, datetime(2026, 1, 1, 2, 58, 0, tzinfo=UTC))   # 31/12/2025 23:58 -03:00
        self.assertEqual(ev[2].utc.year, 2026, "el paso de diciembre a enero suma un año")
        self.assertIn("useradd soporte2", ev[2].detalle)

    def test_formato_iso_de_ubuntu_24(self):
        texto = "2026-03-10T14:22:05.123456-03:00 srv sshd[9]: Accepted publickey for admin from 192.0.2.4 port 1 ssh2\n"
        with tempfile.TemporaryDirectory() as tmp:
            f = fuente("authlog", self.escribir(tmp, texto))
            ev = list(lt.leer_authlog(f))
        self.assertEqual(ev[0].utc, datetime(2026, 3, 10, 17, 22, 5, 123456, tzinfo=UTC))
        self.assertFalse(f.notas, "el formato ISO trae el año: no hay que avisar nada")


class TestVolatility(unittest.TestCase):
    def test_pstree_y_netscan(self):
        with tempfile.TemporaryDirectory() as tmp:
            ps = Path(tmp) / "pstree.csv"
            ps.write_text(
                "TreeDepth,PID,PPID,ImageFileName,Offset(V),CreateTime,ExitTime,Cmd,Path\n"
                "2,4332,2452,w3wp.exe,0xabc,2024-09-10 05:44:45.000000 UTC,2024-09-10 06:10:48.000000 UTC,-,-\n"
                "3,900,4332,implante.exe,0xdef,2024-09-10 06:08:23.000000 UTC,N/A,"
                "\"C:\\\\Startup\\\\implante.exe\",-\n", encoding="utf-8")
            ns = Path(tmp) / "netscan.csv"
            ns.write_text(
                "TreeDepth,Offset,Proto,LocalAddr,LocalPort,ForeignAddr,ForeignPort,State,PID,Owner,Created\n"
                "0,0x1,TCPv4,10.0.2.15,49688,10.0.2.4,4443,CLOSED,4332,w3wp.exe,2024-09-10 06:01:00.000000 UTC\n"
                "0,0x2,TCPv4,0.0.0.0,445,0.0.0.0,0,LISTENING,4,System,2024-09-10 05:30:00.000000 UTC\n"
                "0,0x3,UDPv4,0.0.0.0,500,*,0,,780,svchost.exe,N/A\n", encoding="utf-8")
            pe = list(lt.leer_volatility(fuente("volatility", ps)))
            ne = list(lt.leer_volatility(fuente("volatility", ns)))
        self.assertEqual([e.tipo for e in pe], ["Proceso creado", "Proceso terminado", "Proceso creado"])
        self.assertIn("C:\\Startup\\implante.exe", pe[2].detalle)
        self.assertEqual(pe[0].utc, datetime(2024, 9, 10, 5, 44, 45, tzinfo=UTC))
        self.assertEqual([e.tipo for e in ne], ["Conexión", "Puerto en escucha"])
        self.assertIn("10.0.2.4:4443", ne[0].detalle)


class TestSeguridadYControles(unittest.TestCase):
    def test_csv_sin_inyeccion_de_formulas_y_html_escapado(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada = Path(tmp) / "eventos.csv"
            entrada.write_text('fecha,detalle\n2026-01-02 10:00:00,"=HYPERLINK(""http://x"",""clic"")"\n'
                               "2026-01-02 11:00:00,<script>alert(1)</script>\n", encoding="utf-8")
            codigo, _, err = correr("-q", "-o", tmp, "--fuente", f"csv:{entrada}")
            self.assertEqual(codigo, 0, err)
            filas = leer_salida(tmp)
            self.assertTrue(filas[0]["detalle"].startswith("'="))
            html_ = (Path(tmp) / "linea_tiempo.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>alert", html_)
            self.assertIn("&lt;script&gt;", html_)

    def test_fechas_imposibles(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada = Path(tmp) / "eventos.csv"
            entrada.write_text("fecha,detalle\n1980-01-01 00:00:00,reloj reseteado\n"
                               "2026-06-01 12:00:00,normal\n2026-12-25 00:00:00,posterior al secuestro\n", encoding="utf-8")
            codigo, _, _ = correr("-q", "-o", tmp, "--adquisicion", "2026-11-07 17:00", "--fuente", f"csv:{entrada}")
            marcas = [f["marcas"] for f in leer_salida(tmp)]
        self.assertEqual(codigo, 0)
        self.assertEqual(marcas, ["FECHA IMPOSIBLE", "", "FECHA IMPOSIBLE"])

    def test_nombre_de_pixel_esta_en_utc(self):
        dt, con_hora = lt.fecha_de_nombre("PXL_20261103_131531123.jpg", lt.zona("-03:00"))
        self.assertTrue(con_hora)
        self.assertEqual(dt, datetime(2026, 11, 3, 13, 15, 31, tzinfo=UTC))
        dt, _ = lt.fecha_de_nombre("IMG_20261103_101531.jpg", lt.zona("-03:00"))
        self.assertEqual(dt, datetime(2026, 11, 3, 13, 15, 31, tzinfo=UTC))

    def test_fuente_modificada_durante_el_analisis(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada = Path(tmp) / "eventos.csv"
            entrada.write_text("fecha,detalle\n2026-01-02 10:00:00,a\n", encoding="utf-8")
            original = lt.LECTORES["csv"]

            def lector_que_modifica(f):
                yield from original(f)
                with open(f.ruta, "a", encoding="utf-8") as fh:
                    fh.write("2026-01-02 11:00:00,agregado\n")
            lt.LECTORES["csv"] = lector_que_modifica
            try:
                codigo, _, err = correr("-q", "-o", tmp, "--fuente", f"csv:{entrada}")
            finally:
                lt.LECTORES["csv"] = original
            self.assertEqual(codigo, 1)
            self.assertIn("cambiaron durante el análisis", err)
            self.assertIn("CAMBIÓ durante", (Path(tmp) / "linea_tiempo.html").read_text(encoding="utf-8"))

    def test_errores_claros(self):
        with tempfile.TemporaryDirectory() as tmp:
            entrada = Path(tmp) / "eventos.csv"
            entrada.write_text("Fecha,Concepto\n03/11/2026 10:14,x\n", encoding="utf-8")
            codigo, _, err = correr("-q", "-o", tmp, "--fuente", f"csv:{entrada},fecha=Fecha,detalle=Concepto")
            self.assertEqual(codigo, 2)
            self.assertIn("indicar formato=", err)
            codigo, _, err = correr("-q", "-o", tmp, "--fuente", f"pdf:{entrada}")
            self.assertEqual(codigo, 2)
            codigo, _, err = correr("-q", "-o", tmp, "--fuente", "csv:no_existe.csv")
            self.assertIn("no existe", err)


if __name__ == "__main__":
    unittest.main()
