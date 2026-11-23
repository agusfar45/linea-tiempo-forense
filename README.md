# linea_tiempo.py: línea de tiempo forense con varias fuentes

[![Pruebas](https://github.com/agusfar45/linea-tiempo-forense/actions/workflows/pruebas.yml/badge.svg)](https://github.com/agusfar45/linea-tiempo-forense/actions/workflows/pruebas.yml)

Une en **una sola línea de tiempo** evidencias que guardan la hora de formas distintas:

- WhatsApp en UTC y milisegundos;
- fotos en hora local sin zona;
- el sistema de archivos en epoch;
- un banco en su propia hora;
- un log de Linux sin año.

Convierte todo a UTC, corrige el reloj del equipo si estaba mal y marca lo que no cierra. Genera un CSV y
un informe HTML con la integridad de cada fuente.

Nació del desafío 4 de mi [laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico):
"juntar los CSV de WhatsApp y de fotos en uno ordenado por fecha". La versión del laboratorio solo servía
para ese caso. Esta lee las fuentes originales y resuelve los problemas de hora que aparecen en casos reales.

## Fuentes

| Tipo | Lee | Hora en la fuente |
|---|---|---|
| `whatsapp` | `msgstore.db`, esquema moderno (`message`/`chat`/`jid`) o viejo (`messages`); nombres desde `wa.db` | UTC en ms |
| `fotos` | EXIF (`DateTimeOriginal`, `OffsetTimeOriginal`, marca/modelo, GPS) y la fecha del nombre (`IMG_`, `Screenshot_`, `PXL_`, `IMG-…-WA`) | local, casi nunca con zona |
| `bodyfile` | tiempos MACB de `fls -m` (Sleuth Kit), con los archivos borrados marcados | epoch UTC |
| `authlog` | `auth.log`: accesos SSH, fallos agrupados por IP, `sudo`, cambios de cuentas | local, **sin año** (o ISO en Ubuntu 24.04) |
| `volatility` | CSV de `vol -r csv` con `windows.pslist`/`pstree` (procesos) o `windows.netscan` (conexiones) | UTC |
| `csv` | cualquier CSV: extracto bancario, eventos del acta, exportaciones de otras herramientas | la que indiques |

```bash
python linea_tiempo.py --zona America/Argentina/Salta -o salida \
  --fuente whatsapp:msgstore.db,wa=wa.db \
  --fuente fotos:DCIM,tz=America/Argentina/Salta,desfase=-180s \
  --fuente bodyfile:fls.body,desfase=-180s \
  --fuente "csv:banco.csv,separador=;,fecha=Fecha,formato=%d/%m/%Y %H:%M:%S,tz=-03:00,detalle=Concepto+Importe"
```

Opciones de cada fuente: `tz=` (zona de las horas que vienen sin zona), `desfase=` (error del reloj del
equipo; `-180s` = 3 minutos atrasado, como lo mide [adb_triage.py](https://github.com/agusfar45/adb-triage-android))
y `nombre=`.

Opciones generales:
- `--zona`: zona en la que se muestran las horas;
- `--desde` / `--hasta`: recorta la ventana de tiempo;
- `--adquisicion`: lo posterior a esta fecha se marca como imposible.

## Caso demo: estafa en la venta de una notebook

[generar_demo.py](generar_demo.py) arma una evidencia **ficticia** con cinco fuentes, y
[demo/correr_demo.sh](demo/correr_demo.sh) la procesa. Resultado: [demo/salida/](demo/salida/), con el
[informe HTML](demo/salida/linea_tiempo.html), el [CSV](demo/salida/linea_tiempo.csv) y la
[salida de consola](demo/salida/consola.txt).

```
=== martes 03/11/2026 ===
10:12:40  WhatsApp enviado           → Marcos notebook (5493875550142): Listo, transfiero ahora. Pasame el CBU
10:13:22  WhatsApp recibido          ← Marcos notebook (5493875550142): CBU 0000003100099999999999 a nombre de M. Gómez
10:14:50  Banco                      Transferencia a CBU 0000003100099999999999 (M. GOMEZ) · -650.000,00
10:15:12  Archivo m..b               /data/media/0/Download/comprobante_650000.pdf (deleted)  [BORRADO, DESFASE CORREGIDO]
10:15:31  Imagen (fecha del nombre)  Screenshot_20261103_101231.jpg · sin EXIF · sin GPS  [SIN EXIF, DESFASE CORREGIDO]
10:16:02  WhatsApp enviado           → Marcos notebook (5493875550142): [adjunto, message_type=1]
10:18:47  WhatsApp recibido          ← Marcos notebook (5493875550142): Recibido 👍 mañana la despacho por correo
```

Lo que muestra la línea de tiempo:

1. **El reloj importa.** Cuando se secuestró el teléfono, `adb_triage.py` midió que estaba **3 minutos
   atrasado**. La captura del comprobante se llama `Screenshot_20261103_101231`. Sin corregir, quedaría a
   las 10:12:31, **antes de la transferencia y antes de que el vendedor pasara el CBU**, que es imposible.
   Con `desfase=-180s` queda a las 10:15:31, 41 segundos después de la transferencia del banco. Una prueba
   automática comprueba los dos órdenes.
2. **La foto de la notebook es vieja.** La imagen que mandó el vendedor llegó el 02/11/2026, según su
   nombre `IMG-…-WA0007`, pero su EXIF dice **14/05/2023, Canon EOS 250D, GPS en Madrid**. Es una foto
   reutilizada, no de la notebook que decía tener: queda marcada como `DISCREPANCIA`.
   A esa hora **no se le aplica el desfase** del teléfono, porque la escribió otra cámara.
3. **Un borrado.** El PDF del comprobante figura como borrado en el sistema de archivos. Su `ctime` es del
   05/11 a las 11:20, cinco minutos después del último mensaje a la víctima. Es un dato para preguntar, y la
   captura de pantalla sigue existiendo.
4. **Una foto sin zona.** La foto de la cámara del teléfono tiene EXIF sin `OffsetTimeOriginal`, como la
   mayoría de los Android. La zona se supone (`tz=`) y queda marcada `ZONA SUPUESTA`, para que el informe
   lo diga.

## Marcas

| Marca | Cuándo |
|---|---|
| `DISCREPANCIA` | EXIF y nombre del archivo difieren en más de 60 s, o la foto recibida es de otra fecha |
| `FECHA IMPOSIBLE` | anterior a 1995 (reloj reseteado) o posterior a la adquisición |
| `BORRADO` | entrada `(deleted)` del bodyfile |
| `FUERZA BRUTA` | 10 o más fallos SSH seguidos desde una IP |
| `DESFASE CORREGIDO` | se aplicó la corrección del reloj |
| `ZONA SUPUESTA` / `SIN EXIF` | la hora se interpretó con la zona indicada, o salió del nombre del archivo |

Cada evento conserva el **valor original**, tal como figura en la fuente, junto a la hora convertida. El
perito tiene que poder mostrar de dónde salió cada hora.

## Cuidados forenses

- **Las fuentes no se modifican.** Se hashean (SHA-256) antes y después de leerlas. Si algo cambió, el
  informe lo muestra en rojo y el programa termina con código 1. Hay una prueba que lo provoca a propósito.
- **WhatsApp se lee desde una copia, junto con su `-wal`.** Abrir el original con `immutable=1` parece más
  seguro, pero ignora el WAL y se pierden los mensajes más recientes. Una prueba arma una base con un mensaje
  que solo está en el WAL y comprueba que aparece.
- **Bodyfile, no la carpeta copiada.** Los tiempos del sistema de archivos salen de la imagen con `fls -m`.
  Recorrer una carpeta copiada daría las fechas de la copia, y leerla cambia los `atime`.
- **El CSV se puede abrir en Excel sin riesgo.** Un mensaje que empiece con `=HYPERLINK(…)` se escribe como
  texto, porque el contenido de la evidencia lo controla el sospechoso. En el HTML todo se escapa.

## Detalles que aprendí haciéndolo

- **`with sqlite3.connect(…)` no cierra la conexión**: solo hace `commit`. Lo descubrí porque en Windows la
  prueba no podía borrar `wa.db` al terminar, ya que seguía abierta. Ahora uso `contextlib.closing`.
- **El nombre `PXL_` de los Pixel está en UTC**, mientras que `IMG_` y `Screenshot_` están en hora local.
  Mezclarlos corre los eventos 3 horas.
- **El `auth.log` clásico no tiene año.** Si el log cruza de diciembre a enero, hay que sumarlo. Ubuntu 24.04
  ya usa fechas ISO con zona.
- **En Windows, `zoneinfo` necesita el paquete `tzdata`** para entender `America/Argentina/Salta`.
  Por eso se aceptan también zonas fijas como `-03:00`.

## Pruebas

20 pruebas (`python -m unittest -v`) que corren en GitHub Actions sobre Ubuntu y Windows, con Python 3.10 y
3.13. Cubren:
- zonas y desfases;
- el caso demo completo, con y sin corrección;
- el WAL de WhatsApp y el esquema viejo;
- `auth.log` en los dos formatos y con cambio de año;
- Volatility;
- inyección de fórmulas y escape HTML;
- fechas imposibles;
- una fuente modificada durante el análisis;
- mensajes de error.

El CI además regenera la demo y verifica que dé la misma línea de tiempo.

```bash
pip install -r requirements.txt   # Pillow (y tzdata en Windows)
python -m unittest -v
bash demo/correr_demo.sh
```

## Limitaciones

- No lee EVTX, el registro de Windows, ni el historial de navegadores: para eso están plaso/log2timeline. Se
  pueden sumar exportándolos a CSV.
- El `desfase` se aplica a toda la fuente, salvo a las fotos recibidas por WhatsApp. Si una fuente mezcla
  horas del equipo con horas de un servidor, hay que separarlas.
- Las fotos se identifican por la extensión: un JPEG renombrado a `.dat` no se lee.

---

Agustín Farfán · Ingeniería en Informática (UCASAL) ·
[laboratorio forense](https://github.com/agusfar45/laboratorio-perito-informatico) ·
[adb_triage](https://github.com/agusfar45/adb-triage-android) ·
[analizador de pcap](https://github.com/agusfar45/analizador-pcap-forense)
