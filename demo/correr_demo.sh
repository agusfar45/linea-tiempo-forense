#!/usr/bin/env bash
# Regenera la evidencia ficticia y la línea de tiempo del caso demo (desde la raíz del repo)
set -e
rm -rf demo/evidencia demo/salida
python generar_demo.py demo/evidencia
mkdir -p demo/salida
python linea_tiempo.py --zona America/Argentina/Salta --adquisicion "2026-11-07 17:00" \
  --titulo "Caso demo: estafa en la venta de una notebook" -o demo/salida \
  --fuente whatsapp:demo/evidencia/msgstore.db,wa=demo/evidencia/wa.db,nombre=WhatsApp \
  --fuente fotos:demo/evidencia/DCIM,tz=America/Argentina/Salta,desfase=-180s,nombre=Fotos \
  --fuente "bodyfile:demo/evidencia/fls.body,desfase=-180s,nombre=Sistema de archivos" \
  --fuente "csv:demo/evidencia/banco.csv,separador=;,fecha=Fecha,formato=%d/%m/%Y %H:%M:%S,tz=-03:00,detalle=Concepto+Importe,tipo=Banco,nombre=Home banking" \
  --fuente "csv:demo/evidencia/acta.csv,tz=America/Argentina/Salta,nombre=Expediente" | tee demo/salida/consola.txt
