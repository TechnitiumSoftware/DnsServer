#!/usr/bin/env bash
# Empaqueta medir-pantalla.js como snippet de Playwright, para inyectarlo con
# browser_run_code_unsafe --filename sin tener que pegarlo en cada sesión. El
# servidor MCP sólo lee dentro del repo de ORBITLAB, así que la salida va ahí.
#
# El fichero se serializa como literal JSON, no como plantilla: `medir-pantalla.js`
# lleva sus propias plantillas con acento grave, y meterlas dentro de otra
# —String.raw incluida— produce un `SyntaxError` en cuanto se evalúa.
set -euo pipefail
cd "$(dirname "$0")"
DESTINO="${1:-../../../.playwright-mcp/inyectar-medicion.js}"
mkdir -p "$(dirname "$DESTINO")"

python3 - "$DESTINO" <<'PY'
import json, sys, pathlib

import re
# Los comentarios son la mitad del fichero y no sirven de nada dentro del
# navegador; fuera, que este payload viaja entero en cada inyección.
fuente = pathlib.Path('medir-pantalla.js').read_text(encoding='utf-8')
fuente = re.sub(r'/\*[\s\S]*?\*/', '', fuente)
fuente = re.sub(r'^\s*//.*$', '', fuente, flags=re.M)
fuente = re.sub(r'^[ \t]+', '', fuente, flags=re.M)
fuente = re.sub(r'\n\s*\n+', '\n', fuente)
expuestas = ['medir', 'medirEstado', 'recorrer', 'barridoEstados']
cuerpo = fuente + '\n' + ''.join(f'window.{n}={n};' for n in expuestas)

pathlib.Path(sys.argv[1]).write_text(
    'async (page) => {\n'
    f'  const boot = "(()=>{{" + {json.dumps(cuerpo)} + "}})()";\n'
    '  await page.addInitScript(boot);\n'
    '  await page.evaluate(boot);\n'
    '  return await page.evaluate(() => '
    f'({json.dumps(expuestas)}.map((n) => `${{n}}:${{typeof window[n]}}`)));\n'
    '}\n',
    encoding='utf-8',
)
PY
echo "$DESTINO"
