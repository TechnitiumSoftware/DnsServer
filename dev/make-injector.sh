#!/usr/bin/env bash
# Packages measure-screen.js as a Playwright snippet, to inject it with
# browser_run_code_unsafe --filename instead of pasting it every session. The
# MCP server only reads inside the ORBITLAB repo, so the output goes there.
#
# The file is serialised as a JSON literal, not as a template: `measure-screen.js`
# carries its own backtick templates, and nesting them inside another one
# —String.raw included— produces a `SyntaxError` as soon as it is evaluated.
set -euo pipefail
cd "$(dirname "$0")"
TARGET="${1:-../../../.playwright-mcp/inyectar-medicion.js}"
mkdir -p "$(dirname "$TARGET")"

python3 - "$TARGET" <<'PY'
import json, sys, pathlib

import re
# The comments are half the file and are of no use inside the browser; out they
# go, because this payload travels whole on every injection.
source = pathlib.Path('measure-screen.js').read_text(encoding='utf-8')
source = re.sub(r'/\*[\s\S]*?\*/', '', source)
source = re.sub(r'^\s*//.*$', '', fuente, flags=re.M)
source = re.sub(r'^[ \t]+', '', fuente, flags=re.M)
source = re.sub(r'\n\s*\n+', '\n', source)
exposed = ['measure', 'measureState', 'walk', 'sweepStates']
body = source + '\n' + ''.join(f'window.{n}={n};' for n in exposed)

pathlib.Path(sys.argv[1]).write_text(
    'async (page) => {\n'
    f'  const boot = "(()=>{{" + {json.dumps(body)} + "}})()";\n'
    '  await page.addInitScript(boot);\n'
    '  await page.evaluate(boot);\n'
    '  return await page.evaluate(() => '
    f'({json.dumps(exposed)}.map((n) => `${{n}}:${{typeof window[n]}}`)));\n'
    '}\n',
    encoding='utf-8',
)
PY
echo "$TARGET"
