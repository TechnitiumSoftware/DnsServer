#!/usr/bin/env bash
# Comparación lado a lado por ACCIÓN, no por bytes de la página.
#
# La restricción rectora del proyecto es «solo diseño, cero funcionalidad», y
# eso habilita la verificación que de verdad vale: ejecutar la misma acción en
# las dos instancias y comprobar que el ESTADO RESULTANTE del servidor es el
# mismo. Si el cuerpo que manda la consola nueva difiere en un parámetro, el
# registro que queda difiere y aquí sale.
#
# Los cuerpos son los que arma upstream, copiados de su JS. La consola nueva
# manda los mismos: eso es lo que se está comprobando.
#
# Uso:  ./check-paridad-acciones.sh
set -uo pipefail

DEV=http://127.0.0.1:5380
REF=http://127.0.0.1:5381
USUARIO=admin
CLAVE=technitium-ui-dev
ZONA=paridad.test

fallos=0

token() {
  curl -s "$1/api/user/login?user=$USUARIO&pass=$CLAVE&includeInfo=false" |
    python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])'
}

TD=$(token "$DEV")
TR=$(token "$REF")

# Deja la zona igual en las dos antes de cada bloque de comparación.
resetear() {
  for par in "$DEV $TD" "$REF $TR"; do
    set -- $par
    curl -s "$1/api/zones/delete?token=$2&zone=$ZONA" >/dev/null
    curl -s "$1/api/zones/create?token=$2&zone=$ZONA&type=Primary" >/dev/null
  done
}

# Lo que se compara: los registros de la zona, sin lo que cambia por entorno.
#
# Se normalizan tres cosas, y las tres por la misma razón: no son paridad.
#   · `lastModified` y el serial del SOA cambian con el reloj.
#   · El NOMBRE DEL SERVIDOR está metido en el NS y en el SOA de cada zona, y
#     los dos contenedores tienen `DNS_SERVER_DOMAIN` distinto a propósito
#     (dev.technitium-ui.test / ref.technitium-ui.test). Sin sustituirlo, las
#     catorce comparaciones salen distintas por el hostname y no por la acción.
huella() {
  curl -s "$1/api/zones/records/get?token=$2&domain=$ZONA&zone=$ZONA&listZone=true" |
    python3 -c '
import sys, json, re
d = json.load(sys.stdin)["response"]
salida = []
for r in sorted(d["records"], key=lambda x: (x["type"], x["name"])):
    r.pop("lastModified", None)
    if r["type"] == "SOA":
        r["rData"].pop("serial", None)
    salida.append(r)
texto = json.dumps(salida, sort_keys=True)
print(re.sub(r"(dev|ref)\.technitium-ui\.test", "ESTE-SERVIDOR", texto))'
}

# comparar <nombre> <cuerpo-o-query> [metodo]
comparar() {
  local nombre=$1 ruta=$2 cuerpo=${3:-} metodo=${4:-GET}

  for par in "$DEV $TD" "$REF $TR"; do
    set -- $par
    if [ "$metodo" = POST ]; then
      curl -s -X POST "$1/api/$ruta?token=$2&node=" --data "$cuerpo" >/dev/null
    else
      curl -s "$1/api/$ruta?token=$2&$cuerpo" >/dev/null
    fi
  done

  local d r
  d=$(huella "$DEV" "$TD")
  r=$(huella "$REF" "$TR")

  if [ "$d" = "$r" ]; then
    echo "  OK       $nombre"
  else
    echo "  DISTINTO $nombre"
    diff <(echo "$r" | python3 -m json.tool) <(echo "$d" | python3 -m json.tool) | head -20
    fallos=$((fallos + 1))
  fi
}

echo "== altas de registro =="
resetear
comparar "A con PTR" "zones/records/add" \
  "zone=$ZONA&domain=www.$ZONA&type=A&ttl=3600&overwrite=false&comments=&expiryTtl=&ipAddress=10.0.0.1&ptr=false&createPtrZone=false&updateSvcbHints=false" POST
comparar "MX" "zones/records/add" \
  "zone=$ZONA&domain=$ZONA&type=MX&ttl=3600&overwrite=false&comments=&expiryTtl=&preference=10&exchange=mail.$ZONA" POST
comparar "TXT partido" "zones/records/add" \
  "zone=$ZONA&domain=$ZONA&type=TXT&ttl=3600&overwrite=false&comments=nota&expiryTtl=&text=v=spf1 -all&splitText=true" POST
comparar "SRV" "zones/records/add" \
  "zone=$ZONA&domain=_s._tcp.$ZONA&type=SRV&ttl=3600&overwrite=false&comments=&expiryTtl=&priority=1&weight=2&port=443&target=www.$ZONA" POST
comparar "CAA con valores por defecto" "zones/records/add" \
  "zone=$ZONA&domain=$ZONA&type=CAA&ttl=3600&overwrite=false&comments=&expiryTtl=&flags=0&tag=issue&value=letsencrypt.org" POST
comparar "SVCB con params y pista automática" "zones/records/add" \
  "zone=$ZONA&domain=svc.$ZONA&type=SVCB&ttl=3600&overwrite=false&comments=&expiryTtl=&svcPriority=1&svcTargetName=www.$ZONA&svcParams=alpn|h2&autoIpv4Hint=true&autoIpv6Hint=false" POST
comparar "CNAME" "zones/records/add" \
  "zone=$ZONA&domain=alias.$ZONA&type=CNAME&ttl=3600&overwrite=false&comments=&expiryTtl=&cname=www.$ZONA" POST

echo "== ediciones =="
comparar "editar el A: viejo y nuevo" "zones/records/update" \
  "zone=$ZONA&type=A&domain=www.$ZONA&newDomain=www.$ZONA&ttl=1800&disable=false&comments=&expiryTtl=&ipAddress=10.0.0.1&newIpAddress=10.0.0.2&ptr=false&createPtrZone=false&updateSvcbHints=false" POST
comparar "deshabilitar el MX reenviándolo entero" "zones/records/update" \
  "zone=$ZONA&type=MX&domain=$ZONA&ttl=3600&disable=true&comments=&expiryTtl=&preference=10&exchange=mail.$ZONA" POST
comparar "editar el SOA" "zones/records/update" \
  "zone=$ZONA&type=SOA&domain=$ZONA&newDomain=$ZONA&ttl=900&disable=false&comments=&expiryTtl=&primaryNameServer=ns1.$ZONA&responsiblePerson=hostadmin@$ZONA&serial=42&refresh=900&retry=300&expire=604800&minimum=900&useSerialDateScheme=false" POST

echo "== borrados =="
comparar "borrar el CNAME (sin parámetros: cae al default)" "zones/records/delete" \
  "zone=$ZONA&domain=alias.$ZONA&type=CNAME" POST
comparar "borrar el SVCB por sus svcParams aplanados" "zones/records/delete" \
  "zone=$ZONA&domain=svc.$ZONA&type=SVCB&svcPriority=1&svcTargetName=www.$ZONA&svcParams=alpn|h2" POST
comparar "borrar el SRV por sus cuatro campos" "zones/records/delete" \
  "zone=$ZONA&domain=_s._tcp.$ZONA&type=SRV&priority=1&weight=2&port=443&target=www.$ZONA" POST

echo "== opciones de zona =="
comparar "options/set con las listas vacías como «false»" "zones/options/set" \
  "zone=$ZONA&catalog=&overrideCatalogQueryAccess=false&overrideCatalogZoneTransfer=false&overrideCatalogNotify=false&primaryNameServerAddresses=&primaryZoneTransferProtocol=Tcp&primaryZoneTransferTsigKeyName=&validateZone=false&queryAccess=Allow&queryAccessNetworkACL=&zoneTransfer=AllowOnlyZoneNameServers&zoneTransferNetworkACL=false&zoneTransferTsigKeyNames=false&notify=ZoneNameServers&notifyNameServers=false&notifySecondaryCatalogsNameServers=false&update=Deny&updateNetworkACL=false&updateSecurityPolicies=false"

echo
if [ "$fallos" -eq 0 ]; then
  echo "PARIDAD: todas las acciones dejan el mismo estado"
  exit 0
fi
echo "PARIDAD: $fallos acciones divergen"
exit 2
