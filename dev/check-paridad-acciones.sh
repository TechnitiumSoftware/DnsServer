#!/usr/bin/env bash
# Side-by-side comparison by ACTION, not by bytes of the page.
#
# The project's governing constraint is "design only, zero functionality", and
# that enables the check that actually counts: run the same action on both
# instances and verify the RESULTING SERVER STATE is the same. If the body the
# new console sends differs by one parameter, the record left behind differs and
# it shows up here.
#
# The bodies are the ones upstream builds, copied from its JS. The new console
# sends the same ones: that is what is being verified.
#
# Usage:  ./check-paridad-acciones.sh
set -uo pipefail

DEV=http://127.0.0.1:5380
REF=http://127.0.0.1:5381
USERNAME=admin
PASSWORD=technitium-ui-dev
ZONE=paridad.test

failures=0

token() {
  curl -s "$1/api/user/login?user=$USERNAME&pass=$PASSWORD&includeInfo=false" |
    python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])'
}

TD=$(token "$DEV")
TR=$(token "$REF")

# Leaves the zone identical on both before each comparison block.
reset_zone() {
  for par in "$DEV $TD" "$REF $TR"; do
    set -- $par
    curl -s "$1/api/zones/delete?token=$2&zone=$ZONE" >/dev/null
    curl -s "$1/api/zones/create?token=$2&zone=$ZONE&type=Primary" >/dev/null
  done
}

# What is compared: the zone's records, minus whatever changes with the
# environment.
#
# Three things are normalised, all three for the same reason: they are not parity.
#   · `lastModified` and the SOA serial change with the clock.
#   · The SERVER NAME is embedded in the NS and the SOA of every zone, and the
#     two containers deliberately have a different `DNS_SERVER_DOMAIN`
#     (dev.technitium-ui.test / ref.technitium-ui.test). Without substituting it,
#     all fourteen comparisons come out different over the hostname and not over
#     the action.
fingerprint() {
  curl -s "$1/api/zones/records/get?token=$2&domain=$ZONE&zone=$ZONE&listZone=true" |
    python3 -c '
import sys, json, re
d = json.load(sys.stdin)["response"]
out = []
for r in sorted(d["records"], key=lambda x: (x["type"], x["name"])):
    r.pop("lastModified", None)
    if r["type"] == "SOA":
        r["rData"].pop("serial", None)
    out.append(r)
text = json.dumps(out, sort_keys=True)
print(re.sub(r"(dev|ref)\.technitium-ui\.test", "THIS-SERVER", text))'
}

# compare <name> <body-or-query> [method]
compare() {
  local name=$1 path=$2 body=${3:-} method=${4:-GET}

  for par in "$DEV $TD" "$REF $TR"; do
    set -- $par
    if [ "$method" = POST ]; then
      curl -s -X POST "$1/api/$path?token=$2&node=" --data "$body" >/dev/null
    else
      curl -s "$1/api/$path?token=$2&$body" >/dev/null
    fi
  done

  local d r
  d=$(fingerprint "$DEV" "$TD")
  r=$(fingerprint "$REF" "$TR")

  if [ "$d" = "$r" ]; then
    echo "  OK        $name"
  else
    echo "  DIFFERENT $name"
    diff <(echo "$r" | python3 -m json.tool) <(echo "$d" | python3 -m json.tool) | head -20
    failures=$((failures + 1))
  fi
}

echo "== record creates =="
reset_zone
compare "A with PTR" "zones/records/add" \
  "zone=$ZONE&domain=www.$ZONE&type=A&ttl=3600&overwrite=false&comments=&expiryTtl=&ipAddress=10.0.0.1&ptr=false&createPtrZone=false&updateSvcbHints=false" POST
compare "MX" "zones/records/add" \
  "zone=$ZONE&domain=$ZONE&type=MX&ttl=3600&overwrite=false&comments=&expiryTtl=&preference=10&exchange=mail.$ZONE" POST
compare "split TXT" "zones/records/add" \
  "zone=$ZONE&domain=$ZONE&type=TXT&ttl=3600&overwrite=false&comments=nota&expiryTtl=&text=v=spf1 -all&splitText=true" POST
compare "SRV" "zones/records/add" \
  "zone=$ZONE&domain=_s._tcp.$ZONE&type=SRV&ttl=3600&overwrite=false&comments=&expiryTtl=&priority=1&weight=2&port=443&target=www.$ZONE" POST
compare "CAA with default values" "zones/records/add" \
  "zone=$ZONE&domain=$ZONE&type=CAA&ttl=3600&overwrite=false&comments=&expiryTtl=&flags=0&tag=issue&value=letsencrypt.org" POST
compare "SVCB with params and automatic hint" "zones/records/add" \
  "zone=$ZONE&domain=svc.$ZONE&type=SVCB&ttl=3600&overwrite=false&comments=&expiryTtl=&svcPriority=1&svcTargetName=www.$ZONE&svcParams=alpn|h2&autoIpv4Hint=true&autoIpv6Hint=false" POST
compare "CNAME" "zones/records/add" \
  "zone=$ZONE&domain=alias.$ZONE&type=CNAME&ttl=3600&overwrite=false&comments=&expiryTtl=&cname=www.$ZONE" POST

echo "== edits =="
compare "edit the A: old and new" "zones/records/update" \
  "zone=$ZONE&type=A&domain=www.$ZONE&newDomain=www.$ZONE&ttl=1800&disable=false&comments=&expiryTtl=&ipAddress=10.0.0.1&newIpAddress=10.0.0.2&ptr=false&createPtrZone=false&updateSvcbHints=false" POST
compare "disable the MX by resending it whole" "zones/records/update" \
  "zone=$ZONE&type=MX&domain=$ZONE&ttl=3600&disable=true&comments=&expiryTtl=&preference=10&exchange=mail.$ZONE" POST
compare "edit the SOA" "zones/records/update" \
  "zone=$ZONE&type=SOA&domain=$ZONE&newDomain=$ZONE&ttl=900&disable=false&comments=&expiryTtl=&primaryNameServer=ns1.$ZONE&responsiblePerson=hostadmin@$ZONE&serial=42&refresh=900&retry=300&expire=604800&minimum=900&useSerialDateScheme=false" POST

echo "== deletes =="
compare "delete the CNAME (no parameters: falls to default)" "zones/records/delete" \
  "zone=$ZONE&domain=alias.$ZONE&type=CNAME" POST
compare "delete the SVCB by its flattened svcParams" "zones/records/delete" \
  "zone=$ZONE&domain=svc.$ZONE&type=SVCB&svcPriority=1&svcTargetName=www.$ZONE&svcParams=alpn|h2" POST
compare "delete the SRV by its four fields" "zones/records/delete" \
  "zone=$ZONE&domain=_s._tcp.$ZONE&type=SRV&priority=1&weight=2&port=443&target=www.$ZONE" POST

echo "== zone options =="
compare "options/set with the empty lists as \"false\"" "zones/options/set" \
  "zone=$ZONE&catalog=&overrideCatalogQueryAccess=false&overrideCatalogZoneTransfer=false&overrideCatalogNotify=false&primaryNameServerAddresses=&primaryZoneTransferProtocol=Tcp&primaryZoneTransferTsigKeyName=&validateZone=false&queryAccess=Allow&queryAccessNetworkACL=&zoneTransfer=AllowOnlyZoneNameServers&zoneTransferNetworkACL=false&zoneTransferTsigKeyNames=false&notify=ZoneNameServers&notifyNameServers=false&notifySecondaryCatalogsNameServers=false&update=Deny&updateNetworkACL=false&updateSecurityPolicies=false"

echo
if [ "$failures" -eq 0 ]; then
  echo "PARITY: every action leaves the same state"
  exit 0
fi
echo "PARITY: $failures actions diverge"
exit 2
