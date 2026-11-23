#!/usr/bin/env bash
# Integration test of the whole stack on a host with a TPM:
#   pqc-kms backend (KMIP + REST + administration API) <-> localhsm (TPM-protected Enterprise keystore)
# Run as root (the TPM device is accessible to root / group tss):  sudo bash itest-localhsm.sh /path/to/hsmctl
# It creates temporary objects (service itest-svc and super group itest-div, a TPM key pqckms-itest, keys named
# itest-*, a keystore under ./itest.tmp) and removes what it can at the end.
set -uo pipefail
cd "$(dirname "$0")"
HSMCTL="${1:?usage: itest-localhsm.sh /path/to/hsmctl}"
TPMNAME="pqckms-itest"
NODE="hsm-itest"
WORK="$(pwd)/itest.tmp"
CA="pki/ca.crt"
ADMIN="https://127.0.0.1:9999"
CLIENT="https://127.0.0.1:9998"
KMIPADDR="127.0.0.1:5696"
FAILS=0
step() { printf '\n== %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
bad()  { printf '[FAIL] %s\n' "$*"; FAILS=$((FAILS+1)); }

rm -rf "$WORK"; mkdir -p "$WORK"; chmod 700 "$WORK"
KS="$WORK/ks.json"
H() { "$HSMCTL" -ks "$KS" -name "$TPMNAME" "$@"; }
SYNC() { "$HSMCTL" -ks "$KS" -name "$TPMNAME" -kmip-addr "$KMIPADDR" -kmip-cert "$WORK/node.crt" -kmip-ca "$CA" -kmip-server-name localhost "$@"; }
# administration API as the console would call it: its certificate, acting for the console user "admin"
adm() { # adm METHOD PATH [JSON]
  curl -s -w '\n%{http_code}' --cacert "$CA" --cert pki/console-client.crt --key pki/console-client.key -H 'X-Acting-User: admin' \
    -H 'Content-Type: application/json' -X "$1" ${3:+-d "$3"} "$ADMIN$2"
}
code() { tail -n1; }
body() { sed '$d'; }
jv() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval("d"+sys.argv[1]))' "$1"; }
expect() { # expect "description" WANTED_HTTP "$(adm ...)"
  local d="$1" want="$2" resp="$3" got; got="$(printf '%s' "$resp" | code)"
  [ "$got" = "$want" ] && ok "$d (HTTP $got)" || bad "$d: HTTP $got, want $want: $(printf '%s' "$resp" | body | head -c 200)"
}

step "administration API (separate port, certificate + acting user)"
R="$(adm GET /admin/v1/me)"; expect "root administrator is recognised" 200 "$R"
printf '%s' "$R" | body | grep -q '"global": true' && ok "global scope" || bad "not global: $(printf '%s' "$R" | body)"
R="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" --cert pki/console-client.crt --key pki/console-client.key "$ADMIN/admin/v1/groups")"
[ "$R" = "403" ] && ok "the console certificate without an acting user holds no rights" || bad "proxy without user: $R"
R="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" "$ADMIN/admin/v1/me" 2>/dev/null)"
[ "$R" = "000" ] && ok "no client certificate: the TLS handshake is refused" || bad "served without a certificate: $R"

step "permission structure: super group -> service, mapping by super group"
adm POST /admin/v1/groups '{"name":"itest-div","kind":"super","owner":"itest.owner","description":"integration test"}' >/dev/null
adm POST /admin/v1/groups '{"name":"itest-svc","kind":"service","parent":"itest-div","owner":"itest.owner","description":"integration test service"}' >/dev/null
R="$(adm GET /admin/v1/groups)"; printf '%s' "$R" | body | grep -q '"name": "itest-svc"' && ok "service itest-svc under itest-div exists" || bad "groups: $(printf '%s' "$R" | body | head -c 300)"

step "TPM-protected Enterprise keystore (localhsm) and node certificate"
H -mode enterprise -max-sync-age 24h init >/dev/null 2>"$WORK/err" && ok "keystore initialised (TPM key $TPMNAME)" || bad "init: $(cat "$WORK/err")"
H -cn "$NODE" -dns "$NODE.internal" kms-csr > "$WORK/node.csr" 2>"$WORK/err"
grep -q "BEGIN CERTIFICATE REQUEST" "$WORK/node.csr" && ok "CSR made by the TPM-resident key" || bad "CSR: $(cat "$WORK/err")"
printf 'extendedKeyUsage=clientAuth\n' > "$WORK/node.ext"
openssl x509 -req -in "$WORK/node.csr" -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial -out "$WORK/node.crt" -days 30 -extfile "$WORK/node.ext" 2>/dev/null
[ -s "$WORK/node.crt" ] && ok "node certificate issued (its key never left the TPM)" || bad "no certificate"

step "key lifecycle through the administration API (values are never returned there)"
NAME="itest-$(date +%s)"
R="$(adm POST /admin/v1/keys "{\"algorithm\":\"aes-256\",\"group\":\"itest-svc\",\"name\":\"$NAME\",\"activate\":true}")"; expect "AES-256 created and activated" 201 "$R"
ID1="$(printf '%s' "$R" | body | jv '["keys"][0]["id"]')"
printf '%s' "$R" | body | grep -q '"state": "active"' && ok "state is the lower-case string 'active', not a KMIP number" || bad "state format"
R="$(adm GET "/admin/v1/keys/$ID1/value")"; [ "$(printf '%s' "$R" | code)" != "200" ] && ok "administrators get no key value endpoint" || bad "admin API released a value"

step "without a mapping the node sees nothing"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1 && bad "sync worked without a mapping" || ok "sync refused: $(head -c 120 "$WORK/out")"

step "map the node to the SUPER group with the built-in guest template (read only)"
expect "client mapped to itest-div as guest" 200 "$(adm PUT /admin/v1/bindings "{\"client\":\"$NODE\",\"group\":\"itest-div\",\"template\":\"guest\",\"approvalCode\":\"ITEST-APR-1\",\"owner\":\"itest.owner\"}")"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1; cat "$WORK/out"
grep -q "created: \[$NAME\]" "$WORK/out" && ok "key fetched by name through the super-group mapping" || bad "sync output unexpected"
PLAIN="pqc-kms integration $(date +%s)"
CT="$(printf '%s' "$PLAIN" | H encrypt "$NAME" 2>"$WORK/err")"
[ "$(printf '%s' "$CT" | H decrypt "$NAME" 2>/dev/null)" = "$PLAIN" ] && ok "encrypt/decrypt round trip inside the TPM-protected keystore" || bad "round trip: $(cat "$WORK/err")"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1
grep -q "new-versions: 0" "$WORK/out" && ok "second sync changes nothing" || bad "re-sync changed state"

step "the client REST port requires a client certificate too"
R="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" -X POST "$CLIENT/v1/keys" -H 'Content-Type: application/json' -d '{"algorithm":"aes-128"}' 2>/dev/null)"
[ "$R" = "000" ] && ok "REST without a certificate: handshake refused" || bad "REST without certificate: $R"

step "rotation in the administration API reaches localhsm WITH the old value (no gap)"
R="$(adm POST "/admin/v1/keys/$ID1/rekey")"; expect "re-key" 200 "$R"
ID2="$(printf '%s' "$R" | body | jv '["key"]["id"]')"
printf '%s' "$R" | body | grep -q '"replaced"' && ok "answer carries the new key and the replaced one" || bad "rekey answer"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1; cat "$WORK/out"
grep -q "new-versions: 1" "$WORK/out" && grep -q "status-changes: 1" "$WORK/out" && ! grep -q "skipped:" "$WORK/out" && ok "new version delivered, old one decrypt-only, nothing skipped" || bad "rotation not reflected"
H keys 2>&1 | grep "$NAME"
H keys 2>&1 | grep -q "1:decrypt-only,2:active" && ok "keystore: v1 decrypt-only, v2 active" || bad "version states"
CT2="$(printf '%s' "$PLAIN" | H encrypt "$NAME" 2>/dev/null)"
[ -n "$CT2" ] && [ "$(printf '%s' "$CT2" | H decrypt "$NAME" 2>/dev/null)" = "$PLAIN" ] && ok "new data uses the rotated key" || bad "encrypt after rotation"
[ "$(printf '%s' "$CT" | H decrypt "$NAME" 2>/dev/null)" = "$PLAIN" ] && ok "data from before the rotation still decrypts" || bad "old data lost"

step "permission template edit takes effect at once"
adm POST /admin/v1/templates '{"name":"itest-meta","description":"metadata only","operations":["locate","getattributes"],"approvalCode":"ITEST-APR-4"}' >/dev/null
expect "node moved to the metadata-only template" 200 "$(adm PUT /admin/v1/bindings "{\"client\":\"$NODE\",\"group\":\"itest-div\",\"template\":\"itest-meta\",\"approvalCode\":\"ITEST-APR-2\",\"owner\":\"itest.owner\"}")"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1 && bad "sync worked without 'get'" || ok "sync refused without the get operation"
expect "template edited: get added" 200 "$(adm PUT /admin/v1/templates/itest-meta '{"description":"metadata + value","operations":["locate","getattributes","get"],"approvalCode":"ITEST-APR-5"}')"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1 && ok "sync works again after the edit" || bad "sync after edit: $(cat "$WORK/out")"

step "deactivate and compromise reach localhsm"
expect "deactivate the current key" 200 "$(adm POST "/admin/v1/keys/$ID2/deactivate")"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1; cat "$WORK/out"
H keys 2>&1 | grep -q "1:decrypt-only,2:decrypt-only" && ok "both versions decrypt-only" || bad "deactivate not reflected"
[ -z "$(printf '%s' "$PLAIN" | H encrypt "$NAME" 2>/dev/null)" ] && ok "new encryption refused" || bad "encryption still allowed"
expect "mark compromised" 200 "$(adm POST "/admin/v1/keys/$ID2/compromise")"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1
H keys 2>&1 | grep -q "2:disabled" && ok "compromised version disabled in the keystore" || bad "compromise not reflected"
[ -z "$(printf '%s' "$CT2" | H decrypt "$NAME" 2>/dev/null)" ] && ok "data under the compromised key no longer decrypts here" || bad "compromised key still decrypts"

step "removing the mapping blocks the node"
expect "mapping removed" 200 "$(adm DELETE "/admin/v1/bindings?client=$NODE&group=itest-div")"
SYNC -kmip-types "$NAME=aes256-gcm" kmip-sync "$NAME" >"$WORK/out" 2>&1 && bad "sync works after removal" || ok "sync refused after removal"

step "client REST API with plain JSON values (software certificate, guest on the service)"
openssl req -newkey rsa:2048 -nodes -keyout "$WORK/rest.key" -out "$WORK/rest.csr" -subj "/CN=rest-itest" 2>/dev/null
openssl x509 -req -in "$WORK/rest.csr" -CA pki/ca.crt -CAkey pki/ca.key -CAcreateserial -out "$WORK/rest.crt" -days 2 -extfile "$WORK/node.ext" 2>/dev/null
adm PUT /admin/v1/bindings '{"client":"rest-itest","group":"itest-svc","template":"guest","approvalCode":"ITEST-APR-3","owner":"itest.owner"}' >/dev/null
rest() { curl -s -w '\n%{http_code}' --cacert "$CA" --cert "$WORK/rest.crt" --key "$WORK/rest.key" -H 'Content-Type: application/json' -X "$1" ${3:+-d "$3"} "$CLIENT$2"; }
PQCNAME="itest-pqc-$(date +%s)"
R="$(adm POST /admin/v1/keys "{\"algorithm\":\"ml-dsa-65\",\"group\":\"itest-svc\",\"name\":\"$PQCNAME\",\"activate\":true}")"; expect "post-quantum key pair (ML-DSA-65) created" 201 "$R"
printf '%s' "$R" | body | grep -q '"standard": "FIPS 204"' && ok "response names the algorithm as the standard does (ML-DSA-65, FIPS 204)" || bad "algorithm info"
R="$(rest GET "/v1/keys?name=$PQCNAME")"; expect "guest lists keys by name" 200 "$R"
[ "$(printf '%s' "$R" | body | jv '["count"]')" = "2" ] && ok "private and public key listed" || bad "count"
PRIV="$(printf '%s' "$R" | body | python3 -c 'import sys,json; print([k["id"] for k in json.load(sys.stdin)["keys"] if k["type"]=="private"][0])')"
R="$(rest GET "/v1/keys/$PRIV/value?encoding=hex")"; expect "guest reads the value" 200 "$R"
[ "$(printf '%s' "$R" | body | jv '["value"]["sizeBytes"]')" = "4032" ] && ok "ML-DSA-65 private value is 4032 bytes, hex encoded" || bad "value size"
expect "guest cannot create" 403 "$(rest POST /v1/keys '{"algorithm":"aes-128"}')"
expect "guest cannot destroy" 404 "$(rest POST "/v1/keys/$PRIV/destroy")"
R="$(rest GET /v1/keys/nope)"; printf '%s' "$R" | body | grep -q '"code": "not_found"' && printf '%s' "$R" | body | grep -q '"requestId"' && ok "errors carry code, message and request id" || bad "error format"

step "audit evidence"
R="$(adm GET '/admin/v1/audit/verify?log=admin')"; printf '%s' "$R" | body | grep -q '"ok": true' && ok "admin log: hash chain and MACs verify" || bad "admin log chain: $(printf '%s' "$R" | body | head -c 300)"
R="$(adm GET '/admin/v1/audit/verify?log=client')"; printf '%s' "$R" | body | grep -q '"ok": true' && ok "client log: hash chain and MACs verify" || bad "client log chain"
adm GET '/admin/v1/logs/admin?category=permission-change&q=ITEST-APR-1' | body > "$WORK/perm.json"
python3 - "$WORK/perm.json" <<'PYEOF' && ok "permission grants carry approval number and responsible person" || bad "grant evidence"
import sys, json
e = json.load(open(sys.argv[1]))["entries"]
g = [x for x in e if x["op"] == "binding-put" and x.get("approval") == "ITEST-APR-1"]
assert g and all(x.get("owner") == "itest.owner" and x["outcome"] == "success" and x.get("hash") and x.get("mac") for x in g), e
PYEOF
R="$(adm POST /admin/v1/audit/reviews '{"log":"admin","from":"2026-11-01","to":"2026-11-07","finding":"none","note":"integration test review"}')"; expect "review record" 201 "$R"
curl -s -o "$WORK/audit.zip" --cacert "$CA" --cert pki/console-client.crt --key pki/console-client.key -H 'X-Acting-User: admin' "$ADMIN/admin/v1/audit/export?log=admin"
python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1]); assert sorted(z.namelist())==["admin-audit.jsonl","manifest.json"]' "$WORK/audit.zip" && ok "evidence export (zip with manifest) available" || bad "export"

step "the two logs are separate"
adm GET '/admin/v1/logs/client?limit=500' | body > "$WORK/client.log.json"
adm GET '/admin/v1/logs/admin?limit=500' | body > "$WORK/admin.log.json"
python3 - "$WORK/client.log.json" "$NODE" <<'PYEOF' && ok "client log: KMIP and REST requests of $NODE and rest-itest (plane=client only)" || bad "client log content"
import sys, json
e = json.load(open(sys.argv[1]))["entries"]
who = {x["who"] for x in e}
assert all(x["plane"] == "client" for x in e), "non-client entry in the client log"
assert sys.argv[2] in who and "rest-itest" in who, who
assert any(x["who"] == sys.argv[2] and x["op"].startswith("KMIP") and x["result"].startswith("error") for x in e), "refused KMIP request not logged"
print("client log:", len(e), "entries from", sorted(who))
PYEOF
python3 - "$WORK/admin.log.json" <<'PYEOF' && ok "admin log: administration requests only, with acting user and proxy" || bad "admin log content"
import sys, json
e = json.load(open(sys.argv[1]))["entries"]
assert all(x["plane"] == "admin" for x in e), "non-admin entry in the admin log"
assert any(x["who"] == "admin" and x.get("via") == "kms-console" for x in e), "acting user / proxy not recorded"
print("admin log:", len(e), "entries, acting user recorded together with the proxy")
PYEOF

step "cleanup"
for i in "$ID2" "$ID1" "$PRIV"; do adm POST "/admin/v1/keys/$i/deactivate" >/dev/null; adm POST "/admin/v1/keys/$i/destroy" >/dev/null; done
adm DELETE '/admin/v1/bindings?client=rest-itest&group=itest-svc' >/dev/null
adm DELETE /admin/v1/templates/itest-meta >/dev/null
"$HSMCTL" -name "$TPMNAME" kms-signer-destroy >/dev/null 2>&1 && ok "TPM signing key removed" || bad "could not remove the TPM signing key"
"$HSMCTL" -ks "$KS" -name "$TPMNAME" destroy-node >/dev/null 2>&1 && ok "TPM protector key removed" || bad "could not remove the TPM protector key"
rm -rf "$WORK"
printf '\nRESULT: %s failure(s)\n' "$FAILS"
exit $FAILS
