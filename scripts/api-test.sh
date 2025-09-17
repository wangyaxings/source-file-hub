#!/usr/bin/env bash
set -euo pipefail

# Usage: API_KEY=sk_xxx IPS="192.168.1.10,192.168.1.11" PORTS="8444,30000" TENANT=tenant123 ./scripts/api-test.sh

IPS_CSV=${IPS:-"192.168.197.130"}
PORTS_CSV=${PORTS:-"8444,30000"}
HOSTNAME=${TARGET_HOSTNAME:-"localhost"}
API_KEY=${API_KEY:-"sk_6946cb70c5ad8efe4748cbb587a04e8ace3f6e3c9fb56e32a6ca29529385ac66"}
TENANT=${TENANT:-"tenant123"}
DO_UPLOADS=${DO_UPLOADS:-"0"}

IFS=',' read -r -a IPS_ARR <<< "$IPS_CSV"
IFS=',' read -r -a PORTS_ARR <<< "$PORTS_CSV"

OUT_DIR="tmp/api-test"
mkdir -p "$OUT_DIR"

curl_json() {
  local name=$1; shift
  local outfile=$1; shift
  local code
  code=$(curl -s -k -o "$outfile" -w '%{http_code}' "$@" || true)
  local preview=""
  if [[ -f "$outfile" ]]; then
    preview=$(head -c 160 "$outfile")
  fi
  printf "%s -> %s | %s\n" "$name" "$code" "$preview"
}

for ip in "${IPS_ARR[@]}"; do
  for port in "${PORTS_ARR[@]}"; do
    echo "== Testing $ip:$port =="
    base="https://$HOSTNAME:$port/api/v1"
    resolve=(--resolve "$HOSTNAME:$port:$ip")
    headers=()
    if [[ -n "$API_KEY" ]]; then
      headers=(-H "X-API-Key: $API_KEY")
    fi

    # health
    curl_json health "$OUT_DIR/health-$ip-$port.json" "${resolve[@]}" "$base/health"
    curl_json healthz "$OUT_DIR/healthz-$ip-$port.json" "${resolve[@]}" "$base/healthz"

    # list files
    curl_json files "$OUT_DIR/files-$ip-$port.json" "${resolve[@]}" "${headers[@]}" "$base/public/files"

    # latest endpoints
    curl_json latest-roadmap "$OUT_DIR/latest-roadmap-$ip-$port.json" "${resolve[@]}" "${headers[@]}" "$base/public/versions/roadmap/latest"
    curl_json latest-reco "$OUT_DIR/latest-reco-$ip-$port.json" "${resolve[@]}" "${headers[@]}" "$base/public/versions/recommendation/latest"

    # HEAD download latest roadmap (avoid large file)
    code=$(curl -s -k -I -w '%{http_code}' -o "$OUT_DIR/dl-latest-roadmap-$ip-$port.headers" "${resolve[@]}" "${headers[@]}" "$base/public/versions/roadmap/latest/download" || true)
    echo "download latest roadmap (HEAD) -> $code"

    if [[ "$DO_UPLOADS" == "1" && -n "$API_KEY" ]]; then
      utc=$(date -u +%Y%m%dT%H%M%SZ)
      tmpd="$OUT_DIR/tmp-$ip-$port"; mkdir -p "$tmpd"
      echo 'hello api test' > "$tmpd/dummy.txt"
      zipA="$tmpd/${TENANT}_assets_${utc}.zip"
      zipO="$tmpd/${TENANT}_others_${utc}.zip"
      rm -f "$zipA" "$zipO"
      (cd "$tmpd" && zip -q -r "$zipA" dummy.txt)
      (cd "$tmpd" && zip -q -r "$zipO" dummy.txt)
      curl_json upload-assets "$OUT_DIR/upload-assets-$ip-$port.json" "${resolve[@]}" "${headers[@]}" -F "file=@$zipA" "$base/public/upload/assets-zip"
      curl_json upload-others "$OUT_DIR/upload-others-$ip-$port.json" "${resolve[@]}" "${headers[@]}" -F "file=@$zipO" "$base/public/upload/others-zip"
    fi
  done
done

echo "Done. Outputs in $OUT_DIR"

