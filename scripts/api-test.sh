#!/usr/bin/env bash
set -euo pipefail

# Usage: API_KEY=sk_xxx IPS="10.48.102.36" PORTS="8444,30000" TENANT=tenant123 ./scripts/api-test.sh

# Default target updated for Operation Center testing
IPS_CSV=${IPS:-"10.48.102.36"}
PORTS_CSV=${PORTS:-"8444,30000"}
HOSTNAME=${TARGET_HOSTNAME:-"localhost"}
API_KEY=${API_KEY:-"sk_6946cb70c5ad8efe4748cbb587a04e8ace3f6e3c9fb56e32a6ca29529385ac66"}
TENANT=${TENANT:-"tenant123"}
DO_UPLOADS=${DO_UPLOADS:-"0"}
DO_DOWNLOADS=${DO_DOWNLOADS:-"1"}

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

sha256_file() {
  local f=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$f" | awk '{print $1}'
  else
    echo "" # no hasher available
  fi
}

json_get_version() {
  # Extract integer version from latest info JSON saved by curl_json
  local json=$1
  if command -v jq >/dev/null 2>&1; then
    jq -r '.data.latest.version // empty' "$json" 2>/dev/null
  else
    grep -o '"version"[[:space:]]*:[[:space:]]*[0-9]\+' "$json" | head -n1 | sed 's/[^0-9]//g'
  fi
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

    # latest endpoints (metadata)
    curl_json latest-roadmap "$OUT_DIR/latest-roadmap-$ip-$port.json" "${resolve[@]}" "${headers[@]}" "$base/public/versions/roadmap/latest"
    curl_json latest-reco "$OUT_DIR/latest-reco-$ip-$port.json" "${resolve[@]}" "${headers[@]}" "$base/public/versions/recommendation/latest"

    if [[ "$DO_DOWNLOADS" == "1" ]]; then
      # Download latest roadmap + recommendation and compute SHA256
      for typ in roadmap recommendation; do
        ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        json="$OUT_DIR/latest-$typ-$ip-$port.json"
        ver=$(json_get_version "$json")
        outbin="$OUT_DIR/${typ}-latest-${ip}-${port}.bin"
        headers_file="$OUT_DIR/dl-latest-${typ}-${ip}-${port}.headers"
        code=$(curl -s -k -L -D "$headers_file" -o "$outbin" -w '%{http_code}' "${resolve[@]}" "${headers[@]}" "$base/public/versions/$typ/latest/download" || true)
        if [[ "$code" == "200" && -s "$outbin" ]]; then
          sum=$(sha256_file "$outbin")
          size=$(stat -c %s "$outbin" 2>/dev/null || wc -c <"$outbin")
          echo "[download] $typ -> 200 | version=${ver:-n/a} | size=${size} bytes | checksum=sha256:${sum:-n/a} | time=$ts"
        else
          echo "[download] $typ -> $code | failed"
        fi
      done
    else
      # HEAD only (no download)
      code=$(curl -s -k -I -w '%{http_code}' -o "$OUT_DIR/dl-latest-roadmap-$ip-$port.headers" "${resolve[@]}" "${headers[@]}" "$base/public/versions/roadmap/latest/download" || true)
      echo "download latest roadmap (HEAD) -> $code"
      code=$(curl -s -k -I -w '%{http_code}' -o "$OUT_DIR/dl-latest-recommendation-$ip-$port.headers" "${resolve[@]}" "${headers[@]}" "$base/public/versions/recommendation/latest/download" || true)
      echo "download latest recommendation (HEAD) -> $code"
    fi

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

