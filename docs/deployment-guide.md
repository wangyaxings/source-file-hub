# FileServer Deployment Guide

## 姒傝堪

鏈寚鍗楀皢璇︾粏璇存槑濡備綍浣跨敤棰勬瀯寤虹殑Docker闀滃儚 `ghcr.io/wangyaxings/source-file-hub:latest` 閮ㄧ讲FileServer椤圭洰銆?

## 鍓嶇疆瑕佹眰

- Docker 20.0+
- Docker Compose 2.0+
- 鑷冲皯 2GB 鍙敤纾佺洏绌洪棿

## 蹇€熷紑濮?

### 1. 鍒涘缓椤圭洰鐩綍缁撴瀯

```bash
# 鍒涘缓涓荤洰褰?
mkdir fileserver-docker
cd fileserver-docker

# 鍒涘缓蹇呰鐨勫瓙鐩綍
mkdir -p {configs,certs,data,downloads,logs}
mkdir -p downloads/{configs,certificates,docs}
```

### 2. 鍑嗗閰嶇疆鏂囦欢

鍒涘缓 `configs/config.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "https_port": 8443,
    "read_timeout": "30s",
    "write_timeout": "30s",
    "ssl_enabled": true,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key"
  },
  "application": {
    "name": "FileServer",
    "version": "4.0.0",
    "environment": "production",
    "protocol": "https"
  },
  "logging": {
    "level": "info",
    "format": "json"
  },
  "features": {
    "download_enabled": true,
    "cors_enabled": true,
    "auth_enabled": true,
    "ssl_enabled": true,
    "unified_file_download": true,
    "authenticated_downloads": true
  },
  "auth": {
    "require_auth": true,
    "default_users": [
      {
        "tenant_id": "demo",
        "username": "admin",
        "description": "绠＄悊鍛樿处鎴?
      },
      {
        "tenant_id": "demo",
        "username": "user1",
        "description": "鏅€氱敤鎴疯处鎴?
      }
    ]
  },
  "downloads": {
    "base_directory": "downloads",
    "allowed_paths": [
      "configs/",
      "certificates/",
      "docs/"
    ],
    "supported_types": [".json", ".crt", ".key", ".txt", ".log", ".pem"]
  }
}
```

### 3. 鐢熸垚SSL璇佷功

鍒涘缓璇佷功鐢熸垚鑴氭湰 `generate-certs.sh`:

```bash
#!/bin/bash

# 鐢熸垚SSL璇佷功鐢ㄤ簬HTTPS
openssl genrsa -out certs/server.key 2048

openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=FileServer/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:fileserver.local,IP:127.0.0.1"

# 鐢熸垚璇佷功淇℃伅鏂囦欢
cat > certs/cert_info.json << 'EOF'
{
  "subject": {
    "common_name": "localhost",
    "organization": ["FileServer"],
    "country": ["CN"],
    "province": ["Beijing"],
    "locality": ["Beijing"]
  },
  "validity": {
    "not_before": "$(date -d 'now' -Iseconds)",
    "not_after": "$(date -d '+365 days' -Iseconds)"
  },
  "key_usage": ["Digital Signature", "Key Encipherment"],
  "ext_key_usage": ["Server Authentication"],
  "dns_names": ["localhost", "fileserver.local"],
  "ip_addresses": ["127.0.0.1", "::1"],
  "key_size": 2048,
  "signature_algorithm": "SHA256-RSA",
  "files": {
    "certificate": "server.crt",
    "private_key": "server.key"
  }
}
EOF

echo "鉁?SSL璇佷功鐢熸垚瀹屾垚"
echo "  璇佷功鏂囦欢: certs/server.crt"
echo "  绉侀挜鏂囦欢: certs/server.key"
echo "  璇佷功淇℃伅: certs/cert_info.json"
```

鎵ц鐢熸垚璇佷功:
```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

### 4. 鍒涘缓Docker Compose閰嶇疆

鍒涘缓 `docker-compose.yml`:

```yaml
version: '3.8'

services:
  fileserver:
    image: ghcr.io/wangyaxings/source-file-hub:latest
    container_name: fileserver-app
    ports:
      - "8443:8443"  # HTTPS绔彛
    volumes:
      # 鎸佷箙鍖栨暟鎹?
      - ./data:/app/data
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      # 閰嶇疆鏂囦欢 (鍙)
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
    environment:
      - GO_ENV=production
      - DB_PATH=/app/data/fileserver.db
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:8443/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge

volumes:
  # 濡傛灉闇€瑕佸閮ㄥ嵎绠＄悊锛屽彲浠ュ畾涔夊懡鍚嶅嵎
  fileserver_data:
    driver: local
  fileserver_logs:
    driver: local
```

### 5. 鍑嗗鍒濆涓嬭浇鏂囦欢

澶嶅埗閰嶇疆鏂囦欢鍒颁笅杞界洰褰?
```bash
# 澶嶅埗閰嶇疆鏂囦欢鍒颁笅杞界洰褰?
cp configs/config.json downloads/configs/
cp certs/server.crt downloads/certificates/
cp certs/server.key downloads/certificates/
cp certs/cert_info.json downloads/certificates/

# 鍒涘缓API鏂囨。
cat > downloads/docs/api_guide.txt << 'EOF'
FileServer API 浣跨敤鎸囧崡

鍩虹淇℃伅:
- API Base URL: https://localhost:8443/api/v1
- 璁よ瘉鏂瑰紡: Bearer Token
- 鍗忚: HTTPS Only

涓昏鎺ュ彛:
1. 鍋ュ悍妫€鏌? GET /health
2. 鐢ㄦ埛鐧诲綍: POST /auth/login
3. 鑾峰彇鐢ㄦ埛: GET /auth/users
4. 鏂囦欢涓嬭浇: GET /files/{path}
5. 鐢ㄦ埛鐧诲嚭: POST /auth/logout

浣跨敤姝ラ:
1. 璋冪敤 /auth/users 鑾峰彇娴嬭瘯鐢ㄦ埛
2. 璋冪敤 /auth/login 鐧诲綍鑾峰彇token
3. 浣跨敤token璁块棶 /files/* 涓嬭浇鏂囦欢
4. 璋冪敤 /auth/logout 鐧诲嚭

娉ㄦ剰浜嬮」:
- 鎵€鏈堿PI閮介渶瑕丠TTPS璁块棶
- 鏂囦欢涓嬭浇闇€瑕佺敤鎴疯璇?
- Token鏈夋晥鏈?4灏忔椂
EOF
```

## 鍚姩鏈嶅姟

### 6. 鎷夊彇闀滃儚骞跺惎鍔?

```bash
# 鎷夊彇鏈€鏂伴暅鍍?
docker pull ghcr.io/wangyaxings/source-file-hub:latest

# 鍚姩鏈嶅姟
docker-compose up -d

# 鏌ョ湅鏈嶅姟鐘舵€?
docker-compose ps

# 鏌ョ湅鏃ュ織
docker-compose logs -f fileserver
```

### 7. 楠岃瘉鏈嶅姟杩愯

```bash
# 妫€鏌ュ仴搴风姸鎬?
curl -k https://localhost:8443/api/v1/health

# 鑾峰彇API淇℃伅
curl -k https://localhost:8443/api/v1

# 鑾峰彇榛樿鐢ㄦ埛鍒楄〃
curl -k https://localhost:8443/api/v1/auth/users
```

## 瀹屾暣娴嬭瘯娴佺▼

### 8. API鍔熻兘楠岃瘉

```bash
# 1. 鐢ㄦ埛鐧诲綍
RESPONSE=$(curl -k -s -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}')

# 2. 鎻愬彇token
TOKEN=$(echo $RESPONSE | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "Token: $TOKEN"

# 3. 涓嬭浇閰嶇疆鏂囦欢
curl -k -H "(use cookie.txt)" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

# 4. 涓嬭浇SSL璇佷功
curl -k -H "(use cookie.txt)" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.crt

# 5. 涓嬭浇API鏂囨。
curl -k -H "(use cookie.txt)" \
  -O -J https://localhost:8443/api/v1/files/docs/api_guide.txt

# 6. 鐢ㄦ埛鐧诲嚭
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "(use cookie.txt)"
```

## 绠＄悊鎿嶄綔

### 9. 鏈嶅姟绠＄悊鍛戒护

```bash
# 鍋滄鏈嶅姟
docker-compose down

# 閲嶅惎鏈嶅姟
docker-compose restart

# 鏌ョ湅瀹炴椂鏃ュ織
docker-compose logs -f

# 杩涘叆瀹瑰櫒
docker-compose exec fileserver sh

# 澶囦唤鏁版嵁
tar -czf fileserver-backup-$(date +%Y%m%d).tar.gz data/ downloads/ configs/

# 娓呯悊锛堟厧鐢?- 浼氬垹闄ゆ墍鏈夋暟鎹級
docker-compose down -v
```

### 10. 鏁呴殰鎺掗櫎

```bash
# 鏌ョ湅瀹瑰櫒鐘舵€?
docker ps -a

# 鏌ョ湅璇︾粏鏃ュ織
docker logs fileserver-app

# 妫€鏌ラ厤缃枃浠?
docker-compose config

# 妫€鏌ョ綉缁滆繛鎺?
docker network ls
docker network inspect fileserver_fileserver-network

# 妫€鏌ュ嵎鎸傝浇
docker inspect fileserver-app | grep -A 20 "Mounts"
```

## 楂樼骇閰嶇疆

### 11. 鐢熶骇鐜浼樺寲

瀵逛簬鐢熶骇鐜锛屽垱寤?`docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  fileserver:
    image: ghcr.io/wangyaxings/source-file-hub:latest
    container_name: fileserver-prod
    ports:
      - "8443:8443"
    volumes:
      # 浣跨敤缁濆璺緞鎸傝浇
      - /var/lib/fileserver/data:/app/data
      - /var/lib/fileserver/downloads:/app/downloads
      - /var/log/fileserver:/app/logs
      - /etc/fileserver/configs:/app/configs:ro
      - /etc/ssl/fileserver:/app/certs:ro
    environment:
      - GO_ENV=production
      - DB_PATH=/app/data/fileserver.db
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:8443/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge
    name: fileserver-prod-network
```

### 12. 鍙嶅悜浠ｇ悊閰嶇疆 (鍙€?

濡傞渶瑕侀€氳繃Nginx鍙嶅悜浠ｇ悊锛屽垱寤?`nginx.conf`:

```nginx
upstream fileserver_backend {
    server fileserver:8443;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    location / {
        proxy_pass https://fileserver_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_ssl_verify off;
    }
}
```

## 瀹夊叏寤鸿

1. **鏇存崲榛樿瀵嗙爜**: 鐧诲綍鍚庣珛鍗虫洿鏀归粯璁ょ敤鎴峰瘑鐮?
2. **浣跨敤姝ｅ紡璇佷功**: 鐢熶骇鐜浣跨敤CA绛惧彂鐨凷SL璇佷功
3. **瀹氭湡澶囦唤**: 璁剧疆鑷姩澶囦唤鏁版嵁搴撳拰閰嶇疆鏂囦欢
4. **缃戠粶闅旂**: 浣跨敤闃茬伀澧欓檺鍒惰闂鍙?
5. **鏃ュ織鐩戞帶**: 瀹氭湡妫€鏌ヨ闂棩蹇楀彂鐜板紓甯?
6. **鏇存柊闀滃儚**: 瀹氭湡鎷夊彇鏈€鏂伴暅鍍忚幏鍙栧畨鍏ㄦ洿鏂?

## 甯歌闂

**Q: 瀹瑰櫒鍚姩澶辫触鎬庝箞鍔烇紵**
A: 妫€鏌ユ棩蹇?`docker logs fileserver-app`锛岄€氬父鏄厤缃枃浠舵垨鏉冮檺闂

**Q: 鏃犳硶璁块棶HTTPS鏈嶅姟锛?*
A: 纭璇佷功鏂囦欢瀛樺湪涓旀牸寮忔纭紝妫€鏌ラ槻鐏璁剧疆

**Q: 鏂囦欢涓嬭浇澶辫触锛?*
A: 妫€鏌ownloads鐩綍鏉冮檺锛岀‘璁ゆ枃浠跺瓨鍦ㄤ簬allowed_paths涓?

**Q: 濡備綍鏇存柊鏈嶅姟锛?*
A: 鎷夊彇鏂伴暅鍍忓悗鎵ц `docker-compose up -d` 浼氳嚜鍔ㄩ噸鍚湇鍔?

---

馃挕 **鎻愮ず**: 棣栨鍚姩寤鸿鍏堝湪娴嬭瘯鐜楠岃瘉鎵€鏈夊姛鑳芥甯稿悗鍐嶉儴缃插埌鐢熶骇鐜銆?
