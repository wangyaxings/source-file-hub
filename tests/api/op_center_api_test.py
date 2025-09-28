#!/usr/bin/env python3
"""
Operation Center API 一键测试脚本

功能：
- 健康检查 /api/v1/healthz
- 获取最新信息（roadmap / recommendation）
- 下载最新文件到本地目录
- 生成并上传 assets/others ZIP 包

用法示例：
  python tmp/op_center_api_test.py --base https://localhost:8443 --api-key sk_xxx --do-all
  python tmp/op_center_api_test.py --base http://localhost:30080 --api-key sk_xxx --do-info --do-download
  python tmp/op_center_api_test.py --base https://localhost:8443 --api-key sk_xxx ^
    --gen-upload-assets --gen-upload-others --do-upload-assets --do-upload-others
python tests/api/op_center_api_test.py --base https://localhost:8443 --api-key sk_30b2b2ac2a938a8fdb4479c41cd0f83b25222b2cebda0f7618a91b94b5cb97bf --do-all
python tests/api/op_center_api_test.py --base https://10.48.98.78:8444 --api-key sk_3ca3508393986f24268c0b61e1bb59a00254ba5ddcd5485aa473301f0ab05475 --do-all
注意：
- 若目标是自签名证书，默认 verify=False；如有可信证书可加 --verify 关闭该行为。
"""

import argparse
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Optional, Callable, List, Tuple
from datetime import datetime, timezone
import zipfile

import requests


def parse_args():
    p = argparse.ArgumentParser(description="Operation Center API tester")
    p.add_argument("--base", default=os.environ.get("BASE_URL", "https://localhost:8443"), help="基础地址，如 https://localhost:8443 或 http://localhost:30080")
    p.add_argument("--api-key", default=os.environ.get("API_KEY"), help="API Key，亦可用环境变量 API_KEY")
    p.add_argument("--verify", action="store_true", help="启用 TLS 证书校验（默认关闭）")
    p.add_argument("--save-dir", default=os.path.join("tmp", "api-downloads"), help="下载保存目录")
    p.add_argument("--log-file", default=os.path.join("tmp", "api-test.log"), help="日志输出文件")
    p.add_argument("--tenant", default=os.environ.get("TENANT", "tenant123"), help="生成上传包的租户名；默认 tenant123")
    p.add_argument("--upload-dir", default=os.path.join("tmp", "api-uploads"), help="生成上传 ZIP 的目录")

    # 动作
    p.add_argument("--do-health", action="store_true", help="仅健康检查")
    p.add_argument("--do-status-check", action="store_true", help="健康检查和API key验证合并接口")
    p.add_argument("--do-info", action="store_true", help="查询最新信息（roadmap/recommendation）")
    p.add_argument("--do-download", action="store_true", help="下载最新文件（roadmap/recommendation）")
    p.add_argument("--do-upload-assets", nargs="?", const="AUTO", metavar="ZIP", help="上传 assets ZIP（省略路径或传 AUTO 则自动生成）")
    p.add_argument("--do-upload-others", nargs="?", const="AUTO", metavar="ZIP", help="上传 others ZIP（省略路径或传 AUTO 则自动生成）")
    p.add_argument("--gen-upload-assets", action="store_true", help="先生成 <tenant>_assets_<UTC>.zip")
    p.add_argument("--gen-upload-others", action="store_true", help="先生成 <tenant>_others_<UTC>.zip")
    p.add_argument("--do-all", action="store_true", help="运行健康检查、信息查询与下载")
    return p.parse_args()


def headers(api_key: Optional[str]):
    h = {"Accept": "application/json"}
    if api_key:
        h["Authorization"] = f"ApiKey {api_key}"
    return h


def health(base: str, verify: bool):
    url = f"{base}/api/v1/healthz"
    logging.info("GET %s", url)
    r = requests.get(url, timeout=20, verify=verify)
    r.raise_for_status()
    logging.info("health response: %s", r.text)
    return r.json()


def status_check(base: str, api_key: str, verify: bool):
    """测试健康检查和API key验证合并接口"""
    url = f"{base}/api/v1/status-check"
    if api_key:
        url += f"?api_key={api_key}"
    logging.info("GET %s", url)
    r = requests.get(url, timeout=20, verify=verify)
    r.raise_for_status()
    logging.info("status-check response: %s", r.text)
    return r.json()


def latest_info(base: str, api_key: str, typ: str, verify: bool):
    url = f"{base}/api/v1/public/versions/{typ}/latest/info"
    logging.info("GET %s", url)
    r = requests.get(url, headers=headers(api_key), timeout=30, verify=verify)
    r.raise_for_status()
    j = r.json()
    logging.info("info %s response: %s", typ, r.text)
    return j


def latest_download(base: str, api_key: str, typ: str, save_dir: str, verify: bool):
    os.makedirs(save_dir, exist_ok=True)
    url = f"{base}/api/v1/public/versions/{typ}/latest/download"
    logging.info("GET %s", url)
    with requests.get(url, headers=headers(api_key), stream=True, timeout=120, verify=verify) as r:
        r.raise_for_status()
        cd = r.headers.get("Content-Disposition", "")
        fname = f"{typ}-latest-{int(time.time())}"
        if "filename=" in cd:
            fname = cd.split("filename=")[-1].strip("\" ")
        path = os.path.join(save_dir, fname)
        with open(path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        logging.info("downloaded %s to %s", typ, path)
        return path


def upload_zip(base: str, api_key: str, kind: str, zip_path: str, verify: bool, tenant: str):
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(zip_path)
    ep = "assets-zip" if kind == "assets" else "others-zip"
    url = f"{base}/api/v1/public/upload/{ep}"
    logging.info("POST %s (file=%s)", url, zip_path)
    with open(zip_path, "rb") as f:
        files = {"file": (os.path.basename(zip_path), f, "application/zip")}
        data = {"tenant_id": tenant}
        r = requests.post(url, headers=headers(api_key), files=files, data=data, timeout=300, verify=verify)
        r.raise_for_status()
        logging.info("upload %s response: %s", kind, r.text)
        return r.json()


def utc_stamp() -> str:
    """返回 UTC 时间戳，格式 YYYYMMDDThhmmssZ"""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def generate_zip(kind: str, tenant: str, out_dir: str) -> str:
    if kind not in ("assets", "others"):
        raise ValueError("kind must be 'assets' or 'others'")
    os.makedirs(out_dir, exist_ok=True)
    name = f"{tenant}_{kind}_{utc_stamp()}.zip"
    path = os.path.join(out_dir, name)
    logging.info("generating %s zip: %s", kind, path)
    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dummy.txt", f"generated for {tenant} {kind} at {datetime.now(timezone.utc).isoformat()}Z")
    return path


# --- 测试框架 ---
CHECK = "\u2713"  # ✓
CROSS = "\u2717"  # ✗


@dataclass
class Case:
    name: str
    fn: Callable[[], None]


def run_cases(cases: List[Case]) -> Tuple[int, int, List[Tuple[str, bool, Optional[str]]]]:
    total = len(cases)
    ok = 0
    results: List[Tuple[str, bool, Optional[str]]] = []
    for c in cases:
        try:
            c.fn()
            results.append((c.name, True, None))
            ok += 1
            print(f"[{CHECK}] {c.name}")
        except Exception as e:
            logging.exception("case failed: %s", c.name)
            results.append((c.name, False, str(e)))
            print(f"[{CROSS}] {c.name} -> {e}")
    return total, ok, results


def setup_logging(log_file: str):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def main():
    args = parse_args()
    setup_logging(args.log_file)
    verify = args.verify  # 默认 False，关闭 TLS 校验
    if args.do_all:
        args.do_health = True
        args.do_status_check = True
        args.do_info = True
        args.do_download = True
        # do-all 同时包含上传用例；AUTO 表示自动生成 ZIP 后上传
        args.do_upload_assets = "AUTO"
        args.do_upload_others = "AUTO"

    # 生成上传包（如需）并填充到上传参数
    if args.gen_upload_assets and (not args.do_upload_assets or args.do_upload_assets == "AUTO"):
        args.do_upload_assets = generate_zip("assets", args.tenant, args.upload_dir)
    if args.gen_upload_others and (not args.do_upload_others or args.do_upload_others == "AUTO"):
        args.do_upload_others = generate_zip("others", args.tenant, args.upload_dir)

    # 如果传入了 AUTO 或文件不存在，则生成一个
    if args.do_upload_assets and (args.do_upload_assets == "AUTO" or not os.path.isfile(args.do_upload_assets)):
        args.do_upload_assets = generate_zip("assets", args.tenant, args.upload_dir)
    if args.do_upload_others and (args.do_upload_others == "AUTO" or not os.path.isfile(args.do_upload_others)):
        args.do_upload_others = generate_zip("others", args.tenant, args.upload_dir)

    # 组装用例
    cases: List[Case] = []
    if args.do_health:
        cases.append(Case("Health: /api/v1/healthz", lambda: health(args.base, verify)))
    if args.do_status_check:
        cases.append(Case("Status Check: /api/v1/status-check (no API key)", lambda: status_check(args.base, None, verify)))
        if args.api_key:
            cases.append(Case("Status Check: /api/v1/status-check (with API key)", lambda: status_check(args.base, args.api_key, verify)))
    if args.do_info:
        cases.append(Case("Info: roadmap", lambda: latest_info(args.base, args.api_key, "roadmap", verify)))
        cases.append(Case("Info: recommendation", lambda: latest_info(args.base, args.api_key, "recommendation", verify)))
    if args.do_download:
        cases.append(Case("Download: roadmap", lambda: latest_download(args.base, args.api_key, "roadmap", args.save_dir, verify)))
        cases.append(Case("Download: recommendation", lambda: latest_download(args.base, args.api_key, "recommendation", args.save_dir, verify)))
    if args.do_upload_assets:
        cases.append(Case(f"Upload: assets ({os.path.basename(args.do_upload_assets)})", lambda: upload_zip(args.base, args.api_key, "assets", args.do_upload_assets, verify, args.tenant)))
    if args.do_upload_others:
        cases.append(Case(f"Upload: others ({os.path.basename(args.do_upload_others)})", lambda: upload_zip(args.base, args.api_key, "others", args.do_upload_others, verify, args.tenant)))

    if not cases:
        print("未指定动作。示例：--do-all 或 --do-info --do-download 等。-h 查看帮助。")
        return 1

    print("开始执行用例...\n")
    total, passed, results = run_cases(cases)

    # 汇总输出
    print("\n===== 测试汇总 =====")
    names = ", ".join([n for n, *_ in results])
    print(f"共计 {total} 条用例：{names}")
    for name, ok, err in results:
        mark = CHECK if ok else CROSS
        line = f"{mark} {name}"
        if not ok and err:
            line += f" | 错误：{err}"
        print(line)
    print(f"结果：{passed}/{total} 通过")
    print(f"日志：{args.log_file}")

    return 0 if passed == total else 2


if __name__ == "__main__":
    sys.exit(main())
