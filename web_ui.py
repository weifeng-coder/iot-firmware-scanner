#!/usr/bin/env python3
"""标准库 Web UI：无需 Flask"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import firmware_scanner

PROJECT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_DIR / "outputs"
DEFAULT_JSON = OUTPUT_DIR / "result.json"
DEFAULT_HTML = OUTPUT_DIR / "report.html"
DEFAULT_MD = OUTPUT_DIR / "report.md"
CONFIG = PROJECT_DIR / "scanner_config.json"
LOCK = threading.Lock()
LAST_STATUS = {"state": "idle", "message": "等待扫描", "json": str(DEFAULT_JSON), "html": str(DEFAULT_HTML), "markdown": str(DEFAULT_MD)}


def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f7fb;color:#1f2937}}
header{{background:linear-gradient(135deg,#1d4ed8,#0f172a);color:white;padding:28px}}
main{{max-width:1080px;margin:24px auto;padding:0 18px}}.card{{background:white;border-radius:14px;box-shadow:0 8px 28px rgba(15,23,42,.08);padding:20px;margin-bottom:18px}}
input{{width:100%;box-sizing:border-box;padding:10px;border:1px solid #d1d5db;border-radius:8px;margin:6px 0 14px}}
button,.btn{{background:#1d4ed8;color:white;border:0;border-radius:8px;padding:10px 14px;text-decoration:none;display:inline-block;cursor:pointer}}
pre{{background:#0f172a;color:#d1e7ff;padding:12px;border-radius:10px;white-space:pre-wrap}}code{{color:#0f766e}}
</style></head><body><header><h1>{html.escape(title)}</h1><p>{firmware_scanner.APP_NAME} v{firmware_scanner.APP_VERSION}</p></header><main>{body}</main></body></html>""".encode("utf-8")


class ScannerHandler(BaseHTTPRequestHandler):
    def send_html(self, title: str, body: str, status: int = 200) -> None:
        content = page(title, body)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/report":
            self.show_report(parsed.query)
        elif parsed.path == "/status.json":
            with LOCK:
                data = json.dumps(LAST_STATUS, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.show_home()

    def do_POST(self) -> None:
        if self.path != "/scan":
            self.send_error(404)
            return
        form = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8"))
        target = form.get("target", [""])[0].strip()
        output_json = form.get("output_json", [str(DEFAULT_JSON)])[0].strip() or str(DEFAULT_JSON)
        output_html = form.get("output_html", [str(DEFAULT_HTML)])[0].strip() or str(DEFAULT_HTML)
        output_md = form.get("output_markdown", [str(DEFAULT_MD)])[0].strip() or str(DEFAULT_MD)
        if not target:
            self.send_html("参数错误", "<div class='card'>请填写固件文件或解包目录路径。</div>", 400)
            return
        try:
            with LOCK:
                LAST_STATUS.update({"state": "running", "message": f"正在扫描 {target}", "json": output_json, "html": output_html, "markdown": output_md})
            report = firmware_scanner.run_scan(target, output_json=output_json, output_html=output_html, output_markdown=output_md, config_path=str(CONFIG) if CONFIG.exists() else None)
            with LOCK:
                LAST_STATUS.update({"state": "done", "message": f"扫描完成，发现 {report['summary']['total_findings']} 处危险调用"})
            self.send_html("扫描完成", f"<div class='card'><h2>扫描完成</h2><p>发现 <strong>{report['summary']['total_findings']}</strong> 处危险调用。</p><p><a class='btn' href='/report?json={html.escape(output_json)}'>查看报告</a></p><p>JSON: <code>{html.escape(output_json)}</code></p><p>HTML: <code>{html.escape(output_html)}</code></p><p>Markdown: <code>{html.escape(output_md)}</code></p></div>")
        except Exception as exc:
            with LOCK:
                LAST_STATUS.update({"state": "error", "message": str(exc)})
            self.send_html("扫描失败", f"<div class='card'><h2>扫描失败</h2><pre>{html.escape(str(exc))}</pre></div>", 500)

    def show_home(self) -> None:
        with LOCK:
            status = dict(LAST_STATUS)
        body = f"""
<div class="card"><h2>启动扫描</h2>
<form method="post" action="/scan">
<label>固件文件或已解包目录路径</label><input name="target" placeholder="例如：../.. 或 /path/to/firmware.bin">
<label>JSON 输出路径</label><input name="output_json" value="{html.escape(str(DEFAULT_JSON))}">
<label>HTML 输出路径</label><input name="output_html" value="{html.escape(str(DEFAULT_HTML))}">
<label>Markdown 输出路径</label><input name="output_markdown" value="{html.escape(str(DEFAULT_MD))}">
<button type="submit">开始扫描</button></form></div>
<div class="card"><h2>当前状态</h2><pre>{html.escape(json.dumps(status, ensure_ascii=False, indent=2))}</pre><p><a class="btn" href="/report?json={html.escape(status.get('json', str(DEFAULT_JSON)))}">查看最近报告</a></p></div>
"""
        self.send_html("固件扫描 Web UI", body)

    def show_report(self, query: str) -> None:
        json_path = Path(parse_qs(query).get("json", [str(DEFAULT_JSON)])[0])
        if not json_path.exists():
            self.send_html("报告不存在", f"<div class='card'>找不到报告文件：<code>{html.escape(str(json_path))}</code></div>", 404)
            return
        data = json.loads(json_path.read_text(encoding="utf-8"))
        report = firmware_scanner.normalize_report_input(data, target=str(json_path))
        content = firmware_scanner.render_html_report(report).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="启动固件扫描 Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), ScannerHandler)
    print(f"Web UI 已启动: http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
