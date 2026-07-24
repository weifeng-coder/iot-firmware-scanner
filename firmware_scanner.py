#!/usr/bin/env python3
"""IOT固件高危调用扫描工具 v1.0."""

from __future__ import annotations

import argparse
import html
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

try:
    import magic  # type: ignore
except Exception:
    magic = None

try:
    import r2pipe  # type: ignore
except Exception:
    r2pipe = None

APP_NAME = "IOT固件高危调用扫描工具"
APP_VERSION = "1.0"
REPORT_TITLE = "IOT固件高危调用扫描报告"
SCHEMA_VERSION = "2.0"

DEFAULT_DANGEROUS_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
    "memcpy", "memmove", "system", "popen", "execve", "execvp", "read",
    "recv", "getopt", "strncpy",
]
DEFAULT_SKIP_DIRS = ["/lib/", "/lib32/", "/lib64/", "/usr/lib/", "/usr/lib32/", "/usr/lib64/"]
DEFAULT_CGI_INDICATORS = ["cgi-bin", "/cgi/", "/web/", "httpd", "lighttpd", "nginx", "boa", "uhttpd", ".cgi"]
DEFAULT_CRITICAL_FUNCTIONS = {"system", "popen", "execve", "execvp"}
DEFAULT_HIGH_RISK_FUNCTIONS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
    "memcpy", "memmove", "read", "recv",
}


def default_config() -> Dict[str, Any]:
    return {
        "dangerous_functions": list(DEFAULT_DANGEROUS_FUNCTIONS),
        "skip_dirs": list(DEFAULT_SKIP_DIRS),
        "cgi_indicators": list(DEFAULT_CGI_INDICATORS),
        "risk": {
            "critical": sorted(DEFAULT_CRITICAL_FUNCTIONS),
            "high": sorted(DEFAULT_HIGH_RISK_FUNCTIONS),
        },
        "scan": {"prefer_cgi": True, "radare2_analysis_command": "aaa", "disassembly_instruction_count": 10},
    }


def deep_update(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), dict):
            deep_update(base[key], value)  # type: ignore[index]
        else:
            base[key] = value
    return base


def load_config(path: Optional[os.PathLike[str] | str]) -> Dict[str, Any]:
    cfg = default_config()
    if not path:
        return cfg
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"配置文件不存在: {p}")
    return deep_update(cfg, json.loads(p.read_text(encoding="utf-8")))


def normalized_path(path: os.PathLike[str] | str) -> str:
    return str(path).replace("\\", "/")


def is_elf(filepath: os.PathLike[str] | str) -> bool:
    path = str(filepath)
    try:
        if magic is not None:
            return "ELF" in magic.from_file(path)
    except Exception:
        pass
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def is_cgi_related(path: os.PathLike[str] | str, config: Optional[Mapping[str, Any]] = None) -> bool:
    cfg = config or default_config()
    lower = normalized_path(path).lower()
    return any(str(indicator).lower() in lower for indicator in cfg.get("cgi_indicators", DEFAULT_CGI_INDICATORS))


def find_elf_files(root_dir: os.PathLike[str] | str, config: Optional[Mapping[str, Any]] = None) -> List[str]:
    cfg = config or default_config()
    skip_dirs = [normalized_path(item) for item in cfg.get("skip_dirs", DEFAULT_SKIP_DIRS)]
    elf_files: List[str] = []
    for dirpath, _, filenames in os.walk(root_dir):
        normalized_dir = normalized_path(dirpath) + "/"
        if any(skip in normalized_dir for skip in skip_dirs):
            continue
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if os.path.isfile(full) and is_elf(full):
                elf_files.append(full)
    return elf_files


def prioritize_cgi(elf_list: Iterable[str], config: Optional[Mapping[str, Any]] = None) -> List[str]:
    cfg = config or default_config()
    if not cfg.get("scan", {}).get("prefer_cgi", True):
        return list(elf_list)
    cgi_files, normal_files = [], []
    for path in elf_list:
        (cgi_files if is_cgi_related(path, cfg) else normal_files).append(path)
    return cgi_files + normal_files


def extract_firmware(firmware_path: os.PathLike[str] | str, extract_to: os.PathLike[str] | str) -> str:
    os.makedirs(extract_to, exist_ok=True)
    subprocess.run(["binwalk", "-e", "--directory", str(extract_to), str(firmware_path)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for item in os.listdir(extract_to):
        item_path = os.path.join(extract_to, item)
        if os.path.isdir(item_path) and "extracted" in item:
            return item_path
    return str(extract_to)


def analyze_binary(filepath: os.PathLike[str] | str, config: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
    if r2pipe is None:
        raise RuntimeError("缺少 r2pipe。请先执行: pip install r2pipe，并确保 radare2 在 PATH 中。")
    cfg = config or default_config()
    dangerous_functions = cfg.get("dangerous_functions", DEFAULT_DANGEROUS_FUNCTIONS)
    analysis_command = cfg.get("scan", {}).get("radare2_analysis_command", "aaa")
    asm_count = int(cfg.get("scan", {}).get("disassembly_instruction_count", 10))
    results: List[Dict[str, Any]] = []
    r2 = None
    try:
        r2 = r2pipe.open(str(filepath), flags=["-2"])
        r2.cmd(analysis_command)
        dec_available = False
        try:
            r2.cmd("pdg?")
            dec_available = True
        except Exception:
            pass
        for func in dangerous_functions:
            xrefs = r2.cmdj(f"axtj sym.imp.{func}") or []
            if not xrefs:
                xrefs = r2.cmdj(f"axtj {func}") or []
            for xref in xrefs:
                addr = xref.get("from")
                if addr is None:
                    continue
                caller_func = xref.get("name")
                if not caller_func:
                    finfo = r2.cmdj(f"afij {addr}") or [{}]
                    caller_func = finfo[0].get("name", f"fcn.{addr:x}" if isinstance(addr, int) else f"fcn.{addr}")
                try:
                    pseudo_c = r2.cmd(f"pdg @ {caller_func}") if dec_available else r2.cmd(f"pdc @ {caller_func}")
                except Exception:
                    pseudo_c = "// decompilation failed"
                results.append({
                    "file": str(filepath),
                    "danger_function": str(func),
                    "call_address": f"0x{addr:x}" if isinstance(addr, int) else str(addr),
                    "caller_function": caller_func,
                    "disassembly_around_call": r2.cmd(f"pd {asm_count} @ {addr}").strip(),
                    "caller_decompiled": pseudo_c.strip(),
                })
    except Exception as exc:
        print(f"[!] 分析 {filepath} 出错: {exc}", file=sys.stderr)
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass
    return results


def classify_risk(danger_function: str, config: Optional[Mapping[str, Any]] = None) -> str:
    cfg = config or default_config()
    risk_cfg = cfg.get("risk", {})
    if danger_function in set(risk_cfg.get("critical", DEFAULT_CRITICAL_FUNCTIONS)):
        return "critical"
    if danger_function in set(risk_cfg.get("high", DEFAULT_HIGH_RISK_FUNCTIONS)):
        return "high"
    return "medium"


def sorted_counter(counter: Counter) -> Dict[str, int]:
    return {key: count for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))}


def compact_finding(raw: Mapping[str, Any], finding_id: str, config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    danger_function = str(raw.get("danger_function", "unknown"))
    return {
        "id": finding_id,
        "risk": classify_risk(danger_function, config),
        "danger_function": danger_function,
        "call_address": raw.get("call_address"),
        "caller_function": raw.get("caller_function"),
        "context": {
            "disassembly_around_call": raw.get("disassembly_around_call", ""),
            "caller_decompiled": raw.get("caller_decompiled", ""),
        },
    }


def build_report(raw_findings: Sequence[Mapping[str, Any]], *, target: str, extract_root: str, elf_count: int, config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    cfg = config or default_config()
    grouped: "OrderedDict[str, List[Mapping[str, Any]]]" = OrderedDict()
    risk_counter, function_counter = Counter(), Counter()
    for raw in raw_findings:
        file_path = str(raw.get("file", "<unknown>"))
        grouped.setdefault(file_path, []).append(raw)
        function_name = str(raw.get("danger_function", "unknown"))
        function_counter[function_name] += 1
        risk_counter[classify_risk(function_name, cfg)] += 1
    findings_by_file, next_id = [], 1
    for file_path, file_findings in grouped.items():
        compact_findings = []
        for raw in file_findings:
            compact_findings.append(compact_finding(raw, f"F-{next_id:04d}", cfg))
            next_id += 1
        per_file_counter = Counter(str(raw.get("danger_function", "unknown")) for raw in file_findings)
        per_file_risk_counter = Counter(item["risk"] for item in compact_findings)
        findings_by_file.append({
            "file": file_path,
            "is_cgi_related": is_cgi_related(file_path, cfg),
            "finding_count": len(file_findings),
            "risk_levels": sorted_counter(per_file_risk_counter),
            "dangerous_functions": sorted_counter(per_file_counter),
            "findings": compact_findings,
        })
    top_files = [{
        "file": item["file"],
        "finding_count": item["finding_count"],
        "is_cgi_related": item["is_cgi_related"],
        "risk_levels": item["risk_levels"],
        "dangerous_functions": item["dangerous_functions"],
    } for item in sorted(findings_by_file, key=lambda item: (not item["is_cgi_related"], -item["finding_count"], item["file"]))[:20]]
    return {
        "schema_version": SCHEMA_VERSION,
        "software": {"name": APP_NAME, "version": APP_VERSION},
        "scan": {
            "target": target,
            "extract_root": extract_root,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "analyzed_elf_count": elf_count,
            "finding_count": len(raw_findings),
        },
        "summary": {
            "total_findings": len(raw_findings),
            "affected_file_count": len(grouped),
            "cgi_related_file_count": sum(1 for path in grouped if is_cgi_related(path, cfg)),
            "risk_levels": sorted_counter(risk_counter),
            "dangerous_functions": sorted_counter(function_counter),
            "top_files": top_files,
        },
        "findings_by_file": findings_by_file,
    }


def normalize_report_input(data: Any, *, target: str = "imported-json", config: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    if isinstance(data, dict) and data.get("schema_version") == SCHEMA_VERSION and "findings_by_file" in data:
        return data
    if isinstance(data, list):
        return build_report(data, target=target, extract_root=".", elf_count=-1, config=config)
    raise ValueError("输入 JSON 必须是旧版 finding 数组，或 schema_version=2.0 的报告对象。")


def render_html_report(report: Mapping[str, Any]) -> str:
    summary, scan = report.get("summary", {}), report.get("scan", {})

    def esc(value: Any) -> str:
        return html.escape(str(value if value is not None else ""))

    top_rows = "".join(
        f"<tr><td>{esc(i.get('file'))}</td><td>{i.get('finding_count', 0)}</td><td>{'是' if i.get('is_cgi_related') else '否'}</td><td><code>{esc(i.get('dangerous_functions'))}</code></td></tr>"
        for i in summary.get("top_files", [])
    )
    sections = []
    for file_item in report.get("findings_by_file", []):
        rows = []
        for finding in file_item.get("findings", []):
            ctx = finding.get("context", {})
            risk = esc(finding.get("risk"))
            rows.append(f"""<details class="finding {risk}"><summary>{esc(finding.get('id'))} <span class="badge badge-{risk}">{risk}</span> <strong>{esc(finding.get('danger_function'))}</strong> @ <code>{esc(finding.get('call_address'))}</code> in <code>{esc(finding.get('caller_function'))}</code></summary><h4>反汇编上下文</h4><pre>{esc(ctx.get('disassembly_around_call'))}</pre><h4>伪代码上下文</h4><pre>{esc(ctx.get('caller_decompiled'))}</pre></details>""")
        sections.append(f"""<section class="file-card"><h3>{esc(file_item.get('file'))}</h3><p>发现数：<strong>{file_item.get('finding_count', 0)}</strong>；CGI/Web 相关：<strong>{'是' if file_item.get('is_cgi_related') else '否'}</strong></p><p>风险：<code>{esc(file_item.get('risk_levels'))}</code></p><p>函数：<code>{esc(file_item.get('dangerous_functions'))}</code></p>{''.join(rows)}</section>""")
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>{REPORT_TITLE}</title><style>body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;background:#f5f7fb;color:#1f2937}}header{{background:linear-gradient(135deg,#1d4ed8,#0f172a);color:white;padding:32px}}main{{max-width:1180px;margin:24px auto;padding:0 18px}}.card,.file-card{{background:white;border-radius:14px;box-shadow:0 8px 28px rgba(15,23,42,.08);padding:20px;margin-bottom:20px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}.metric{{background:#eff6ff;border-radius:12px;padding:16px}}.metric b{{display:block;font-size:28px;color:#1d4ed8}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}}pre{{white-space:pre-wrap;background:#0f172a;color:#d1e7ff;padding:12px;border-radius:10px;overflow-x:auto}}.badge{{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;color:white}}.badge-critical{{background:#dc2626}}.badge-high{{background:#ea580c}}.badge-medium{{background:#ca8a04}}.finding{{border:1px solid #e5e7eb;border-radius:10px;padding:10px;margin:10px 0}}code{{color:#0f766e}}</style></head><body><header><h1>{REPORT_TITLE}</h1><p>{esc(report.get('software', {}).get('name', APP_NAME))} v{esc(report.get('software', {}).get('version', APP_VERSION))}</p></header><main><section class="card"><h2>扫描摘要</h2><div class="grid"><div class="metric">发现总数<b>{summary.get('total_findings', 0)}</b></div><div class="metric">受影响文件<b>{summary.get('affected_file_count', 0)}</b></div><div class="metric">CGI/Web 文件<b>{summary.get('cgi_related_file_count', 0)}</b></div><div class="metric">ELF 数量<b>{scan.get('analyzed_elf_count', 0)}</b></div></div><p>目标：<code>{esc(scan.get('target'))}</code></p><p>解包/扫描根目录：<code>{esc(scan.get('extract_root'))}</code></p><p>生成时间：<code>{esc(scan.get('generated_at'))}</code></p><p>风险统计：<code>{esc(summary.get('risk_levels'))}</code></p><p>函数统计：<code>{esc(summary.get('dangerous_functions'))}</code></p></section><section class="card"><h2>重点文件 Top 20</h2><table><thead><tr><th>文件</th><th>发现数</th><th>CGI/Web</th><th>危险函数</th></tr></thead><tbody>{top_rows}</tbody></table></section>{''.join(sections)}</main></body></html>"""


def render_markdown_report(report: Mapping[str, Any]) -> str:
    summary, scan = report.get("summary", {}), report.get("scan", {})
    lines = [
        f"# {REPORT_TITLE}", "",
        f"- 软件名称：{report.get('software', {}).get('name', APP_NAME)}",
        f"- 软件版本：{report.get('software', {}).get('version', APP_VERSION)}",
        f"- 扫描目标：`{scan.get('target')}`",
        f"- 扫描根目录：`{scan.get('extract_root')}`",
        f"- 生成时间：`{scan.get('generated_at')}`",
        f"- ELF 数量：{scan.get('analyzed_elf_count')}",
        f"- 发现总数：{summary.get('total_findings')}",
        f"- 受影响文件数：{summary.get('affected_file_count')}",
        f"- CGI/Web 相关文件数：{summary.get('cgi_related_file_count')}", "",
        "## 风险统计", "", f"```json\n{json.dumps(summary.get('risk_levels', {}), ensure_ascii=False, indent=2)}\n```", "",
        "## 危险函数统计", "", f"```json\n{json.dumps(summary.get('dangerous_functions', {}), ensure_ascii=False, indent=2)}\n```", "",
        "## 重点文件 Top 20", "", "| 文件 | 发现数 | CGI/Web | 危险函数 |", "|---|---:|---|---|",
    ]
    for item in summary.get("top_files", []):
        lines.append(f"| `{item.get('file')}` | {item.get('finding_count')} | {'是' if item.get('is_cgi_related') else '否'} | `{item.get('dangerous_functions')}` |")
    lines.extend(["", "## 详细发现", ""])
    for file_item in report.get("findings_by_file", []):
        lines.extend([f"### `{file_item.get('file')}`", "", f"- 发现数：{file_item.get('finding_count')}", f"- CGI/Web 相关：{'是' if file_item.get('is_cgi_related') else '否'}", f"- 风险分布：`{file_item.get('risk_levels')}`", f"- 函数分布：`{file_item.get('dangerous_functions')}`", ""])
        for finding in file_item.get("findings", []):
            ctx = finding.get("context", {})
            lines.extend([f"#### {finding.get('id')} [{finding.get('risk')}] `{finding.get('danger_function')}`", "", f"- 地址：`{finding.get('call_address')}`", f"- 调用函数：`{finding.get('caller_function')}`", "", "反汇编上下文：", "```asm", str(ctx.get("disassembly_around_call", "")), "```", "", "伪代码上下文：", "```c", str(ctx.get("caller_decompiled", "")), "```", ""])
    return "\n".join(lines)


def write_outputs(report: Mapping[str, Any], *, json_path: os.PathLike[str] | str, html_path: Optional[os.PathLike[str] | str] = None, markdown_path: Optional[os.PathLike[str] | str] = None) -> None:
    json_file = Path(json_path)
    json_file.parent.mkdir(parents=True, exist_ok=True)
    json_file.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if html_path:
        html_file = Path(html_path)
        html_file.parent.mkdir(parents=True, exist_ok=True)
        html_file.write_text(render_html_report(report), encoding="utf-8")
    if markdown_path:
        md_file = Path(markdown_path)
        md_file.parent.mkdir(parents=True, exist_ok=True)
        md_file.write_text(render_markdown_report(report), encoding="utf-8")


def run_scan(target: str, *, output_json: str, output_html: Optional[str] = None, output_markdown: Optional[str] = None, config_path: Optional[str] = None) -> Dict[str, Any]:
    config = load_config(config_path)
    temp_dir = tempfile.mkdtemp(prefix="fwscan_")
    try:
        if os.path.isfile(target):
            print(f"[*] 检测到固件文件，开始解包: {target}")
            extract_root = extract_firmware(target, temp_dir)
            print(f"[*] 解包完成: {extract_root}")
        else:
            extract_root = target
        elf_list = prioritize_cgi(find_elf_files(extract_root, config), config)
        print(f"[*] 找到 {len(elf_list)} 个 ELF 文件，开始扫描危险函数引用")
        all_findings: List[Dict[str, Any]] = []
        for index, elf_path in enumerate(elf_list, 1):
            print(f"[{index}/{len(elf_list)}] {elf_path}")
            all_findings.extend(analyze_binary(elf_path, config))
        report = build_report(all_findings, target=target, extract_root=extract_root, elf_count=len(elf_list), config=config)
        write_outputs(report, json_path=output_json, html_path=output_html, markdown_path=output_markdown)
        return report
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("target", nargs="?", help="固件镜像文件、已解包固件目录，或配合 --from-json 使用时可省略")
    parser.add_argument("-o", "--output", default="outputs/result.json", help="输出 JSON 路径")
    parser.add_argument("--html", default="outputs/report.html", help="输出 HTML 报告路径；传空字符串可关闭")
    parser.add_argument("--markdown", default="outputs/report.md", help="输出 Markdown 报告路径；传空字符串可关闭")
    parser.add_argument("--config", default="scanner_config.json", help="扫描配置文件路径")
    parser.add_argument("--from-json", help="从旧版 finding 数组或新版 JSON 报告生成 HTML/Markdown，不执行扫描")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} v{APP_VERSION}")
    return parser


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    return parser.parse_args(argv)


def prompt_with_default(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def print_main_menu() -> None:
    print()
    print("=" * 60)
    print(f"{APP_NAME} v{APP_VERSION} 主菜单")
    print("=" * 60)
    print("1. 扫描固件文件或已解包目录")
    print("2. 从已有 JSON 结果生成报告")
    print("3. 查看当前扫描配置")
    print("4. 显示命令行帮助")
    print("0. 退出")


def interactive_menu() -> int:
    while True:
        print_main_menu()
        try:
            raw_choice = input("请选择功能编号: ").strip()
            choice = raw_choice[:1]
        except (EOFError, KeyboardInterrupt):
            print("\n已退出。")
            return 0

        if choice == "0":
            print("已退出。")
            return 0
        if choice == "1":
            target = input("请输入固件文件或解包目录路径: ").strip()
            if not target:
                print("[!] 扫描目标不能为空。")
                continue
            output_json = prompt_with_default("JSON 输出路径", "outputs/result.json")
            output_html = prompt_with_default("HTML 报告路径，留空使用默认值", "outputs/report.html")
            output_markdown = prompt_with_default("Markdown 报告路径，留空使用默认值", "outputs/report.md")
            config_path = prompt_with_default("配置文件路径", "scanner_config.json")
            try:
                report = run_scan(
                    target,
                    output_json=output_json,
                    output_html=output_html or None,
                    output_markdown=output_markdown or None,
                    config_path=config_path if Path(config_path).exists() else None,
                )
                print(f"[+] 扫描完成：{output_json}，发现 {report['summary']['total_findings']} 处危险调用")
            except Exception as exc:
                print(f"[!] 执行失败: {exc}", file=sys.stderr)
        elif choice == "2":
            json_path = input("请输入已有 JSON 文件路径: ").strip()
            if not json_path:
                print("[!] JSON 文件路径不能为空。")
                continue
            output_json = prompt_with_default("规范化 JSON 输出路径", "outputs/result.json")
            output_html = prompt_with_default("HTML 报告路径，留空使用默认值", "outputs/report.html")
            output_markdown = prompt_with_default("Markdown 报告路径，留空使用默认值", "outputs/report.md")
            config_path = prompt_with_default("配置文件路径", "scanner_config.json")
            try:
                config = load_config(config_path if Path(config_path).exists() else None)
                data = json.loads(Path(json_path).read_text(encoding="utf-8"))
                report = normalize_report_input(data, target=json_path, config=config)
                write_outputs(report, json_path=output_json, html_path=output_html or None, markdown_path=output_markdown or None)
                print(f"[+] 已从 JSON 生成报告: {output_json}")
            except Exception as exc:
                print(f"[!] 执行失败: {exc}", file=sys.stderr)
        elif choice == "3":
            config_path = prompt_with_default("配置文件路径", "scanner_config.json")
            try:
                config = load_config(config_path if Path(config_path).exists() else None)
                print(json.dumps(config, ensure_ascii=False, indent=2))
            except Exception as exc:
                print(f"[!] 读取配置失败: {exc}", file=sys.stderr)
        elif choice == "4":
            build_parser().print_help()
        else:
            print("[!] 无效选项，请重新输入。")


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if not raw_args:
        return interactive_menu()

    args = parse_args(raw_args)
    html_path = args.html or None
    markdown_path = args.markdown or None
    try:
        config = load_config(args.config if args.config and Path(args.config).exists() else None)
        if args.from_json:
            data = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
            report = normalize_report_input(data, target=args.from_json, config=config)
            write_outputs(report, json_path=args.output, html_path=html_path, markdown_path=markdown_path)
            print(f"[+] 已从 JSON 生成报告: {args.output}")
            return 0
        if not args.target:
            print("缺少 target。用法: python firmware_scanner.py <固件文件或目录>", file=sys.stderr)
            return 2
        report = run_scan(args.target, output_json=args.output, output_html=html_path, output_markdown=markdown_path, config_path=args.config if Path(args.config).exists() else None)
        print(f"[+] 扫描完成：{args.output}，发现 {report['summary']['total_findings']} 处危险调用")
        return 0
    except Exception as exc:
        print(f"[!] 执行失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
