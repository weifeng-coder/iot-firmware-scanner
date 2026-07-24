import json
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import firmware_scanner


def sample_findings():
    return [
        {
            "file": "./web/cgi-bin/login.cgi",
            "danger_function": "sprintf",
            "call_address": "0x401000",
            "caller_function": "sym.login",
            "disassembly_around_call": "jalr t9",
            "caller_decompiled": "sprintf(buf, user);",
        },
        {
            "file": "./bin/helper",
            "danger_function": "system",
            "call_address": "0x402000",
            "caller_function": "sym.run",
            "disassembly_around_call": "jalr t9",
            "caller_decompiled": "system(cmd);",
        },
    ]


class ReportExportTest(unittest.TestCase):
    def test_report_groups_findings_and_exports_html_markdown(self):
        report = firmware_scanner.build_report(
            sample_findings(),
            target="firmware-root",
            extract_root="firmware-root",
            elf_count=3,
        )

        self.assertEqual(report["schema_version"], "2.0")
        self.assertEqual(report["summary"]["total_findings"], 2)
        self.assertEqual(report["summary"]["risk_levels"], {"critical": 1, "high": 1})
        self.assertTrue(report["findings_by_file"][0]["is_cgi_related"])
        self.assertEqual(report["findings_by_file"][0]["findings"][0]["id"], "F-0001")

        html = firmware_scanner.render_html_report(report)
        markdown = firmware_scanner.render_markdown_report(report)

        self.assertIn("IOT固件高危调用扫描报告", html)
        self.assertIn("./web/cgi-bin/login.cgi", html)
        self.assertIn("# IOT固件高危调用扫描报告", markdown)
        self.assertIn("F-0002", markdown)

        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            out_json = out_dir / "result.json"
            out_html = out_dir / "result.html"
            out_md = out_dir / "result.md"
            firmware_scanner.write_outputs(report, json_path=out_json, html_path=out_html, markdown_path=out_md)

            self.assertEqual(json.loads(out_json.read_text(encoding="utf-8"))["summary"]["total_findings"], 2)
            self.assertIn("login.cgi", out_html.read_text(encoding="utf-8"))
            self.assertIn("system", out_md.read_text(encoding="utf-8"))

    def test_main_without_arguments_opens_menu_and_can_exit(self):
        stdout = io.StringIO()

        with patch("builtins.input", side_effect=["0"]), patch.object(sys, "stdout", stdout):
            exit_code = firmware_scanner.main([])

        self.assertEqual(exit_code, 0)
        self.assertIn("主菜单", stdout.getvalue())
        self.assertIn("IOT固件高危调用扫描工具 v1.0", stdout.getvalue())
        self.assertIn("退出", stdout.getvalue())

    def test_menu_help_returns_to_menu_until_exit(self):
        stdout = io.StringIO()

        with patch("builtins.input", side_effect=["4", "0"]), patch.object(sys, "stdout", stdout):
            exit_code = firmware_scanner.main([])

        self.assertEqual(exit_code, 0)
        self.assertIn("usage:", stdout.getvalue())
        self.assertGreaterEqual(stdout.getvalue().count("主菜单"), 2)

    def test_menu_accepts_first_non_space_character_from_piped_input(self):
        stdout = io.StringIO()

        with patch("builtins.input", side_effect=["0\\n"]), patch.object(sys, "stdout", stdout):
            exit_code = firmware_scanner.main([])

        self.assertEqual(exit_code, 0)
        self.assertNotIn("无效选项", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
