# IOT固件高危调用扫描工具 v1.0

这是一个面向软著申报材料整理的独立项目包，包含 CLI 扫描器、Web UI、结构化 JSON 报告、HTML 报告、Markdown 报告、配置文件、运行脚本和用户手册。

## 软件定位

本软件用于对 IoT 固件解包目录或固件镜像进行 ELF 文件识别，调用 radare2/r2pipe 分析危险函数引用，并按文件、风险等级、CGI/Web 相关性生成可读报告。

建议软著名称：

> IOT固件高危调用扫描工具 v1.0

## 目录结构

```text
software copyright/
├── firmware_scanner.py          # CLI 扫描器与报告生成核心
├── web_ui.py                    # 标准库 Web UI
├── scanner_config.json          # 扫描规则与风险等级配置
├── requirements.txt             # Python 依赖说明
├── README.md                    # 项目说明
├── docs/user_manual.md          # 用户手册/软著文档素材
├── scripts/run_scan.ps1         # Windows PowerShell 扫描脚本
├── scripts/run_web_ui.ps1       # Windows PowerShell Web UI 启动脚本
├── scripts/run_scan.sh          # Linux/macOS 扫描脚本
├── scripts/run_web_ui.sh        # Linux/macOS Web UI 启动脚本
├── tests/test_report_exports.py # 回归测试
└── outputs/                     # 默认报告输出目录
```

## 环境依赖

基础功能仅需要 Python 3.9+。

实际扫描 ELF 时建议安装：

```bash
pip install -r requirements.txt
```

系统工具：

- radare2
- binwalk（仅扫描固件镜像文件时需要；扫描已解包目录可不需要）

## CLI 使用

扫描已解包目录：

```bash
python firmware_scanner.py /path/to/squashfs-root \
  -o outputs/result.json \
  --html outputs/report.html \
  --markdown outputs/report.md
```

扫描固件镜像：

```bash
python firmware_scanner.py firmware.bin -o outputs/result.json --html outputs/report.html --markdown outputs/report.md
```

从旧版平铺 `result.json` 生成新版报告：

```bash
python firmware_scanner.py --from-json old_result.json -o outputs/result.json --html outputs/report.html --markdown outputs/report.md
```

## Web UI 使用

```bash
python web_ui.py --host 127.0.0.1 --port 8088
```

浏览器打开：

```text
http://127.0.0.1:8088
```

Web UI 支持：

- 输入固件文件或解包目录路径
- 设置 JSON/HTML/Markdown 输出路径
- 查看最近扫描状态
- 在线查看 HTML 报告

## 报告内容

新版 JSON 采用 `schema_version=2.0`，包含：

- 软件名称与版本
- 扫描目标、扫描根目录、生成时间
- ELF 文件数量、发现数量
- 风险等级统计
- 危险函数统计
- CGI/Web 相关文件统计
- Top 20 重点文件
- 按文件分组的详细发现
- 每个发现的编号、风险等级、函数名、地址、调用函数、反汇编上下文、伪代码上下文

## 测试

```bash
python -m unittest discover -s tests -p "test*.py"
```

## 软著材料建议

建议在软著材料中突出以下原创功能：

1. 固件 ELF 自动发现与目录过滤策略。
2. CGI/Web 相关二进制优先排序。
3. 危险函数规则配置与风险分级。
4. 按文件分组的结构化 JSON 报告。
5. HTML/Markdown 可视化报告生成。
6. 标准库 Web UI 扫描与报告查看功能。

第三方工具如 radare2、binwalk、r2pipe、python-magic 属于运行依赖，软件原创部分主要是扫描调度、规则配置、数据整理、报告结构和界面展示。
# iot-firmware-scanner
