param(
  [string]$HostName = "127.0.0.1",
  [int]$Port = 8088
)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir
python .\web_ui.py --host $HostName --port $Port
