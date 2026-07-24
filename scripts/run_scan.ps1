param(
  [Parameter(Mandatory=$true)][string]$Target,
  [string]$OutputJson = "outputs/result.json",
  [string]$OutputHtml = "outputs/report.html",
  [string]$OutputMarkdown = "outputs/report.md"
)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir
python .\firmware_scanner.py $Target -o $OutputJson --html $OutputHtml --markdown $OutputMarkdown
