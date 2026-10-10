"""Week 5: detection rule derived from the PowerShell threat hunt.

The rule works on a process-creation record (command line + parent image),
the same fields used in the Splunk hunt (Sysmon Event ID 1).

Run this file directly to validate the rule against the hunt data:
    python powershell_rule.py
"""

import ntpath
import re

# Parents that should rarely spawn PowerShell on a personal endpoint (phishing indicator)
SUSPICIOUS_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
}

# -EncodedCommand can be abbreviated (-e, -ec, -enc, ...), so match any prefix
_ENC_FULL = "encodedcommand"
_ENC_FORMS = {_ENC_FULL[:i] for i in range(1, len(_ENC_FULL) + 1)} | {"ec"}
_ENC_RE = re.compile(r"(?:^|\s)[-/]([a-z]+)(?=\s|$)", re.IGNORECASE)

# Execution / download-cradle keywords
_EXEC_RE = re.compile(r"\b(iex|invoke-expression|downloadstring)\b", re.IGNORECASE)

# Hidden window: -w hidden, -win hidden, -WindowStyle Hidden, ...
_HIDDEN_RE = re.compile(r"(?:^|\s)[-/]w\w*\s+hidden\b", re.IGNORECASE)


def check_powershell(command_line: str, parent_image: str = "") -> dict:
    """Return {'flagged': bool, 'reasons': [...]} for one PowerShell process creation."""
    reasons = []

    if any(m.lower() in _ENC_FORMS for m in _ENC_RE.findall(command_line)):
        reasons.append("encoded command")
    if _EXEC_RE.search(command_line):
        reasons.append("IEX / Invoke-Expression / DownloadString")
    parent = ntpath.basename(parent_image).lower() if parent_image else ""
    if parent in SUSPICIOUS_PARENTS:
        reasons.append(f"suspicious parent ({parent})")

    # A hidden window alone is NOT flagged (legitimate installers such as VS Code use it).
    # It only adds weight when another indicator is already present.
    if reasons and _HIDDEN_RE.search(command_line):
        reasons.append("hidden window")

    return {"flagged": bool(reasons), "reasons": reasons}


PS = r'"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"'
PS_PARENT = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# (label, source, command_line, parent_image, expected_flagged)
CASES = [
    ("Encoded whoami test", "hunt data",
     f"{PS} -NoProfile -WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkA", PS_PARENT, True),
    ("IEX Get-Date test", "hunt data",
     f"{PS} -NoProfile -Command \"IEX 'Get-Date'\"", PS_PARENT, True),
    ("Get-Process baseline", "hunt data",
     f"{PS} -Command \"Get-Process | Select-Object -First 5\"", PS_PARENT, False),
    ("Bare interactive shell", "hunt data",
     r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", "", False),
    ("VS Code Add-AppxPackage", "hunt data",
     f"{PS} -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass "
     "-Command \"Add-AppxPackage -Path 'C:\\Users\\PC\\AppData\\Local\\Programs\\Microsoft VS Code"
     "\\07f806f999\\appx\\code_x64.appx' -ExternalLocation 'C:\\Users\\PC\\AppData\\Local\\Programs"
     "\\Microsoft VS Code\\07f806f999\\appx'\"", "", False),
    ("VS Code Remove-AppxPackage", "hunt data",
     f"{PS} -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass "
     "-Command \"Remove-AppxPackage -Package 'Microsoft.VisualStudioCode_1.0.124.0_neutral__8wekyb3d8bbwe'\"",
     "", False),
    ("VS Code Get-AppxPackage", "hunt data",
     "powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass "
     "-Command \"Get-AppxPackage -Name 'Microsoft.VisualStudioCode' | Select-Object -ExpandProperty PackageFullName\"",
     "", False),
    ("Abbreviated -ec", "synthetic",
     "powershell.exe -NoProfile -ec dwBoAG8AYQBtAGkA", PS_PARENT, True),
    ("Out-File -Encoding", "synthetic",
     "powershell.exe -Command \"Get-Date | Out-File x.txt -Encoding utf8\"", PS_PARENT, False),
    ("Plain command from Word", "synthetic",
     "powershell.exe -Command \"Get-Date\"", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", True),
]


if __name__ == "__main__":
    ok = 0
    print(f"{'Case':<28}{'Source':<11}{'Flagged':<9}{'Expected':<10}Reasons")
    for label, source, cmd, parent, expected in CASES:
        result = check_powershell(cmd, parent)
        ok += result["flagged"] == expected
        print(f"{label:<28}{source:<11}{str(result['flagged']):<9}{str(expected):<10}{', '.join(result['reasons']) or '-'}")
    print(f"\n{ok}/{len(CASES)} cases behaved as expected")
