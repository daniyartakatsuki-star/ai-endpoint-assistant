# Week 8 — harmless "second stage" served by the lab C2 listener.
# It does nothing destructive: it prints a marker and lists a few process
# names so the Sysmon/Splunk telemetry has something benign to show.
# This mirrors the Week 6 test.ps1 ("Write-Output 'T1059.001 simulation OK'").

Write-Output "W8-STAGE2-OK: in-memory execution reached (emulation marker)"
Get-Process | Select-Object -First 3 Name, Id | Format-Table
