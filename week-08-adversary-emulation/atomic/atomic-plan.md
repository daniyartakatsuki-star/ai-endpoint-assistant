# Atomic Red Team runner — the same plan in a second, independent tool

The point of this file is deliberate: an emulation plan should not be welded to
one product. The same five phases authored as a CALDERA profile
(`emulation-plan/`) are expressed here as **Atomic Red Team** tests, so the plan
is portable and tool-agnostic. CALDERA is the orchestrated-agent view; Atomic
Red Team is the per-technique view a purple team uses to spot-check one control.

**Setup (once, in an elevated PowerShell on the lab VM):**

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

Each phase below follows the same three-command discipline — check prerequisites,
run, then clean up — so nothing is left on the machine:

| Phase | ATT&CK | Atomic test | Run |
| ----- | ------ | ----------- | --- |
| A2 Execution | T1059.001 | PowerShell download/execute tests | `Invoke-AtomicTest T1059.001 -ShowDetailsBrief` then pick a lab-safe test number |
| **A3 Persistence** | **T1547.001** | **Test #1 "Reg Key Run"** (GUID `e55be3fd-3521-4610-9d1a-e210e42dcf05`) | see below |
| A4 Collection | T1119 / T1005 | Data-from-local-system tests | `Invoke-AtomicTest T1005 -ShowDetailsBrief` |
| A5 Exfiltration | T1041 / T1048 | Exfil-over-protocol tests | `Invoke-AtomicTest T1048 -ShowDetailsBrief` |

**The persistence phase, end to end (the one the syllabus explicitly asks for):**

```powershell
# 1. Check prerequisites
Invoke-AtomicTest T1547.001 -TestNumbers 1 -CheckPrereqs

# 2. Execute — adds HKCU\...\Run "Atomic Red Team" value
Invoke-AtomicTest T1547.001 -TestNumbers 1

# 3. Verify it landed
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Atomic Red Team"

# 4. Clean up — removes the value
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

The underlying attack command (from the atomic) is exactly what our CALDERA
ability `a3-runkey-persistence.yml` runs:

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "#{command_to_execute}"
```

**Why two tools, not one:** running A3 in *both* CALDERA and Atomic Red Team and
confirming the **same** Sysmon Event ID 13 (registry set) appears proves the plan
is a property of the behavior, not of the tool — which is the whole idea behind
an ATT&CK-based emulation plan. It also directly answers the gap this week
exposes: the Week 5/7 PowerShell rule never sees A3 at all, because A3 is `reg.exe`,
not `powershell.exe`.
