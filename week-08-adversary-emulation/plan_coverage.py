"""Week 8: parse the CALDERA adversary profile and measure detection coverage.

This is the "connective tissue" of the plan and the part that is genuinely ours:
it reads the real CALDERA profile + ability YAML files (not a hand-typed list),
walks them in atomic_ordering, and cross-references each step against the
project's existing Week 5 detection rule (powershell_rule.py). The output is a
coverage matrix that says, per ATT&CK technique, whether our assistant would
catch that phase of the emulated LummaC2 chain.

Runs with no installs and from any folder:
    python plan_coverage.py
- If PyYAML is present it is used; otherwise a tiny built-in reader parses these
  (simple) YAML files, so you do NOT need `pip install pyyaml`.
- It finds powershell_rule.py next to this file or in ../week-05-threat-hunting/;
  if neither exists it falls back to a bundled copy of the same logic, so the
  script always runs.
"""

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE = os.path.join(HERE, "emulation-plan", "lumma-endpoint.yml")
ABILITIES_DIR = os.path.join(HERE, "emulation-plan", "abilities")


# --------------------------------------------------------------------------
# 1. Load the Week 5 detection rule. Prefer the real file; fall back to a
#    bundled copy of check_powershell() so the script never dies on import.
# --------------------------------------------------------------------------
def _load_check_powershell():
    for cand in (HERE, os.path.join(HERE, "..", "week-05-threat-hunting")):
        if os.path.exists(os.path.join(cand, "powershell_rule.py")):
            sys.path.insert(0, cand)
            from powershell_rule import check_powershell  # type: ignore
            return check_powershell, "powershell_rule.py (Week 5)"

    # Bundled fallback — identical logic to Week 5's powershell_rule.py.
    import ntpath
    SUSP = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "chrome.exe", "msedge.exe", "firefox.exe"}
    enc_full = "encodedcommand"
    enc_forms = {enc_full[:i] for i in range(1, len(enc_full) + 1)} | {"ec"}
    enc_re = re.compile(r"(?:^|\s)[-/]([a-z]+)(?=\s|$)", re.IGNORECASE)
    exec_re = re.compile(r"\b(iex|invoke-expression|downloadstring)\b", re.IGNORECASE)
    hidden_re = re.compile(r"(?:^|\s)[-/]w\w*\s+hidden\b", re.IGNORECASE)

    def check_powershell(command_line, parent_image=""):
        reasons = []
        if any(m.lower() in enc_forms for m in enc_re.findall(command_line)):
            reasons.append("encoded command")
        if exec_re.search(command_line):
            reasons.append("IEX / Invoke-Expression / DownloadString")
        parent = ntpath.basename(parent_image).lower() if parent_image else ""
        if parent in SUSP:
            reasons.append(f"suspicious parent ({parent})")
        if reasons and hidden_re.search(command_line):
            reasons.append("hidden window")
        return {"flagged": bool(reasons), "reasons": reasons}

    return check_powershell, "bundled fallback copy"


# --------------------------------------------------------------------------
# 2. Read the YAML plan. Use PyYAML if installed, else a minimal parser that
#    handles exactly these files (ids, tactic, attack_id, executors, commands).
# --------------------------------------------------------------------------
def _load_yaml(path):
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        return _mini_yaml(path)


def _mini_yaml(path):
    """A tiny reader for the simple structure of these plan files."""
    with open(path) as f:
        lines = f.readlines()

    # Profile file: top-level mapping with an atomic_ordering list.
    text = "".join(lines)
    if "atomic_ordering:" in text and "technique:" not in text:
        order = []
        in_list = False
        for ln in lines:
            if re.match(r"^atomic_ordering:\s*$", ln):
                in_list = True
                continue
            if in_list:
                m = re.match(r"^\s*-\s*([0-9a-fA-F-]{36})", ln)
                if m:
                    order.append(m.group(1))
                elif ln.strip() and not ln.lstrip().startswith("#"):
                    break
        name = ""
        for ln in lines:
            m = re.match(r"^name:\s*(.+?)\s*$", ln)
            if m:
                name = m.group(1)
                break
        return {"name": name, "atomic_ordering": order}

    # Ability file: a one-item list with id/tactic/technique/executors.
    def grab(pattern):
        for ln in lines:
            m = re.search(pattern, ln)
            if m:
                return m.group(1).strip()
        return ""

    ability = {
        "id": grab(r"^\s*-?\s*id:\s*([0-9a-fA-F-]{36})"),
        "tactic": grab(r"^\s*tactic:\s*(\S+)"),
        "technique": {"attack_id": grab(r"^\s*attack_id:\s*(\S+)")},
    }
    # executor platform/name (we only need the executor name: psh / cmd)
    ex_name = ""
    seen_executors = False
    for ln in lines:
        if re.match(r"^\s*executors:", ln):
            seen_executors = True
        if seen_executors:
            m = re.match(r"^\s*name:\s*(\S+)", ln)
            if m:
                ex_name = m.group(1)
                break
    # command block under the executor
    cmd_lines, in_cmd, cmd_indent = [], False, None
    for ln in lines:
        if re.match(r"^\s*command:\s*\|\s*$", ln):
            in_cmd = True
            cmd_indent = None
            continue
        if in_cmd:
            if ln.strip() == "":
                continue
            indent = len(ln) - len(ln.lstrip())
            if cmd_indent is None:
                cmd_indent = indent
            if indent < cmd_indent or re.match(r"^\s*(cleanup|#|-)\s*", ln):
                in_cmd = False
            else:
                cmd_lines.append(ln.strip())
    ability["executors"] = [{"platform": "windows", "name": ex_name,
                             "command": "\n".join(cmd_lines)}]
    return [ability]


# --------------------------------------------------------------------------
# 3. Coverage logic.
# --------------------------------------------------------------------------
ATOMIC = {
    "T1059.001": "ART T1059.001 (PowerShell)",
    "T1547.001": "ART T1547.001 #1 Reg Key Run",
    "T1119": "ART T1005 / T1119 (local data)",
    "T1041": "ART T1041 / T1048 (exfil)",
}
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"


def load_abilities():
    by_id = {}
    for path in sorted(glob.glob(os.path.join(ABILITIES_DIR, "*.yml"))):
        doc = _load_yaml(path)
        for ab in (doc if isinstance(doc, list) else [doc]):
            by_id[ab["id"]] = ab
    return by_id


def windows_command(ability):
    for ex in ability.get("executors", []):
        if ex.get("platform") == "windows":
            return ex.get("name", ""), (ex.get("command") or "").strip()
    return "", ""


def main():
    check_powershell, rule_src = _load_check_powershell()
    profile = _load_yaml(PROFILE)
    abilities = load_abilities()

    print(f"Profile: {profile['name']}")
    print(f"Detection rule: {rule_src}")
    print(f"Steps in atomic_ordering: {len(profile['atomic_ordering'])}\n")
    header = f"{'ATT&CK':<12}{'Phase':<13}{'Executor':<9}{'PS rule?':<10}Cross-tool"
    print(header)
    print("-" * len(header))

    covered, ps_steps = 0, 0
    for ab_id in profile["atomic_ordering"]:
        ab = abilities.get(ab_id)
        if not ab:
            print(f"(missing ability file for {ab_id})")
            continue
        attack = ab["technique"]["attack_id"]
        tactic = ab["tactic"]
        ex_name, cmd = windows_command(ab)

        if ex_name == "psh":
            ps_steps += 1
            parent = WORD if attack == "T1059.001" else r"C:\Windows\explorer.exe"
            res = check_powershell(cmd, parent)
            verdict = "ALERT" if res["flagged"] else "no"
            covered += 1 if res["flagged"] else 0
        else:
            verdict = "blind"   # non-PowerShell (reg.exe) — rule never sees it

        print(f"{attack:<12}{tactic:<13}{ex_name or '-':<9}{verdict:<10}{ATOMIC.get(attack, '-')}")

    print("-" * len(header))
    print(f"PowerShell-execution steps the rule can inspect: {ps_steps} of {len(profile['atomic_ordering'])}")
    print(f"  of those, alerted on: {covered}")
    print("\nFinding: the existing detection is a PowerShell-execution rule, so it is")
    print("'blind' to the persistence (reg.exe) step and sees collection/exfiltration")
    print("only as benign cmdlets. Emulating the full initial-access -> persistence ->")
    print("exfiltration chain is what makes that blind spot visible (week8-work.md 8.6).")


if __name__ == "__main__":
    main()
