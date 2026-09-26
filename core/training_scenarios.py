"""
Blue Team Training Scenarios
Structured detection exercises based on real APT TTPs.
Each scenario describes observable indicators, log sources,
and analyst actions — no exploit code involved.
"""

from dataclasses import dataclass, field


@dataclass
class TrainingScenario:
    id: str
    title: str
    apt_group: str
    difficulty: str          # Beginner / Intermediate / Advanced
    tactic: str
    technique_id: str
    technique_name: str
    scenario_description: str
    observables: list[str]   # What the analyst sees in logs
    questions: list[str]     # Analyst decision points
    answers: list[str]       # Correct analysis steps
    mitigations: list[str]   # Defensive actions

    def to_dict(self) -> dict:
        return self.__dict__


SCENARIOS: list[TrainingScenario] = [
    TrainingScenario(
        id="sc-001",
        title="Spearphishing with Macro-Enabled Document",
        apt_group="APT28",
        difficulty="Beginner",
        tactic="initial-access",
        technique_id="T1566.001",
        technique_name="Phishing: Spearphishing Attachment",
        scenario_description=(
            "Your email gateway alerts on an inbound message to a finance employee. "
            "The email impersonates a vendor and contains a .docm attachment. "
            "The user opens the file. Shortly after, WinWord.exe spawns cmd.exe, "
            "which connects to an external IP on port 443."
        ),
        observables=[
            "Email from external domain registered 3 days ago",
            "Attachment: Invoice_Q4.docm (macro-enabled Word document)",
            "Process tree: OUTLOOK.EXE → WINWORD.EXE → CMD.EXE → powershell.exe -enc <base64>",
            "Outbound connection to 185.220.x.x:443 (TOR exit node)",
            "Sysmon Event ID 1: powershell.exe with encoded command",
            "Sysmon Event ID 3: network connection to foreign IP",
        ],
        questions=[
            "What is the initial delivery mechanism?",
            "Which Sysmon event IDs are most relevant to triage?",
            "What does the base64-encoded PowerShell command likely indicate?",
            "Is the outbound connection expected for a finance workstation?",
            "What should be your first containment action?",
        ],
        answers=[
            "Spearphishing via macro-enabled Office document (T1566.001).",
            "Sysmon EID 1 (process creation) and EID 3 (network connection). Also check EID 11 for file drops.",
            "Encoded PowerShell is a classic defense-evasion technique (T1027) — decode it with [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String(...)).",
            "No — finance workstations should not initiate raw outbound connections to TOR. This is a strong C2 indicator.",
            "Isolate the endpoint from the network immediately, preserve a memory image, then revoke the user's credentials.",
        ],
        mitigations=[
            "Block macro execution in Office via Group Policy (set to 'Disable all macros without notification').",
            "Enable Attack Surface Reduction rules in Defender (rule: Block Office applications from creating child processes).",
            "Implement email attachment sandboxing (e.g., Microsoft Defender for Office 365 Safe Attachments).",
            "Block outbound connections to TOR exit nodes at the firewall.",
            "Deploy PowerShell Constrained Language Mode and Script Block Logging.",
        ],
    ),

    TrainingScenario(
        id="sc-002",
        title="LSASS Memory Dump via ProcDump",
        apt_group="APT29",
        difficulty="Intermediate",
        tactic="credential-access",
        technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory",
        scenario_description=(
            "EDR alerts on a suspicious process accessing LSASS memory. "
            "A privileged user account ran procdump64.exe with '-ma lsass.exe' arguments. "
            "The resulting .dmp file was copied to a network share 10 minutes later."
        ),
        observables=[
            "Sysmon EID 10: SourceImage procdump64.exe → TargetImage lsass.exe (PROCESS_VM_READ)",
            "Command line: procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp",
            "Security EID 4656: handle request to lsass.exe from non-system process",
            "File creation: lsass.dmp in C:\\Windows\\Temp",
            "SMB copy of lsass.dmp to \\\\FILESERVER\\share$ 10 min later",
            "Account used: IT admin account last seen 2 weeks ago",
        ],
        questions=[
            "Why is LSASS the target of this attack?",
            "Which Windows event IDs indicate process handle abuse?",
            "What does the dormant admin account suggest?",
            "How would you confirm whether real credentials were extracted?",
            "What long-term defensive control would prevent this?",
        ],
        answers=[
            "LSASS holds credentials in memory (NTLM hashes, Kerberos tickets). Dumping it allows offline cracking or pass-the-hash attacks.",
            "Security EID 4656 (handle request) and Sysmon EID 10 (process access with PROCESS_VM_READ or PROCESS_ALL_ACCESS flags).",
            "Dormant privileged accounts are a common sign of prior compromise or insider threat — the attacker may have obtained these credentials earlier.",
            "Check subsequent logon events (4624) from new IPs using that account. Look for lateral movement within minutes of the dump.",
            "Enable Credential Guard (isolates LSASS into a VSM) and enforce MFA on all privileged accounts.",
        ],
        mitigations=[
            "Enable Windows Credential Guard via Hyper-V to protect LSASS in a virtualization-based security enclave.",
            "Configure PPL (Protected Process Light) for LSASS via registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa → RunAsPPL = 1.",
            "Block ProcDump and similar tools via application allowlisting (AppLocker or WDAC).",
            "Alert on any process opening PROCESS_VM_READ handle to lsass.exe from non-system processes.",
            "Rotate all privileged account credentials immediately and review dormant account lifecycle policy.",
        ],
    ),

    TrainingScenario(
        id="sc-003",
        title="Scheduled Task Persistence via schtasks.exe",
        apt_group="Lazarus Group",
        difficulty="Beginner",
        tactic="persistence",
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
        scenario_description=(
            "A threat hunt query reveals a scheduled task created on 47 endpoints "
            "within a 2-hour window. The task runs a PowerShell script from a user's "
            "AppData folder every 15 minutes. The task was created by a service account."
        ),
        observables=[
            "Windows EID 4698: Scheduled task created — TaskName: \\Microsoft\\Windows\\Update\\SvcHost",
            "Task action: powershell.exe -w hidden -ep bypass -f C:\\Users\\<user>\\AppData\\Roaming\\svchost.ps1",
            "Task trigger: every 15 minutes",
            "Created by: SVC_DEPLOY (service account)",
            "svchost.ps1 contains base64-encoded content",
            "47 endpoints affected within 120 minutes (lateral spread indicator)",
        ],
        questions=[
            "Why is AppData\\Roaming a common malware staging location?",
            "What does the '-ep bypass' flag tell you?",
            "What does the 47-endpoint spread in 2 hours suggest?",
            "How would you hunt for similar tasks across the environment?",
            "What account should be investigated first?",
        ],
        answers=[
            "AppData\\Roaming is writable by standard users without admin rights, making it a low-privilege persistence location that often evades application allowlisting.",
            "-ep bypass (ExecutionPolicy bypass) disables the default restriction on running unsigned scripts — a classic evasion indicator.",
            "The spread pattern suggests automated lateral movement via the compromised SVC_DEPLOY service account, likely using the account's network access to push the task via schtasks /s <remote_host>.",
            "Use Get-ScheduledTask or WMI query across endpoints; filter for tasks in \\Microsoft\\Windows\\* with non-standard actions (PowerShell, cmd, cscript).",
            "SVC_DEPLOY — it was used to create tasks on 47 hosts. Disable it, rotate its credentials, and audit all its recent activity.",
        ],
        mitigations=[
            "Alert on EID 4698 (task created) for tasks in user-writable directories or using scripting interpreters.",
            "Restrict service account privileges — SVC_DEPLOY should not have rights to create scheduled tasks remotely.",
            "Block PowerShell execution policy bypass via Group Policy: set execution policy to AllSigned.",
            "Monitor AppData\\Roaming for script files (*.ps1, *.vbs, *.js) via file integrity monitoring.",
            "Implement JIT/PAM for service accounts to limit their active session window.",
        ],
    ),

    TrainingScenario(
        id="sc-004",
        title="DNS Tunneling C2 Channel",
        apt_group="Turla",
        difficulty="Advanced",
        tactic="command-and-control",
        technique_id="T1071.004",
        technique_name="Application Layer Protocol: DNS",
        scenario_description=(
            "Network monitoring flags anomalous DNS query volume from a single workstation. "
            "The workstation is sending hundreds of queries per minute to a single external "
            "domain, with subdomains containing high-entropy strings up to 60 characters long. "
            "No corresponding HTTP/S traffic is observed."
        ),
        observables=[
            "DNS queries: a94f3b2e1c.d7e8f0a1b2.exfil-domain.com (60-char subdomain, base32-encoded)",
            "Query rate: ~400 queries/min (normal baseline: ~5/min)",
            "Domain registered 6 days ago via privacy proxy registrar",
            "No HTTP/S to same domain — traffic is DNS-only",
            "Workstation process: svchost.exe (PID 4832) → unusual for DNS volume this high",
            "TTL on responses: 0 seconds (prevents caching — C2 control signal)",
        ],
        questions=[
            "Why would an attacker use DNS for C2 rather than HTTPS?",
            "What makes the subdomain strings suspicious?",
            "How would you confirm DNS tunneling vs legitimate high-volume DNS?",
            "What endpoint artifact would confirm the implant?",
            "What detection rule would catch this pattern at scale?",
        ],
        answers=[
            "DNS is allowed through most firewalls and rarely inspected at the content level. It can exfiltrate data even in highly restricted network segments where HTTP/S is blocked.",
            "Legitimate subdomains are short and human-readable. High-entropy, long subdomains are characteristic of base32/base64-encoded data being sent as DNS queries (T1048 / T1071.004).",
            "Calculate subdomain entropy: run `echo <subdomain> | ent` or use Shannon entropy. >3.5 bits/char suggests encoding. Compare against baseline; also look for NX (non-existent) domain responses.",
            "Look for a DLL or executable in a suspicious location loaded by svchost.exe. Check Sysmon EID 7 (image loaded) and EID 1 (process create) for the parent of PID 4832.",
            "DNS SIEM rule: alert when a single host sends >50 unique subdomain queries to the same apex domain within 60 seconds, with average subdomain length >20 characters.",
        ],
        mitigations=[
            "Deploy DNS security (e.g., Cisco Umbrella, Cloudflare Gateway) to block newly-registered domains and high-entropy query patterns.",
            "Restrict DNS resolution to internal resolvers only — block direct outbound UDP/TCP 53 at the perimeter except from designated resolvers.",
            "Alert on anomalous DNS query volumes per host using UEBA baselines.",
            "Implement RPZ (Response Policy Zones) to block known malicious apex domains.",
            "Enable DNS over HTTPS (DoH) logging so encrypted DNS is visible to security monitoring.",
        ],
    ),
]


def get_all_scenarios() -> list[dict]:
    return [s.to_dict() for s in SCENARIOS]


def get_scenario(scenario_id: str) -> dict | None:
    for s in SCENARIOS:
        if s.id == scenario_id:
            return s.to_dict()
    return None


def get_scenarios_by_tactic(tactic: str) -> list[dict]:
    return [s.to_dict() for s in SCENARIOS if s.tactic == tactic]


def get_scenarios_by_difficulty(difficulty: str) -> list[dict]:
    return [s.to_dict() for s in SCENARIOS if s.difficulty.lower() == difficulty.lower()]
