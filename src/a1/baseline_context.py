"""Deterministic baseline and anomaly context for endpoint activities (Issue #10)."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

# Known administrative or system accounts
KNOWN_ADMIN_ACCOUNTS: Set[str] = {
    "administrator",
    "admin",
    "system",
    "local service",
    "network service",
    "svc-backup",
    "svc-deploy",
    "svc-monitor",
    "domain admin",
}

# Known management/infrastructure hosts
KNOWN_MANAGEMENT_HOSTS: Set[str] = {
    "dc-01",
    "dc-02",
    "srv-mgmt-01",
    "srv-mgmt-02",
    "admin-pc",
    "jumpbox-01",
}

# Normal parent -> child execution patterns in Windows enterprise environments
NORMAL_PARENT_CHILD: Dict[str, Set[str]] = {
    "explorer.exe": {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "chrome.exe",
        "msedge.exe",
        "notepad.exe",
        "calc.exe",
        "taskmgr.exe",
        "excel.exe",
        "winword.exe",
        "outlook.exe",
    },
    "services.exe": {
        "svchost.exe",
        "spoolsv.exe",
        "msmpeng.exe",
        "searchindexer.exe",
    },
    "wininit.exe": {
        "services.exe",
        "lsass.exe",
        "lsm.exe",
    },
    "svchost.exe": {
        "dllhost.exe",
        "werfault.exe",
        "backgroundtaskhost.exe",
        "wermgr.exe",
    },
    "smss.exe": {
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
    },
}

# Suspicious parent-child executions (e.g. web servers, database engines, or LSASS spawning shells)
SUSPICIOUS_PARENT_CHILD: Dict[str, Set[str]] = {
    "w3wp.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "whoami.exe"},
    "httpd.exe": {"cmd.exe", "powershell.exe", "sh.exe", "bash.exe"},
    "nginx.exe": {"cmd.exe", "powershell.exe", "sh.exe", "bash.exe"},
    "sqlservr.exe": {"cmd.exe", "powershell.exe", "pwsh.exe", "bitsadmin.exe"},
    "tomcat.exe": {"cmd.exe", "powershell.exe", "pwsh.exe"},
    "lsass.exe": {"cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"},
    "winlogon.exe": {"powershell.exe", "cmd.exe"},
}

# Known software updater binaries
NORMAL_UPDATER_PROCESSES: Set[str] = {
    "googleupdate.exe",
    "msedgeupdate.exe",
    "onedriveupdate.exe",
    "adobearm.exe",
    "usoclient.exe",
}


def is_known_admin_account(username: Optional[str]) -> bool:
    if not username:
        return False
    u = username.lower().strip()
    if u in KNOWN_ADMIN_ACCOUNTS:
        return True
    return any(u.startswith(prefix) for prefix in ("admin_", "adm-", "svc-", "sa_"))


def is_management_host(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    h = hostname.lower().strip()
    if h in KNOWN_MANAGEMENT_HOSTS:
        return True
    return any(h.startswith(prefix) for prefix in ("dc-", "srv-mgmt-", "jump-", "bastion-"))


def is_suspicious_parent_child(parent_name: Optional[str], child_name: Optional[str]) -> bool:
    if not parent_name or not child_name:
        return False
    p = parent_name.lower().strip()
    c = child_name.lower().strip()
    if p in SUSPICIOUS_PARENT_CHILD and c in SUSPICIOUS_PARENT_CHILD[p]:
        return True
    return False


def is_expected_parent_child(parent_name: Optional[str], child_name: Optional[str]) -> bool:
    if not parent_name or not child_name:
        return False
    p = parent_name.lower().strip()
    c = child_name.lower().strip()
    if p in NORMAL_PARENT_CHILD and c in NORMAL_PARENT_CHILD[p]:
        return True
    return False


def assess_activity_context(event: Dict[str, Any]) -> Dict[str, Any]:
    """Provide deterministic baseline context for an event/process."""
    reasons = []
    is_anomaly = False

    parent_name = event.get("parent_process_name") or event.get("parent_name")
    proc_name = event.get("process_name") or event.get("name") or event.get("image_path")
    user = event.get("user") or event.get("username")
    host = event.get("hostname") or event.get("host_name")

    if is_suspicious_parent_child(parent_name, proc_name):
        is_anomaly = True
        reasons.append(f"Suspicious execution: {parent_name} spawned shell/utility {proc_name}")

    if proc_name and proc_name.lower() in NORMAL_UPDATER_PROCESSES:
        reasons.append(f"Recognized legitimate updater binary: {proc_name}")

    is_admin = is_known_admin_account(user)
    is_mgmt = is_management_host(host)

    return {
        "is_anomaly": is_anomaly,
        "is_admin_account": is_admin,
        "is_management_host": is_mgmt,
        "context_notes": reasons,
    }
