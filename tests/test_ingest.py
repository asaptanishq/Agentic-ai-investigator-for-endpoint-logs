"""Tests for turning Wazuh/Suricata log exports into telemetry databases."""
import json
import sqlite3
from pathlib import Path

import pytest

from a1.db import EndpointDatabase
from a1.ingest import IngestError, ingest_bytes, ingest_file, ingest_merged, scenario_stem


SURICATA_EVENTS = [
    {
        "timestamp": "2026-09-10T08:05:00.123456+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "src_port": 50000,
        "dest_ip": "10.0.0.9",
        "dest_port": 445,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature_id": 2027865,
            "signature": "ET MALWARE SMB",
            "category": "A Network Trojan",
            "severity": 1,
        },
    },
    {
        "timestamp": "2026-09-10T08:06:00+0000",
        "event_type": "flow",
        "src_ip": "10.0.0.5",
        "src_port": 50001,
        "dest_ip": "10.0.0.10",
        "dest_port": 80,
        "proto": "TCP",
        "flow": {"state": "established"},
    },
]

WAZUH_EVENTS = [
    {
        "@timestamp": "2026-09-10T08:07:00.000Z",
        "agent": {"name": "host-a01"},
        "rule": {
            "id": "92052",
            "level": 10,
            "description": "Suspicious powershell",
            "groups": ["windows", "powershell", "sysmon_event_1"],
        },
        "data": {
            "win": {
                "eventdata": {
                    "processGuid": "{abc}",
                    "processId": "1234",
                    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "commandLine": "powershell -enc x",
                    "parentProcessId": "1",
                    "parentImage": r"C:\Windows\explorer.exe",
                    "user": "alice",
                }
            }
        },
    }
]


def test_suricata_jsonl_builds_queryable_database(tmp_path):
    source = tmp_path / "eve.jsonl"
    source.write_text("\n".join(json.dumps(item) for item in SURICATA_EVENTS), encoding="utf-8")
    result = ingest_file(source)

    assert result["source"] == "suricata"
    assert result["format"] == "jsonl"
    assert result["rows"] == 2
    assert Path(result["path"]).is_file()

    conn = sqlite3.connect(result["path"])
    try:
        rows = conn.execute(
            "SELECT event_id, timestamp, provider, event_code, event_type, severity FROM events ORDER BY timestamp"
        ).fetchall()
        assert len(rows) == 2
        assert rows[0][1] == "2026-09-10T08:05:00.123456Z"
        assert rows[0][2:5] == ("Suricata", "2027865", "alert")
        assert rows[0][5] == 9
        schema = json.loads(conn.execute("SELECT value FROM ingest_meta WHERE key='schema'").fetchone()[0])
    finally:
        conn.close()
    fields = {field["path"] for field in schema["fields"]}
    assert {"alert.signature_id", "src_ip", "dest_ip"}.issubset(fields)

    db = EndpointDatabase(Path(result["path"]))
    try:
        network = db.execute_query("SELECT source_ip, destination_ip, protocol FROM network_connections")
        assert {row["source_ip"] for row in network} == {"10.0.0.5"}
        assert {row["protocol"] for row in network} == {"tcp"}
    finally:
        db.close()


def test_wazuh_json_array_maps_canonical_and_process_fields(tmp_path):
    source = tmp_path / "wazuh-alerts.json"
    source.write_text(json.dumps(WAZUH_EVENTS), encoding="utf-8")
    result = ingest_file(source)

    assert result["source"] == "wazuh"
    assert result["format"] == "json"

    db = EndpointDatabase(Path(result["path"]))
    try:
        event = db.execute_query("SELECT * FROM events")[0]
        assert event["provider"] == "Wazuh"
        assert event["event_code"] == "92052"
        assert event["severity"] == 10
        assert event["host_id"] == "host-a01"
        assert event["user_id"] == "alice"
        assert event["process_entity_id"] == "{abc}"
        assert "powershell" in event["category"]

        process = db.execute_query("SELECT * FROM processes")[0]
        assert process["process_name"] == "powershell.exe"
        assert process["command_line"] == "powershell -enc x"
        assert process["parent_process_name"] == "explorer.exe"
    finally:
        db.close()


def test_wazuh_agent_id_and_relayed_network_fields(tmp_path):
    record = {
        "@timestamp": "2022-01-14T00:00:09.728Z",
        "agent": {"name": "wazuh-client", "id": "30", "ip": "10.229.0.4"},
        "rule": {"id": "86601", "level": 3, "description": "Suricata alert", "groups": ["ids", "suricata"]},
        "data": {
            "srcip": "192.168.104.218",
            "dstip": "192.168.104.1:53",
            "proto": "UDP",
        },
    }
    result = ingest_bytes(json.dumps([record]).encode("utf-8"), "santos_wazuh.json", tmp_path / "santos.db")

    assert result["source"] == "wazuh"
    db = EndpointDatabase(Path(result["path"]))
    try:
        events = db.execute_query("SELECT host_id, event_code, category FROM events")
        assert events == [{"host_id": "wazuh-client-30", "event_code": "86601", "category": "ids,suricata"}]
        host = db.execute_query(
            "SELECT ip_address FROM hosts WHERE host_id = 'wazuh-client-30'"
        )[0]
        assert host["ip_address"] == "10.229.0.4"
        network = db.execute_query(
            "SELECT source_ip, source_port, destination_ip, destination_port, protocol FROM network_connections"
        )
        assert network == [{
            "source_ip": "192.168.104.218",
            "source_port": None,
            "destination_ip": "192.168.104.1",
            "destination_port": 53,
            "protocol": "udp",
        }]
    finally:
        db.close()


def test_wazuh_fast_log_keeps_signature_and_priority(tmp_path):
    record = {
        "@timestamp": "2022-01-14T00:00:23.976Z",
        "agent": {"name": "wazuh-client", "id": "24"},
        "rule": {"id": "20101", "level": 6, "description": "IDS event.", "groups": ["ids"]},
        "data": {"srcip": "172.21.128.119", "dstip": "91.189.88.142:80"},
        "full_log": "01/14/2022-00:00:23.976694  [**] [1:2013504:6] ET POLICY GNU/Linux APT User-Agent Outbound [**] [Classification: Not Suspicious Traffic] [Priority: 3] {TCP} 172.21.128.119:60526 -> 91.189.88.142:80",
    }
    result = ingest_bytes(json.dumps([record]).encode("utf-8"), "relayed.json", tmp_path / "relayed.db")
    db = EndpointDatabase(Path(result["path"]))
    try:
        event = db.execute_query(
            "SELECT event_code, action, severity, host_id FROM events"
        )[0]
        assert event == {
            "event_code": "2013504",
            "action": "ET POLICY GNU/Linux APT User-Agent Outbound",
            "severity": 3,
            "host_id": "wazuh-client-24",
        }
        network = db.execute_query(
            "SELECT source_ip, source_port, destination_ip, destination_port, protocol FROM network_connections"
        )[0]
        assert network == {
            "source_ip": "172.21.128.119",
            "source_port": 60526,
            "destination_ip": "91.189.88.142",
            "destination_port": 80,
            "protocol": "tcp",
        }
    finally:
        db.close()


def test_wazuh_web_events_expose_source_and_server_ip(tmp_path):
    record = {
        "@timestamp": "2022-01-17T11:21:46Z",
        "agent": {"name": "wazuh-client", "id": "23", "ip": "172.21.128.54"},
        "rule": {"id": "31101", "level": 5, "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"]},
        "data": {"protocol": "GET", "srcip": "172.21.128.119", "url": "/nmaplowercheck"},
    }
    result = ingest_bytes(json.dumps([record]).encode("utf-8"), "web.json", tmp_path / "web.db")
    db = EndpointDatabase(Path(result["path"]))
    try:
        event = db.execute_query(
            "SELECT source_ip, destination_ip, protocol FROM events"
        )[0]
        assert event == {
            "source_ip": "172.21.128.119",
            "destination_ip": "172.21.128.54",
            "protocol": "tcp",
        }
        network = db.execute_query(
            "SELECT source_ip, destination_ip FROM network_connections"
        )[0]
        assert network == {"source_ip": "172.21.128.119", "destination_ip": "172.21.128.54"}
    finally:
        db.close()


def test_events_without_destination_do_not_create_blank_network_rows(tmp_path):
    record = {
        "@timestamp": "2022-01-15T08:46:49Z",
        "agent": {"name": "wazuh-client", "id": "22", "ip": "172.21.131.50"},
        "rule": {"id": "5503", "level": 5, "description": "PAM: User login failed.", "groups": ["pam", "authentication_failed"]},
        "data": {"srcip": "172.21.131.50", "srcuser": "alice"},
    }
    result = ingest_bytes(json.dumps([record]).encode("utf-8"), "auth.json", tmp_path / "auth.db")
    db = EndpointDatabase(Path(result["path"]))
    try:
        assert db.execute_query("SELECT COUNT(*) AS c FROM network_connections") == [{"c": 0}]
    finally:
        db.close()


def test_generic_nested_schema_is_recorded(tmp_path):
    records = [
        {"ts": "2026-09-10T09:00:00Z", "actor": {"user": {"name": "bob"}}, "message": "hello", "severity": "7"},
        {"ts": "2026-09-10T09:00:01Z", "actor": {"user": {"name": "eve"}}, "message": "world", "severity": "2"},
    ]
    result = ingest_bytes(
        json.dumps(records).encode("utf-8"), "custom.json", tmp_path / "custom.db"
    )

    assert result["source"] == "generic"
    assert result["rows"] == 2
    fields = {field["path"]: field for field in result["schema"]["fields"]}
    assert fields["actor.user.name"]["types"] == ["string"]
    assert fields["severity"]["types"] == ["string"]

    conn = sqlite3.connect(result["path"])
    try:
        event_ids = [row[0] for row in conn.execute("SELECT event_id FROM events")]
        assert len(event_ids) == len(set(event_ids)) == 2
    finally:
        conn.close()


def test_aminer_jsonl_with_json_suffix_is_ingested(tmp_path):
    record = {
        "AnalysisComponent": {
            "AnalysisComponentIdentifier": 3,
            "AnalysisComponentType": "NewMatchPathDetector",
            "Message": "New path(es) detected",
            "TrainingMode": True,
        },
        "LogData": {
            "RawLogData": ["type=USER_ACCT msg=audit(1642204801.159:657): pid=5790 acct=www-data"],
            "Timestamps": [1642204801.16],
        },
        "AMiner": {"ID": "172.17.129.140"},
    }
    source = tmp_path / "fox_aminer.json"
    source.write_text(json.dumps(record) + chr(10) + json.dumps(record) + chr(10), encoding="utf-8")

    result = ingest_file(source)
    assert result["source"] == "aminer"
    assert result["format"] == "jsonl"
    assert result["rows"] == 2
    fields = {field["path"]: field for field in result["schema"]["fields"]}
    assert fields["AMiner.ID"]["types"] == ["string"]

    db = EndpointDatabase(Path(result["path"]))
    try:
        events = db.execute_query(
            "SELECT provider, event_code, category, host_id, user_id, process_entity_id, timestamp "
            "FROM events ORDER BY event_id"
        )
        assert {row["provider"] for row in events} == {"AMiner"}
        assert events[0]["event_code"] == "NewMatchPathDetector"
        assert events[0]["category"] == "anomaly"
        assert events[0]["host_id"] == "172.17.129.140"
        assert events[0]["user_id"] == "www-data"
        assert events[0]["process_entity_id"] == "proc-172.17.129.140-5790"
        assert events[0]["timestamp"].startswith("2022-01-15")
        processes = db.execute_query("SELECT pid, command_line FROM processes")
        assert processes[0]["pid"] == 5790
        assert "pid=5790" in processes[0]["command_line"]
    finally:
        db.close()


def test_merged_wazuh_aminer_database(tmp_path):
    wazuh_line = json.dumps({
        "timestamp": "2022-01-17T11:58:17.100+0000",
        "rule": {"id": "554", "level": 0, "description": "File added to the system."},
        "agent": {"id": "021", "name": "wazuh-client-21"},
        "manager": {"name": "wazuh-manager"},
        "decoder": {"name": "sshd"},
        "data": {"protocol": "sshd"},
        "full_log": "Jan 17 11:58:17 intranet-server sshd[20749]: Accepted password for katelyn.clayton from 172.21.128.119 port 51222 ssh2",
    }) + "\n"
    aminer = {
        "AnalysisComponent": {
            "AnalysisComponentIdentifier": 3,
            "AnalysisComponentType": "NewMatchPathValueComboDetector",
            "Message": "New path(es) detected",
            "TrainingMode": False,
        },
        "LogData": {
            "RawLogData": [
                "type=USER_CMD msg=audit(1642420709.209:663): pid=21058 uid=1002 "
                "msg='cwd=\"/var/www\" cmd=636174202F6574632F736861646F77 terminal=pts/1 res=success'"
            ],
            "Timestamps": [1642420709.25],
        },
        "AMiner": {"ID": "192.168.104.155"},
    }
    ecs_line = json.dumps({
        "@timestamp": "2022-01-14T00:00:05.000Z",
        "ecs": {"version": "1.9.0"},
        "agent": {"hostname": "intranet-server"},
        "host": {"name": "intranet-server"},
        "metricset": {"name": "cpu"},
    }) + "\n"
    aminer_jsonl = ecs_line + json.dumps(aminer) + "\n"

    wazuh_file = tmp_path / "santos_wazuh.json"
    wazuh_file.write_text(wazuh_line, encoding="utf-8")
    aminer_file = tmp_path / "santos_aminer.json"
    aminer_file.write_text(aminer_jsonl, encoding="utf-8")

    out = tmp_path / "santos.db"
    result = ingest_merged(
        [(wazuh_file.read_bytes(), wazuh_file.name), (aminer_file.read_bytes(), aminer_file.name)], out
    )
    assert result["source"] == "wazuh+aminer"
    assert result["rows"] == 3
    assert result["files"] == [
        {"filename": "santos_wazuh.json", "source": "wazuh", "format": "json", "rows": 1},
        {"filename": "santos_aminer.json", "source": "aminer", "format": "jsonl", "rows": 2},
    ]

    db = EndpointDatabase(Path(result["path"]))
    try:
        events = db.execute_query(
            "SELECT provider, event_code, severity, category, host_id, user_id, action FROM events ORDER BY event_id"
        )
        assert [row["provider"] for row in events] == ["AMiner", "Wazuh", "AMiner"]
        assert [row["event_code"] for row in events] == ["anomaly", "554", "NewMatchPathValueComboDetector"]
        aminer_rows = [row for row in events if row["provider"] == "AMiner"]
        detector_rows = [row for row in aminer_rows if row["event_code"] == "NewMatchPathValueComboDetector"]
        assert detector_rows and detector_rows[0]["host_id"] == "intranet-server"
        cmd_rows = [row for row in aminer_rows if "cat /etc/shadow" in (row["action"] or "")]
        assert len(cmd_rows) == 1
        assert "ran cat /etc/shadow" in cmd_rows[0]["action"]

        users = db.execute_query("SELECT user_id FROM users")
        assert any(row["user_id"] == "katelyn.clayton" for row in users)

        meta = db.execute_query("SELECT key, value FROM ingest_meta WHERE key IN ('source','files')")
        assert {row["key"] for row in meta} == {"source", "files"}
    finally:
        db.close()


def test_scenario_stem_strips_provider_suffix():
    assert scenario_stem("santos_wazuh.json") == "santos"
    assert scenario_stem("shaw_aminer.jsonl") == "shaw"
    assert scenario_stem("plain.log") == "plain"


def test_suricata_fast_log_text_is_parsed(tmp_path):
    line = (
        "09/10/2026-08:05:00.123456  [**] [1:2027865:3] ET MALWARE SMB "
        "[**] [Classification: A Network Trojan] [Priority: 1] {TCP} "
        "10.0.0.5:50000 -> 10.0.0.9:445"
    )
    source = tmp_path / "fast.log"
    source.write_text(line + "\n", encoding="utf-8")
    result = ingest_file(source)

    assert result["source"] == "suricata"
    assert result["format"] == "text"
    db = EndpointDatabase(Path(result["path"]))
    try:
        network = db.execute_query("SELECT source_ip, destination_port FROM network_connections")
        assert network == [{"source_ip": "10.0.0.5", "destination_port": 445}]
    finally:
        db.close()


def test_ingest_rejects_empty_and_unsupported_files(tmp_path):
    with pytest.raises(IngestError):
        ingest_bytes(b"  ", "empty.json", tmp_path / "empty.db")

    source = tmp_path / "events.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    with pytest.raises(IngestError):
        ingest_file(source)
