"""Shared pytest configuration for the a1 test suite.

The original five-scenario agent bundle
(``endpoint_security_dataset_expanded_corrected/agent_bundle/agent_endpoint_security.db``)
is no longer part of this repository, so the default database path resolved by
``a1.config.get_db_path()`` would not exist and every database-backed test would
fail at connection time.

This conftest points the suite at a telemetry database that actually ships with
the repository. An explicitly configured ``ENDPOINT_DB_PATH`` always wins, so the
suite can still be run against a different dataset.
"""
import os
from pathlib import Path

DATASET_DIR = Path(__file__).resolve().parents[1] / "endpoint_security_dataset_expanded_corrected"

# Preferred first, then any other attack database shipped with the repository.
_PREFERRED_DBS = ("attack_lateral_movement.db", "attack_data_exfiltration.db")


def _select_test_database() -> Path | None:
    for name in _PREFERRED_DBS:
        candidate = DATASET_DIR / name
        if candidate.exists():
            return candidate
    fallback = sorted(DATASET_DIR.glob("*.db")) if DATASET_DIR.exists() else []
    return fallback[0] if fallback else None


if not os.getenv("ENDPOINT_DB_PATH"):
    _selected = _select_test_database()
    if _selected is not None:
        os.environ["ENDPOINT_DB_PATH"] = str(_selected)
