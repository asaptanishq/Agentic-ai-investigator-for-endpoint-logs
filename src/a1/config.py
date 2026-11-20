from pathlib import Path
import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_PATH = BASE_DIR / ".env"
DATASET_DIR = BASE_DIR / "dataset"

# Telemetry databases searched in order: the attack and benign databases that ship today.
_DB_PREFERENCE = (
    "attack_lateral_movement.db",
    "attack_data_exfiltration.db",
    "ransomware_attack_complete_ecs.db",
    "benign_admin_activity.db",
)


def discover_default_db() -> Path:
    """Return the first preferred telemetry database that exists on disk.

    Falls back to any other ``*.db`` in the dataset directory, so a missing
    dataset still reports a meaningful path.
    """
    for relative in _DB_PREFERENCE:
        candidate = DATASET_DIR / relative
        if candidate.exists():
            return candidate
    shipped = sorted(DATASET_DIR.glob("*.db")) if DATASET_DIR.is_dir() else []
    return shipped[0] if shipped else DATASET_DIR / _DB_PREFERENCE[0]


DEFAULT_DB_PATH = discover_default_db()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "opencode").lower()  # "opencode" (default), "ollama", or "openai"

# OpenCode Settings
OPENCODE_MODEL_NAME = os.getenv("OPENCODE_MODEL_NAME", "deepseek-v4.1-flash")
OPENCODE_BASE_URL = os.getenv("OPENCODE_BASE_URL", "https://opencode.ai/inference/go/openai/v1")
OPENCODE_API_KEY = os.getenv("OPENCODE_API_KEY", "")

# Ollama Settings
OLLAMA_MODEL_NAME = os.getenv("OLLAMA_MODEL_NAME", "llama3.1")
raw_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
if raw_url.endswith("/api"):
    raw_url = raw_url[:-4].rstrip("/")
OLLAMA_BASE_URL = raw_url
OLLAMA_NUM_CTX = int(os.getenv("OLLAMA_NUM_CTX", "32768"))
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "")

# OpenAI Settings (for future use)
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", None)

# DB Path setting
_DB_PATH_OVERRIDE: ContextVar[str] = ContextVar("a1_db_path_override", default="")

_API_KEY_NAMES = {
    "opencode": "OPENCODE_API_KEY",
    "ollama": "OLLAMA_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def _write_env_value(name: str, value: str) -> None:
    """Persist one key in .env without disturbing the other settings."""
    if "\n" in value or "\r" in value:
        raise ValueError("API key must be a single line")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    line = f'{name}="{escaped}"'
    try:
        lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    except OSError as exc:
        raise ValueError(f"Could not read {ENV_PATH.name}: {exc}") from exc
    prefix = f"{name}="
    replaced = False
    for index, existing in enumerate(lines):
        if existing.strip().startswith(prefix):
            lines[index] = line
            replaced = True
            break
    if not replaced:
        lines.append(line)
    tmp_path = ENV_PATH.with_name(f".{ENV_PATH.name}.tmp")
    try:
        tmp_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tmp_path.replace(ENV_PATH)
    except OSError as exc:
        tmp_path.unlink(missing_ok=True)
        raise ValueError(f"Could not save API key to {ENV_PATH.name}: {exc}") from exc


def set_api_key(provider: str, api_key: str) -> str:
    """Set a provider API key for this process and persist it to .env."""
    provider = str(provider or "").strip().lower()
    name = _API_KEY_NAMES.get(provider)
    if not name:
        raise ValueError("Unsupported provider. Use opencode, ollama, or openai.")
    value = str(api_key or "").strip()
    _write_env_value(name, value)
    globals()[name] = value
    os.environ[name] = value
    return name


def get_db_path() -> Path:
    return Path(_DB_PATH_OVERRIDE.get() or os.getenv("ENDPOINT_DB_PATH", str(DEFAULT_DB_PATH)))


@contextmanager
def database_request_context(db_path) -> Iterator[None]:
    """Scope an explicit database path to one request thread."""
    token = None
    if db_path:
        token = _DB_PATH_OVERRIDE.set(str(Path(db_path).resolve()))
    try:
        yield
    finally:
        if token is not None:
            _DB_PATH_OVERRIDE.reset(token)


DB_PATH = get_db_path()


def set_active_database(db_path, allow_external: bool = False) -> Path:
    """Switch the active telemetry database and reset every tool singleton.

    Raises FileNotFoundError when the requested database does not exist, or
    ValueError if the path is invalid or outside permitted directories.
    """
    resolved = Path(db_path).resolve()
    if not allow_external:
        base_dir = BASE_DIR.resolve()
        if not resolved.is_relative_to(base_dir):
            raise ValueError("Invalid database path: access outside allowed directory is prohibited")

    if resolved.suffix.lower() != ".db":
        raise ValueError("Invalid database file format: expected a .db file")

    if not resolved.is_file():
        raise FileNotFoundError(f"Database file not found: {resolved.name}")

    os.environ["ENDPOINT_DB_PATH"] = str(resolved)
    global DB_PATH
    DB_PATH = resolved

    # Reset the centralized active database instance
    try:
        from a1.db import reset_active_db
        reset_active_db()
    except ImportError:
        pass

    return resolved


# Investigation step limits
MAX_INVESTIGATION_STEPS = int(os.getenv("MAX_INVESTIGATION_STEPS", "12"))

