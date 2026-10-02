"""FastAPI Web Server for A1 DFIR Agent with SSE streaming."""
import asyncio
import json
import logging
import re
import threading
import urllib.request
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import a1.config as cfg
from a1.graph import create_investigation_graph
from a1.llm import get_active_llm_info, set_active_llm
from a1.tools import summarize_tool_output

logger = logging.getLogger("a1.web")
logging.basicConfig(level=logging.INFO)

STATIC_DIR = Path(__file__).resolve().parent / "static"
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Active cancellation event tracking
_active_investigations: Dict[str, asyncio.Event] = {}

def get_available_databases() -> List[Dict[str, Any]]:
    """Scan the repository for SQLite database files."""
    dbs = []
    base = PROJECT_ROOT / "endpoint_security_dataset_expanded_corrected"
    search_dirs = [base, PROJECT_ROOT]

    found_paths = set()
    for sdir in search_dirs:
        if not sdir.exists():
            continue
        for p in sdir.glob("**/*.db"):
            resolved = p.resolve()
            if resolved in found_paths:
                continue
            found_paths.add(resolved)
            
            # Determine friendly relative name
            try:
                rel = resolved.relative_to(PROJECT_ROOT)
                display_name = str(rel).replace("\\", "/")
            except ValueError:
                display_name = resolved.name

            dbs.append({
                "name": resolved.name,
                "display": display_name,
                "path": str(resolved),
                "size_bytes": resolved.stat().st_size,
                "is_active": str(resolved) == str(Path(cfg.DB_PATH).resolve())
            })

    # Sort so default agent db is first
    dbs.sort(key=lambda d: ("agent_endpoint_security.db" not in d["name"], d["display"]))
    return dbs

def set_active_database(db_path_str: str) -> str:
    """Switch active database path and reset tool caches.

    Delegates to ``a1.config.set_active_database`` so CLI, web and benchmark
    share one switching implementation.
    """
    import a1.config as _cfg

    # Match against available scanned databases first (safe allowlist lookup)
    available = get_available_databases()
    target_path = None
    clean_name = str(db_path_str).strip()

    for item in available:
        if clean_name in (item["path"], item["name"], item["display"]):
            target_path = Path(item["path"])
            break

    if target_path is None:
        safe_base = PROJECT_ROOT.resolve()
        candidate = (safe_base / clean_name).resolve()
        if not candidate.is_relative_to(safe_base):
            raise ValueError("Invalid database path: access outside permitted directory is prohibited")
        if candidate.suffix.lower() != ".db":
            raise ValueError("Invalid database file format: expected a .db file")
        target_path = candidate

    return str(_cfg.set_active_database(target_path, allow_external=False))

def fetch_live_ollama_models() -> List[str]:
    """Query Ollama server for available tags."""
    try:
        url = f"{cfg.OLLAMA_BASE_URL}/api/tags"
        req = urllib.request.Request(url)
        if cfg.OLLAMA_API_KEY:
            req.add_header("Authorization", f"Bearer {cfg.OLLAMA_API_KEY}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name") for m in data.get("models", []) if m.get("name")]
            if models:
                return models
    except Exception as e:
        logger.debug(f"Could not fetch Ollama models dynamically: {e}")
    return []

def get_model_catalog() -> Dict[str, Any]:
    """Return model catalog grouped by provider."""
    live_ollama = fetch_live_ollama_models()
    default_ollama = [
        "gemma4:31b",
        "llama3.1",
        "llama3.3",
        "mistral-large-3:675b",
        "deepseek-v4-pro:0813",
        "deepseek-r1",
        "nemotron-3-nano:30b",
        "glm-5.3-flash",
    ]
    # Merge and preserve order with current active first
    active_info = get_active_llm_info()
    ollama_models = []
    seen = set()
    if active_info["provider"] == "ollama":
        ollama_models.append(active_info["model"])
        seen.add(active_info["model"])
    for m in live_ollama + default_ollama:
        if m not in seen:
            ollama_models.append(m)
            seen.add(m)

    openai_models = [
        "gpt-4o",
        "gpt-4o-mini",
        "o1-mini",
        "o3-mini",
        "gpt-4-turbo"
    ]

    return {
        "active": active_info,
        "ollama": ollama_models,
        "openai": openai_models,
        "has_openai_key": bool(cfg.OPENAI_API_KEY),
        "ollama_base_url": cfg.OLLAMA_BASE_URL,
    }

class ModelConfigRequest(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None

class DatabaseConfigRequest(BaseModel):
    db_path: str

class InvestigateRequest(BaseModel):
    query: str
    provider: Optional[str] = None
    model: Optional[str] = None
    db_path: Optional[str] = None

def extract_and_clean_thoughts(raw_text: str) -> tuple[Optional[str], str]:
    """Extract embedded thought/reasoning blocks and return (thought, cleaned_text)."""
    if not raw_text:
        return None, ""

    thought_parts = []
    cleaned = raw_text

    # Match Gemma 4 / ChatML format: <|channel>thought ... <channel|>
    gemma_matches = list(re.finditer(r"<\|?channel>thought(.*?)<channel\|>", cleaned, re.DOTALL | re.IGNORECASE))
    for gm in gemma_matches:
        t = gm.group(1).strip()
        if t:
            thought_parts.append(t)
    if gemma_matches:
        cleaned = re.sub(r"<\|?channel>thought.*?<channel\|>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    # Match DeepSeek / standard <think> ... </think>
    think_matches = list(re.finditer(r"<think>(.*?)</think>", cleaned, re.DOTALL | re.IGNORECASE))
    for tm in think_matches:
        t = tm.group(1).strip()
        if t:
            thought_parts.append(t)
    if think_matches:
        cleaned = re.sub(r"<think>.*?</think>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

    # Clean leftover channel / think control tokens
    cleaned = re.sub(r"<\|?channel[^>]*\|?>", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"</?think>", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.strip()

    thought = "\n\n".join(thought_parts) if thought_parts else None
    return thought, cleaned


def _safe_queue_put(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, payload: Any) -> None:
    loop.call_soon_threadsafe(queue.put_nowait, payload)


def _emit_alert_prep_if_needed(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, event: dict, already_sent: bool) -> bool:
    enriched = event.get("enriched_alert")
    if not enriched or already_sent:
        return already_sent
    ents = enriched.get("entities", {})
    tw = enriched.get("time_window", {})
    _safe_queue_put(
        loop,
        queue,
        {
            "type": "alert_prep",
            "data": {
                "host_ids": ents.get("host_ids", []),
                "resolved_hosts": ents.get("resolved_hosts", {}),
                "time_window": {
                    "start_time": tw.get("start_time"),
                    "end_time": tw.get("end_time"),
                    "is_default": tw.get("is_default", False),
                },
                "missing": enriched.get("missing", []),
            },
        },
    )
    return True


def _emit_triage_if_needed(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, event: dict, already_sent: bool) -> bool:
    hypos = event.get("hypotheses", [])
    if not hypos or already_sent:
        return already_sent
    plan_lines = []
    for m in event.get("messages", []):
        if getattr(m, "type", "") == "human" and "Plan:" in getattr(m, "content", ""):
            plan_lines = [
                ln.strip() for ln in m.content.splitlines()
                if ln.startswith(("Plan:", "Initial entities:"))
            ]
            break
    _safe_queue_put(
        loop,
        queue,
        {
            "type": "triage",
            "data": {
                "hypotheses": hypos,
                "plan": "\n".join(plan_lines) if plan_lines else "",
            },
        },
    )
    return True


def _emit_evidence_pack_if_needed(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, event: dict, already_sent: bool) -> bool:
    pack = event.get("evidence_pack")
    if not pack or already_sent:
        return already_sent
    _safe_queue_put(
        loop,
        queue,
        {
            "type": "evidence_pack",
            "data": {
                "total_kept_events": pack.get("total_kept_events", 0),
                "timeline_count": len(pack.get("timeline", [])),
                "timeline": pack.get("timeline", []),
                "excluded_count": pack.get("excluded_row_count", 0),
                "hypotheses_evidence": {
                    h: {"status": info.get("status"), "event_count": info.get("event_count", 0)}
                    for h, info in pack.get("hypotheses_evidence", {}).items()
                },
            },
        },
    )
    _safe_queue_put(
        loop,
        queue,
        {"type": "reasoning", "text": "Forensic evidence gathered. Correlating multi-source telemetry and assessing benign hypotheses..."},
    )
    return True


def _emit_ai_message(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, msg: Any, step_num: int) -> int:
    add_kwargs = getattr(msg, "additional_kwargs", {}) or {}
    reasoning_content = (
        add_kwargs.get("reasoning_content")
        or getattr(msg, "reasoning_content", None)
        or ""
    )
    text_content = str(getattr(msg, "content", "") or "").strip()
    embedded_thought, cleaned_content = extract_and_clean_thoughts(text_content)
    final_thought = reasoning_content or embedded_thought

    if final_thought:
        _safe_queue_put(loop, queue, {"type": "thought", "text": final_thought})
    if cleaned_content and cleaned_content != final_thought:
        _safe_queue_put(loop, queue, {"type": "reasoning", "text": cleaned_content})

    tool_calls = getattr(msg, "tool_calls", None) or []
    for tc in tool_calls:
        step_num += 1
        _safe_queue_put(
            loop,
            queue,
            {
                "type": "tool_call",
                "data": {
                    "step": step_num,
                    "tool": tc.get("name"),
                    "args": tc.get("args") or {},
                },
            },
        )
    return step_num


def _emit_tool_message(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, msg: Any) -> None:
    t_name = getattr(msg, "name", "tool")
    raw_content = str(getattr(msg, "content", ""))
    summary = summarize_tool_output(raw_content)
    _safe_queue_put(
        loop,
        queue,
        {
            "type": "tool_result",
            "data": {
                "tool": t_name,
                "summary": summary,
                "raw": raw_content[:1500],
            },
        },
    )


def _extract_report_content(final_state: dict) -> str:
    report_content = final_state.get("report") or ""
    if report_content:
        return report_content
    for m in reversed(final_state.get("messages", [])):
        if getattr(m, "type", "") == "human":
            c = getattr(m, "content", "")
            if "DFIR Incident Investigation Report" in c or "## Verdict:" in c:
                return c
    report_msgs = [m for m in final_state.get("messages", []) if getattr(m, "type", "") == "human"]
    return getattr(report_msgs[-1], "content", "") if report_msgs else ""


def _normalize_confidence_score(raw_conf: Any) -> float:
    try:
        conf_val = float(raw_conf)
        if conf_val > 1.0:
            conf_val /= 100.0
    except Exception:
        conf_val = 0.85
    return max(0.05, min(1.0, conf_val))


def _emit_final_report_complete(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue, final_state: dict) -> None:
    report_content = _extract_report_content(final_state)
    conf_val = _normalize_confidence_score(final_state.get("confidence", 0.85))

    _safe_queue_put(
        loop,
        queue,
        {
            "type": "complete",
            "data": {
                "verdict": final_state.get("verdict", "UNKNOWN"),
                "verdict_boundary": final_state.get("verdict_boundary", ""),
                "confidence": conf_val,
                "hypotheses": final_state.get("hypotheses", []),
                "report": report_content,
                "report_fallback_used": bool(final_state.get("report_fallback_used", False)),
            },
        },
    )


def _emit_iteration_if_advanced(
    loop: asyncio.AbstractEventLoop,
    queue: asyncio.Queue,
    event: dict,
    last_iteration: int,
) -> int:
    iteration = event.get("iteration_count", 0)
    if iteration > last_iteration:
        _safe_queue_put(
            loop,
            queue,
            {
                "type": "loop",
                "data": {
                    "iteration": iteration,
                    "max_steps": cfg.MAX_INVESTIGATION_STEPS,
                    "active_hypothesis": event.get("active_hypothesis"),
                },
            },
        )
        return iteration
    return last_iteration


def _emit_messages_incremental(
    loop: asyncio.AbstractEventLoop,
    queue: asyncio.Queue,
    messages: list,
    processed_count: int,
    step_num: int,
) -> Tuple[int, int]:
    if len(messages) <= processed_count:
        return processed_count, step_num
    new_msgs = messages[processed_count:]
    for msg in new_msgs:
        m_type = getattr(msg, "type", "unknown")
        if m_type == "ai":
            step_num = _emit_ai_message(loop, queue, msg, step_num)
        elif m_type == "tool":
            _emit_tool_message(loop, queue, msg)
    return len(messages), step_num


def _run_sync_investigation(
    loop: asyncio.AbstractEventLoop,
    queue: asyncio.Queue,
    query: str,
    session_id: str,
    cancel_event: asyncio.Event,
) -> None:
    try:
        active_info = get_active_llm_info()
        _safe_queue_put(
            loop,
            queue,
            {
                "type": "start",
                "query": query,
                "session_id": session_id,
                "llm": active_info,
                "db": Path(cfg.DB_PATH).name,
            },
        )

        graph = create_investigation_graph()
        initial_state = {
            "messages": [],
            "hypotheses": [],
            "iteration_count": 0,
            "alert_context": query,
        }

        alert_prep_sent = False
        triage_sent = False
        evidence_pack_sent = False
        correlation_sent = False
        processed_msg_count = 0
        last_iteration = 0
        step_num = 0
        for event in graph.stream(initial_state, stream_mode="values"):
            if cancel_event.is_set():
                _safe_queue_put(loop, queue, {"type": "cancelled", "message": "Investigation cancelled by user."})
                break

            final_state = event
            alert_prep_sent = _emit_alert_prep_if_needed(loop, queue, event, alert_prep_sent)
            triage_sent = _emit_triage_if_needed(loop, queue, event, triage_sent)
            last_iteration = _emit_iteration_if_advanced(loop, queue, event, last_iteration)
            evidence_pack_sent = _emit_evidence_pack_if_needed(loop, queue, event, evidence_pack_sent)

            if (event.get("confirmed_correlations") is not None or event.get("evidence_gaps") is not None) and not correlation_sent:
                correlation_sent = True
                _safe_queue_put(
                    loop,
                    queue,
                    {"type": "reasoning", "text": "Correlation analysis complete. Synthesizing DFIR incident investigation report and assigning final verdict..."},
                )

            processed_msg_count, step_num = _emit_messages_incremental(
                loop, queue, event.get("messages", []), processed_msg_count, step_num
            )

        if final_state and not cancel_event.is_set():
            _emit_final_report_complete(loop, queue, final_state)

    except Exception as e:
        logger.exception("Investigation graph execution error")
        _safe_queue_put(loop, queue, {"type": "error", "message": str(e)})
    finally:
        _safe_queue_put(loop, queue, None)


async def _sse_generator(queue: asyncio.Queue, request: Request, session_id: str, cancel_event: asyncio.Event) -> AsyncGenerator[str, None]:
    try:
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=2.0)
                if item is None:
                    break
                yield f"data: {json.dumps(item)}\n\n"
            except asyncio.TimeoutError:
                if await request.is_disconnected():
                    cancel_event.set()
                    break
                yield ": keep-alive\n\n"
    finally:
        _active_investigations.pop(session_id, None)


router = APIRouter()


@router.get("/api/status")
async def get_status():
    active = get_active_llm_info()
    dbs = get_available_databases()
    return {
        "status": "ready",
        "active_llm": active,
        "current_db": str(cfg.DB_PATH),
        "databases": dbs,
    }


@router.get("/api/models")
async def list_models():
    return get_model_catalog()


@router.post("/api/models/set")
async def update_model(req: ModelConfigRequest):
    if req.provider or req.model:
        set_active_llm(provider=req.provider, model=req.model)
    return {"status": "updated", "active_llm": get_active_llm_info()}


@router.get("/api/databases")
async def list_databases():
    return {"databases": get_available_databases()}


@router.post(
    "/api/databases/set",
    responses={
        400: {"description": "Invalid database path or format"},
        404: {"description": "Database file not found"},
    },
)
async def update_database(req: DatabaseConfigRequest):
    try:
        active_path = set_active_database(req.db_path)
        return {"status": "updated", "active_db": active_path}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/events")
async def get_events(limit: int = 2500):
    active_db_path = cfg.get_db_path()
    try:
        from a1.db import get_active_db
        db = get_active_db(active_db_path)
        count_rows = db.execute_query("SELECT COUNT(*) as cnt FROM events", max_rows=1)
        total_in_db = count_rows[0]["cnt"] if count_rows else 0

        fetch_limit = 2500 if limit in (100, 200) else max(limit, 1)

        rows = db.execute_query(
            "SELECT e.event_id, e.timestamp, e.host_id, e.action, e.raw_json FROM events e ORDER BY e.timestamp DESC LIMIT ?",
            params=(fetch_limit,),
            max_rows=fetch_limit,
        )
        events = []
        for r in rows:
            ev = dict(r)
            if ev.get("raw_json"):
                try:
                    ev["details"] = json.loads(ev["raw_json"])
                except Exception:
                    pass
            events.append(ev)
        return {
            "db_name": Path(active_db_path).name,
            "total": total_in_db,
            "loaded": len(events),
            "events": events,
        }
    except Exception as e:
        return {"db_name": Path(active_db_path).name, "total": 0, "loaded": 0, "events": [], "error": str(e)}


@router.post(
    "/api/investigate",
    responses={
        400: {"description": "Query cannot be empty"},
    },
)
async def investigate_stream(req: InvestigateRequest, request: Request):
    """Run investigation and stream progressive events via Server-Sent Events (SSE)."""
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")

    if req.provider or req.model:
        set_active_llm(provider=req.provider, model=req.model)
    if req.db_path:
        try:
            set_active_database(req.db_path)
        except Exception as e:
            logger.warning(f"Could not switch database: {e}")

    session_id = f"inv-{asyncio.get_event_loop().time()}"
    cancel_event = asyncio.Event()
    _active_investigations[session_id] = cancel_event

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    worker = threading.Thread(
        target=_run_sync_investigation,
        args=(loop, queue, req.query, session_id, cancel_event),
        daemon=True,
    )
    worker.start()

    return StreamingResponse(_sse_generator(queue, request, session_id, cancel_event), media_type="text/event-stream")


@router.post("/api/cancel")
async def cancel_all():
    for cancel_event in _active_investigations.values():
        cancel_event.set()
    return {"status": "cancelling"}


def create_app() -> FastAPI:
    app = FastAPI(title="A1 DFIR Investigator Web API", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html_file = STATIC_DIR / "index.html"
        if html_file.exists():
            return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
        return HTMLResponse("<h2>A1 DFIR Web UI static files not found.</h2>")

    return app

def start(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True):
    """Start uvicorn server and open the browser."""
    import uvicorn
    import webbrowser

    app = create_app()

    if open_browser:
        def _open():
            import time
            time.sleep(1.2)
            scheme = "http"
            url = f"{scheme}://{host}:{port}/"
            print(f"[*] Opening browser to {url} ...")
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    scheme = "http"
    print("\n=======================================================")
    print(" A1 DFIR AI Investigator Web Server")
    print(f" Web UI available at: {scheme}://{host}:{port}/")
    print("=======================================================\n")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    start()
