"""FastAPI Web Server for A1 DFIR Agent with SSE streaming."""
import asyncio
import json
import logging
import re
import threading
import urllib.request
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import a1.config as cfg
from a1.graph import create_investigation_graph
from a1.llm import get_active_llm_info, set_active_llm

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
    dbs.sort(key=lambda d: (not ("agent_endpoint_security.db" in d["name"]), d["display"]))
    return dbs

def set_active_database(db_path_str: str) -> str:
    """Switch active database path and reset tool caches.

    Delegates to ``a1.config.set_active_database`` so CLI, web and benchmark
    share one switching implementation.
    """
    import a1.config as _cfg

    return str(_cfg.set_active_database(db_path_str))

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

def create_app() -> FastAPI:
    app = FastAPI(title="A1 DFIR Investigator Web API", version="1.0.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/status")
    async def get_status():
        active = get_active_llm_info()
        dbs = get_available_databases()
        return {
            "status": "ready",
            "active_llm": active,
            "current_db": str(cfg.DB_PATH),
            "databases": dbs,
        }

    @app.get("/api/models")
    async def list_models():
        return get_model_catalog()

    @app.post("/api/models/set")
    async def update_model(req: ModelConfigRequest):
        if req.provider or req.model:
            set_active_llm(provider=req.provider, model=req.model)
        return {"status": "updated", "active_llm": get_active_llm_info()}

    @app.get("/api/databases")
    async def list_databases():
        return {"databases": get_available_databases()}

    @app.post("/api/databases/set")
    async def update_database(req: DatabaseConfigRequest):
        try:
            active_path = set_active_database(req.db_path)
            return {"status": "updated", "active_db": active_path}
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/api/events")
    async def get_events(limit: int = 100):
        try:
            from a1.db import EndpointDatabase
            db = EndpointDatabase(cfg.DB_PATH)
            rows = db.execute_query(
                "SELECT e.event_id, e.timestamp, e.host_id, e.action, e.raw_json FROM events e ORDER BY e.timestamp DESC LIMIT ?",
                params=(limit,),
                max_rows=limit,
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
                "db_name": Path(cfg.DB_PATH).name,
                "total": len(events),
                "events": events,
            }
        except Exception as e:
            return {"db_name": Path(cfg.DB_PATH).name, "total": 0, "events": [], "error": str(e)}

    def extract_and_clean_thoughts(raw_text: str) -> tuple[Optional[str], str]:
        """Extract embedded thought/reasoning blocks and return (thought, cleaned_text)."""
        if not raw_text:
            return None, ""

        thought_parts = []
        cleaned = raw_text

        # Match Gemma 4 / ChatML format: <|channel>thought ... <channel|>
        gemma_matches = list(re.finditer(r"<\|?channel>thought\s*(.*?)\s*<channel\|>", cleaned, re.DOTALL | re.IGNORECASE))
        for gm in gemma_matches:
            t = gm.group(1).strip()
            if t:
                thought_parts.append(t)
        if gemma_matches:
            cleaned = re.sub(r"<\|?channel>thought\s*.*?\s*<channel\|>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

        # Match DeepSeek / standard <think> ... </think>
        think_matches = list(re.finditer(r"<think>\s*(.*?)\s*</think>", cleaned, re.DOTALL | re.IGNORECASE))
        for tm in think_matches:
            t = tm.group(1).strip()
            if t:
                thought_parts.append(t)
        if think_matches:
            cleaned = re.sub(r"<think>\s*.*?\s*</think>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

        # Clean leftover channel / think control tokens
        cleaned = re.sub(r"<\|?channel[^>]*\|?>", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"</?think>", "", cleaned, flags=re.IGNORECASE)
        cleaned = cleaned.strip()

        thought = "\n\n".join(thought_parts) if thought_parts else None
        return thought, cleaned

    def summarize_tool_output(content: str) -> str:
        """Produce a clean summary of tool output for frontend telemetry stream."""
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                if "matches" in data:
                    count = len(data.get("matches", []))
                    details = ", ".join(
                        str(m.get("child_process_name", m.get("process_entity_id", "?")))
                        for m in data.get("matches", [])[:3]
                    )
                    return f"{count} process match(es): {details}" if details else f"{count} match(es)"
                if "ancestors" in data or "descendants" in data:
                    a = len(data.get("ancestors", []))
                    d = len(data.get("descendants", []))
                    return f"Process tree: {a} ancestor(s), {d} descendant(s)"
                if "network_connections" in data:
                    return (
                        f"{len(data.get('network_connections', []))} net conns, "
                        f"{len(data.get('files', []))} file ops, "
                        f"{len(data.get('registry_events', []))} reg events"
                    )
                parts = []
                for k, v in data.items():
                    if isinstance(v, list):
                        parts.append(f"{k}: {len(v)} item(s)")
                    elif isinstance(v, dict):
                        parts.append(f"{k}: object")
                    else:
                        parts.append(f"{k}={v}")
                    if len(parts) >= 6:
                        break
                return "; ".join(parts) if parts else "(empty result)"
            if isinstance(data, list):
                return f"{len(data)} row(s) returned"
            return str(data)[:200]
        except Exception:
            pass
        return str(content)[:200]

    @app.post("/api/investigate")
    async def investigate_stream(req: InvestigateRequest, request: Request):
        """Run investigation and stream progressive events via Server-Sent Events (SSE)."""
        if not req.query.strip():
            raise HTTPException(status_code=400, detail="Query cannot be empty.")

        # Update LLM or DB if supplied in request
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

        async def event_generator() -> AsyncGenerator[str, None]:
            loop = asyncio.get_running_loop()
            queue = asyncio.Queue()

            def run_sync_investigation():
                try:
                    active_info = get_active_llm_info()
                    # Emit start event
                    loop.call_soon_threadsafe(
                        queue.put_nowait,
                        {
                            "type": "start",
                            "query": req.query,
                            "session_id": session_id,
                            "llm": active_info,
                            "db": Path(cfg.DB_PATH).name,
                        }
                    )

                    graph = create_investigation_graph()
                    initial_state = {
                        "messages": [],
                        "hypotheses": [],
                        "iteration_count": 0,
                        "alert_context": req.query,
                    }

                    alert_prep_sent = False
                    triage_sent = False
                    evidence_pack_sent = False
                    processed_msg_count = 0
                    last_iteration = 0
                    step_num = 0
                    final_state = None

                    for event in graph.stream(initial_state, stream_mode="values"):
                        if cancel_event.is_set():
                            loop.call_soon_threadsafe(
                                queue.put_nowait,
                                {"type": "cancelled", "message": "Investigation cancelled by user."}
                            )
                            break

                        final_state = event

                        # 1. Alert Prep
                        enriched = event.get("enriched_alert")
                        if enriched and not alert_prep_sent:
                            ents = enriched.get("entities", {})
                            tw = enriched.get("time_window", {})
                            loop.call_soon_threadsafe(
                                queue.put_nowait,
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
                                    }
                                }
                            )
                            alert_prep_sent = True

                        # 2. Triage & Hypotheses
                        hypos = event.get("hypotheses", [])
                        if hypos and not triage_sent:
                            plan_lines = []
                            for m in event.get("messages", []):
                                if getattr(m, "type", "") == "human" and "Plan:" in getattr(m, "content", ""):
                                    plan_lines = [
                                        ln.strip() for ln in m.content.splitlines()
                                        if ln.startswith("Plan:") or ln.startswith("Initial entities:")
                                    ]
                                    break
                            loop.call_soon_threadsafe(
                                queue.put_nowait,
                                {
                                    "type": "triage",
                                    "data": {
                                        "hypotheses": hypos,
                                        "plan": "\n".join(plan_lines) if plan_lines else "",
                                    }
                                }
                            )
                            triage_sent = True

                        # 3. Investigation Loop step
                        iteration = event.get("iteration_count", 0)
                        active_hypo = event.get("active_hypothesis")
                        if iteration > last_iteration:
                            last_iteration = iteration
                            loop.call_soon_threadsafe(
                                queue.put_nowait,
                                {
                                    "type": "loop",
                                    "data": {
                                        "iteration": iteration,
                                        "max_steps": cfg.MAX_INVESTIGATION_STEPS,
                                        "active_hypothesis": active_hypo,
                                    }
                                }
                            )

                        # 4. Evidence Pack
                        pack = event.get("evidence_pack")
                        if pack and not evidence_pack_sent:
                            loop.call_soon_threadsafe(
                                queue.put_nowait,
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
                                        }
                                    }
                                }
                            )
                            evidence_pack_sent = True

                        # 5. Messages stream (Thoughts & Tool Calls)
                        messages = event.get("messages", [])
                        if len(messages) > processed_msg_count:
                            new_msgs = messages[processed_msg_count:]
                            processed_msg_count = len(messages)

                            for msg in new_msgs:
                                msg_type = getattr(msg, "type", "unknown")
                                if msg_type == "ai":
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
                                        loop.call_soon_threadsafe(
                                            queue.put_nowait,
                                            {"type": "thought", "text": final_thought}
                                        )
                                    if cleaned_content and cleaned_content != final_thought:
                                        loop.call_soon_threadsafe(
                                            queue.put_nowait,
                                            {"type": "reasoning", "text": cleaned_content}
                                        )

                                    tool_calls = getattr(msg, "tool_calls", None) or []
                                    for tc in tool_calls:
                                        step_num += 1
                                        loop.call_soon_threadsafe(
                                            queue.put_nowait,
                                            {
                                                "type": "tool_call",
                                                "data": {
                                                    "step": step_num,
                                                    "tool": tc.get("name"),
                                                    "args": tc.get("args") or {},
                                                }
                                            }
                                        )

                                elif msg_type == "tool":
                                    t_name = getattr(msg, "name", "tool")
                                    raw_content = str(getattr(msg, "content", ""))
                                    summary = summarize_tool_output(raw_content)
                                    loop.call_soon_threadsafe(
                                        queue.put_nowait,
                                        {
                                            "type": "tool_result",
                                            "data": {
                                                "tool": t_name,
                                                "summary": summary,
                                                "raw": raw_content[:1500],
                                            }
                                        }
                                    )

                    # Finished graph execution - synthesize complete payload
                    if final_state and not cancel_event.is_set():
                        report_content = ""
                        report_msgs = [m for m in final_state.get("messages", []) if getattr(m, "type", "") == "human"]
                        if report_msgs:
                            report_content = report_msgs[-1].content

                        loop.call_soon_threadsafe(
                            queue.put_nowait,
                            {
                                "type": "complete",
                                "data": {
                                    "verdict": final_state.get("verdict", "UNKNOWN"),
                                    "verdict_boundary": final_state.get("verdict_boundary", ""),
                                    "confidence": final_state.get("confidence", 0.0),
                                    "hypotheses": final_state.get("hypotheses", []),
                                    "report": report_content,
                                    "report_fallback_used": bool(final_state.get("report_fallback_used", False)),
                                }
                            }
                        )

                except Exception as e:
                    logger.exception("Investigation graph execution error")
                    loop.call_soon_threadsafe(
                        queue.put_nowait,
                        {"type": "error", "message": str(e)}
                    )
                finally:
                    loop.call_soon_threadsafe(queue.put_nowait, None)

            # Start worker thread
            worker = threading.Thread(target=run_sync_investigation, daemon=True)
            worker.start()

            try:
                while True:
                    if await request.is_disconnected():
                        cancel_event.set()
                        break

                    item = await queue.get()
                    if item is None:
                        break
                    yield f"data: {json.dumps(item)}\n\n"
            finally:
                _active_investigations.pop(session_id, None)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.post("/api/cancel")
    async def cancel_all():
        for cancel_event in _active_investigations.values():
            cancel_event.set()
        return {"status": "cancelling"}

    # Mount static assets
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
            url = f"http://{host}:{port}/"
            print(f"[*] Opening browser to {url} ...")
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    print(f"\n=======================================================")
    print(f" A1 DFIR AI Investigator Web Server")
    print(f" Web UI available at: http://{host}:{port}/")
    print(f"=======================================================\n")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    start()
