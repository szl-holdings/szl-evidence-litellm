"""A minimal, REAL, offline demo proxy surface for the evidence plane.

POST /v1/chat/completions runs a caller-supplied completion callable inside
the plugin's receipt path and echoes the correlation id in the
``x-szl-receipt-id`` response header. GET /receipts/{receipt_id} serves the
receipt + its evidence document from the sink; GET /receipts/verify verifies
the whole chain from genesis.

The default completion callable is a **local deterministic demo backend —
not an LLM**. It echoes the last user message with a fixed template so the
whole surface works offline with reproducible output. It is honest about
what it is: the string "local deterministic demo backend — not an LLM"
appears in every response it produces, and the evidence document records
``mock: false`` (this IS the backend; nothing is mocked) with
``provider: "local-demo"``.

FastAPI is an optional extra (``pip install szl-evidence-litellm[proxy]``);
importing this module without it raises a clear, actionable ImportError.
"""

from __future__ import annotations

import inspect
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .modes import EvidencePolicy
from .plugin import SZLEvidenceLogger
from .sink import EvidenceSink, verify_sink

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
except ImportError as exc:  # pragma: no cover - exercised only without fastapi
    raise ImportError(
        "the demo proxy needs the 'proxy' extra: "
        "pip install 'szl-evidence-litellm[proxy]' (fastapi + uvicorn)"
    ) from exc

__all__ = ["RECEIPT_ID_HEADER", "create_app", "local_demo_completion"]

RECEIPT_ID_HEADER = "x-szl-receipt-id"

CompletionCallable = Callable[[dict[str, Any]], Any]


def local_demo_completion(request: dict[str, Any]) -> dict[str, Any]:
    """Local deterministic demo backend — not an LLM.

    Echoes the last user message through a fixed template. Deterministic by
    construction: same request bytes in, same response bytes out, so a
    re-run of the demo reproduces the receipt digests exactly (modulo the
    wall-clock timestamp, which is data, not formatting).
    """
    messages = request.get("messages") or []
    last_user = ""
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            last_user = content if isinstance(content, str) else str(content)
            break
    model = request.get("model") or "local-demo"
    text = (
        "local deterministic demo backend — not an LLM. "
        f"Echo of your last user message ({len(last_user)} chars): {last_user!r}"
    )
    prompt_tokens = sum(
        len(str(m.get("content", "")).split()) for m in messages if isinstance(m, dict)
    )
    completion_tokens = len(text.split())
    return {
        "id": "chatcmpl-local-demo",
        "object": "chat.completion",
        "created": 0,  # deterministic: the receipt timestamp carries real time
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }


def create_app(
    *,
    completion: CompletionCallable | None = None,
    sink: EvidenceSink | None = None,
    policy: EvidencePolicy | None = None,
    sink_dir: str | Path | None = None,
) -> FastAPI:
    """Build the demo proxy app around a completion callable and a sink."""
    logger = SZLEvidenceLogger(sink=sink, policy=policy, sink_dir=sink_dir)
    backend = completion or local_demo_completion
    backend_name = getattr(backend, "__name__", type(backend).__name__)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202 — FastAPI owns the signature
        await logger.sink.start()
        yield
        await logger.aclose()

    app = FastAPI(
        title="szl-evidence-litellm demo proxy",
        version="0.1.0",
        description=(
            "OpenAI-shaped demo surface proving the evidence plane: every "
            "request is receipted, hash-chained, and correlatable via the "
            f"{RECEIPT_ID_HEADER} header. Backend: {backend_name}."
        ),
        lifespan=lifespan,
    )
    app.state.evidence_logger = logger

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            return JSONResponse(
                status_code=400,
                content={"error": {"message": "body must be an object with messages[]"}},
            )
        call_kwargs = {
            "litellm_call_id": f"proxy:{time.time_ns()}",
            "model": body.get("model"),
            "messages": body["messages"],
            "custom_llm_provider": "local-demo",
            **{
                k: v
                for k, v in body.items()
                if k not in {"model", "messages"} and isinstance(k, str)
            },
        }
        started = time.perf_counter()
        try:
            result = backend(body)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:  # noqa: BLE001 — receipt the failure, then report it
            await logger.async_log_failure_event(
                call_kwargs, exc, started, time.perf_counter()
            )
            receipt_ids = logger.receipt_ids_for(call_kwargs["litellm_call_id"])
            headers = {RECEIPT_ID_HEADER: receipt_ids[-1]} if receipt_ids else {}
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "message": f"completion backend failed: {type(exc).__name__}",
                        "receipt_ids": receipt_ids,
                    }
                },
                headers=headers,
            )
        await logger.async_log_success_event(
            call_kwargs, result, started, time.perf_counter()
        )
        receipt_ids = logger.receipt_ids_for(call_kwargs["litellm_call_id"])
        headers = {RECEIPT_ID_HEADER: receipt_ids[-1]} if receipt_ids else {}
        return JSONResponse(content=jsonable_response(result), headers=headers)

    # Static route BEFORE the path-parameter route, or "verify" would be
    # swallowed as a receipt id.
    @app.get("/receipts/verify")
    async def receipts_verify() -> dict[str, Any]:
        return verify_sink(logger.sink.directory)

    @app.get("/receipts/stats")
    async def receipts_stats() -> dict[str, Any]:
        return logger.stats()

    @app.get("/receipts/{receipt_id}")
    async def receipts_get(receipt_id: str) -> JSONResponse:
        found = logger.sink.receipt_by_id(receipt_id)
        if found is None:
            return JSONResponse(
                status_code=404, content={"error": f"no receipt {receipt_id} in this sink"}
            )
        receipt, evidence_doc = found
        return JSONResponse(content={"receipt": receipt, "evidence": evidence_doc})

    return app


def jsonable_response(result: Any) -> Any:
    """Best-effort JSON for whatever the completion callable returned."""
    from .payload import jsonable

    return jsonable(result)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin wrapper
    from .cli import main as cli_main

    return cli_main(["demo-proxy", *(argv or [])])
