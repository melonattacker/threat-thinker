from __future__ import annotations

import os
import time
from collections import deque
from threading import Lock
from typing import Deque, Dict, Optional

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


class AnalyzeInput(BaseModel):
    type: str
    content: str


class AnalyzeOptions(BaseModel):
    language: str = Field(default="en")


class AnalyzeRequest(BaseModel):
    input: AnalyzeInput
    options: AnalyzeOptions


app = FastAPI(title="Threat Thinker Demo Proxy", docs_url=None, redoc_url=None)

BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")

BACKEND_URL = os.getenv("TT_BACKEND_URL", "http://server:8000").rstrip("/")
BACKEND_API_KEY = os.getenv("TT_BACKEND_API_KEY", "")

MAX_INPUT_CHARS = int(os.getenv("DEMO_MAX_INPUT_CHARS", "200000"))
MAX_BODY_BYTES = int(os.getenv("DEMO_MAX_BODY_BYTES", "400000"))
RATE_LIMIT_RPM = int(os.getenv("DEMO_RATE_LIMIT_RPM", "0"))

RATE_LOCK = Lock()
REQUEST_LOG: Dict[str, Deque[float]] = {}

ALLOWED_INPUT_TYPES = {
    "mermaid": "mermaid",
    "drawio": "drawio",
    "threat_dragon": "threat-dragon",
}

ALLOWED_LANGUAGES = {"en", "ja"}


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large."},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header."},
            )
    return await call_next(request)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if RATE_LIMIT_RPM <= 0 or not request.url.path.startswith("/api/"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    with RATE_LOCK:
        entries = REQUEST_LOG.setdefault(client_ip, deque())
        while entries and entries[0] < window_start:
            entries.popleft()
        if len(entries) >= RATE_LIMIT_RPM:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down."},
            )
        entries.append(now)

    return await call_next(request)


@app.get("/")
async def index() -> HTMLResponse:
    index_path = os.path.join(STATIC_DIR, "index.html")
    return FileResponse(index_path, media_type="text/html")


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest) -> JSONResponse:
    if not BACKEND_API_KEY:
        raise HTTPException(status_code=500, detail="Backend API key is not set.")

    if payload.input.type not in ALLOWED_INPUT_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported diagram type.")

    if payload.options.language not in ALLOWED_LANGUAGES:
        raise HTTPException(status_code=400, detail="Unsupported language.")

    content = payload.input.content or ""
    if len(content) > MAX_INPUT_CHARS:
        raise HTTPException(status_code=413, detail="Diagram input is too large.")

    backend_payload = {
        "input": {
            "type": ALLOWED_INPUT_TYPES[payload.input.type],
            "content": content,
        },
        "report_formats": ["markdown", "html"],
        "language": payload.options.language,
        "topn": 5,
    }

    response = _backend_request(
        "post",
        "/v1/analyze",
        json=backend_payload,
    )

    return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/jobs/{job_id}")
async def job_status(job_id: str) -> JSONResponse:
    response = _backend_request("get", f"/v1/jobs/{job_id}")
    return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/jobs/{job_id}/result")
async def job_result(job_id: str) -> JSONResponse:
    response = _backend_request("get", f"/v1/jobs/{job_id}/result")
    if response.status_code != 200:
        return JSONResponse(status_code=response.status_code, content=_safe_json(response))

    data = response.json()
    reports = data.get("reports", [])
    markdown = _extract_report(reports, "markdown")
    html = _extract_report(reports, "html")

    if markdown is None or html is None:
        raise HTTPException(status_code=502, detail="Missing report content.")

    return JSONResponse(
        content={
            "job_id": job_id,
            "reports": {"markdown": markdown, "html": html},
            "duration_ms": data.get("duration_ms"),
            "model": data.get("model"),
        }
    )


@app.get("/api/jobs/{job_id}/download/html")
async def download_html(job_id: str) -> Response:
    response = _backend_request("get", f"/v1/jobs/{job_id}/result")
    if response.status_code != 200:
        return JSONResponse(status_code=response.status_code, content=_safe_json(response))

    data = response.json()
    reports = data.get("reports", [])
    html = _extract_report(reports, "html")
    if html is None:
        raise HTTPException(status_code=502, detail="Missing HTML report content.")

    filename = f"threat-report-{job_id}.html"
    headers = {"Content-Disposition": f"attachment; filename=\"{filename}\""}
    return Response(content=html, media_type="text/html", headers=headers)


def _backend_request(method: str, path: str, **kwargs) -> requests.Response:
    url = f"{BACKEND_URL}{path}"
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {BACKEND_API_KEY}"
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=30,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Backend request failed: {exc}") from exc

    return response


def _extract_report(reports: list, report_format: str) -> Optional[str]:
    for report in reports:
        if report.get("report_format") == report_format:
            return report.get("content")
    return None


def _safe_json(response: requests.Response) -> dict:
    try:
        return response.json()
    except ValueError:
        return {"detail": response.text}


app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")
