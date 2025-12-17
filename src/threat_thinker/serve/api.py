from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from redis.asyncio import from_url as redis_from_url

from threat_thinker.serve.auth import APIKeyAuthenticator
from threat_thinker.serve.config import ServeConfig
from threat_thinker.serve.jobstore import (
    AsyncJobStore,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_SUCCEEDED,
)
from threat_thinker.serve.ratelimit import RateLimiter
from threat_thinker.serve.schemas import (
    AnalyzeOptions,
    AnalyzeRequest,
    InputPayload,
    JobResponse,
    JobResultResponse,
    JobStatusResponse,
    ReportContent,
    ReportFormat,
)

logger = logging.getLogger(__name__)


def _apply_security_schemes(app: FastAPI, config: ServeConfig) -> None:
    """Inject security schemes so Swagger UI exposes the Authorize button."""
    auth = config.security.auth
    scheme_name = "ApiKeyAuth"

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        components = openapi_schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        if auth.scheme == "bearer":
            security_schemes[scheme_name] = {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        else:
            security_schemes[scheme_name] = {
                "type": "apiKey",
                "in": "header",
                "name": auth.header_name or "Authorization",
            }
        openapi_schema["security"] = [{scheme_name: []}]
        app.openapi_schema = openapi_schema
        return app.openapi_schema

    if config.server.openapi.enabled:
        app.openapi = custom_openapi  # type: ignore[assignment]


def _detect_input_type(filename: Optional[str]) -> Optional[str]:
    if not filename:
        return None
    name = filename.lower()
    if name.endswith((".mmd", ".mermaid")):
        return "mermaid"
    if name.endswith((".drawio", ".xml")):
        return "drawio"
    if name.endswith(".json"):
        return "threat_dragon"
    if name.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return "image"
    return None


def _validate_body_size(request: Request, limit: int) -> None:
    if not limit:
        return
    length = request.headers.get("content-length")
    try:
        if length and int(length) > limit:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Request body exceeds configured limit.",
            )
    except ValueError:
        return


def _normalize_options(opts: AnalyzeOptions, config: ServeConfig) -> AnalyzeOptions:
    allowed: set[ReportFormat] = {"markdown", "html", "json"}
    formats = [fmt for fmt in opts.report_formats if fmt in allowed]
    if opts.report_format and opts.report_format in allowed:
        # keep deprecated field as a single-item list if no other formats supplied
        formats = formats or [opts.report_format]
    if not formats:
        formats = [config.engine.report.default_format]  # type: ignore[list-item]
    opts.report_formats = formats
    opts.report_format = None
    if not opts.language:
        opts.language = config.engine.report.default_language
    return opts


def create_app(config: ServeConfig) -> FastAPI:
    docs_url = "/docs" if config.server.openapi.docs_enabled else None
    redoc_url = "/redoc" if config.server.openapi.redoc_enabled else None
    openapi_url = "/openapi.json" if config.server.openapi.enabled else None

    app = FastAPI(
        title="Threat Thinker Serve",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        version="0.1.0",
    )

    if config.server.cors.enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.server.cors.allow_origins or ["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    authenticator = APIKeyAuthenticator(config.security.auth)
    redis = redis_from_url(config.queue.redis_url, decode_responses=True)
    job_store = AsyncJobStore(redis, config.queue)
    rate_limiter = RateLimiter(redis, config.security.rate_limit)
    _apply_security_schemes(app, config)

    async def auth_dep(request: Request) -> Optional[str]:
        return authenticator.authenticate(request)

    async def rate_dep(request: Request, api_key: Optional[str] = Depends(auth_dep)):
        scope_key = rate_limiter.scope_key(request.client.host if request.client else None, api_key)
        allowed = await rate_limiter.allow(scope_key)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded.",
            )
        return api_key

    @app.on_event("shutdown")
    async def _shutdown_event() -> None:
        await redis.close()

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.post("/v1/analyze", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
    async def analyze(
        request: Request,
        _api_key: Optional[str] = Depends(rate_dep),
        file: UploadFile = File(None),
        type: Optional[str] = Form(None),
        options: Optional[str] = Form(None),
    ):
        _validate_body_size(request, config.security.request_limits.max_body_bytes)

        if file is not None:
            input_type = type or _detect_input_type(file.filename) or ""
            if config.engine.autodetect is False and not type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Input type is required.",
                )
            if not input_type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unable to detect input type from filename.",
                )
            if input_type not in config.engine.allowed_inputs:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Input type '{input_type}' is not allowed.",
                )
            raw_bytes = await file.read()
            if input_type == "image":
                if file.content_type not in config.security.request_limits.allowed_image_types:
                    raise HTTPException(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        detail="Image content type not allowed.",
                    )
                if len(raw_bytes) > config.security.request_limits.max_image_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Image exceeds configured size limit.",
                    )
                input_payload = InputPayload(
                    type=input_type,
                    filename=file.filename,
                    content_type=file.content_type,
                    data_b64=base64.b64encode(raw_bytes).decode("utf-8"),
                )
            else:
                try:
                    decoded = raw_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Uploaded file is not valid UTF-8 text.",
                    )
                if len(decoded) > config.security.request_limits.max_text_chars:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Diagram text exceeds configured limit.",
                    )
                input_payload = InputPayload(
                    type=input_type,
                    filename=file.filename,
                    content=decoded,
                    content_type=file.content_type,
                )
            try:
                opts_payload = (
                    AnalyzeOptions.model_validate_json(options)
                    if options
                    else AnalyzeOptions()
                )
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid options payload: {exc}",
                ) from exc
            opts_payload = _normalize_options(opts_payload, config)
            job_payload = AnalyzeRequest(input=input_payload, options=opts_payload)
        else:
            try:
                body = await request.json()
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid JSON payload: {exc}",
                ) from exc
            try:
                job_payload = AnalyzeRequest.model_validate(body)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid analyze request: {exc}",
                ) from exc

            if job_payload.input.type not in config.engine.allowed_inputs:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Input type '{job_payload.input.type}' is not allowed.",
                )

            if job_payload.input.type == "image":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Image inputs must be uploaded as multipart/form-data.",
                )

            if (
                job_payload.input.content
                and len(job_payload.input.content) > config.security.request_limits.max_text_chars
            ):
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Diagram text exceeds configured limit.",
                )
            job_payload.options = _normalize_options(job_payload.options, config)

        payload_dict = job_payload.model_dump()
        payload_dict["options"]["report_formats"] = job_payload.options.report_formats
        payload_dict["options"]["language"] = (
            job_payload.options.language or config.engine.report.default_language
        )

        job_id = await job_store.enqueue(payload_dict)
        logger.info("Enqueued job %s", job_id)
        return JobResponse(job_id=job_id, status=STATUS_QUEUED)

    @app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
    async def get_job(job_id: str, _api_key: Optional[str] = Depends(rate_dep)):
        status_payload = await job_store.get_status(job_id)
        if status_payload["status"] == STATUS_EXPIRED:
            return JobStatusResponse(job_id=job_id, status=STATUS_EXPIRED)
        return JobStatusResponse(**status_payload)

    @app.get("/v1/jobs/{job_id}/result", response_model=JobResultResponse)
    async def get_result(job_id: str, _api_key: Optional[str] = Depends(rate_dep)):
        result = await job_store.get_result(job_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Result not available.",
            )
        reports = result.get("reports") or []
        parsed_reports = [
            ReportContent(report_format=entry.get("report_format"), content=entry.get("content", ""))
            for entry in reports
            if entry.get("report_format")
        ]
        if not parsed_reports and result.get("report_format"):
            parsed_reports = [
                ReportContent(
                    report_format=result.get("report_format"), content=result.get("content", "")
                )
            ]
        return JobResultResponse(
            reports=parsed_reports,
            duration_ms=int(result["duration_ms"]) if result.get("duration_ms") else None,
            model=result.get("model"),
        )

    return app
