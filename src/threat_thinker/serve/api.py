from __future__ import annotations

import base64
import io
import logging
import zipfile
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Response,
    Request,
    UploadFile,
    status,
)
from starlette.datastructures import UploadFile as StarletteUploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from redis.asyncio import from_url as redis_from_url

from threat_thinker.serve.auth import APIKeyAuthenticator
from threat_thinker.serve.config import ServeConfig
from threat_thinker.serve.jobstore import (
    AsyncJobStore,
    STATUS_EXPIRED,
    STATUS_QUEUED,
)
from threat_thinker.serve.ratelimit import RateLimiter, resolve_client_ip
from threat_thinker.serve.schemas import (
    AnalyzeRequest,
    AnalyzeOptions,
    InputPayload,
    InputType,
    JobResponse,
    JobResultResponse,
    JobStatusResponse,
    ReportContent,
    ReportFormat,
)

logger = logging.getLogger(__name__)


def _extension_for_format(fmt: str) -> str:
    return {
        "markdown": ".md",
        "html": ".html",
        "json": ".json",
        "threat-dragon": ".threat-dragon.json",
    }.get(fmt, ".txt")


def _build_zip_bytes(job_id: str, reports: list[ReportContent]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry in reports:
            suffix = _extension_for_format(entry.report_format)
            filename = f"threat-thinker-{job_id}{suffix}"
            zf.writestr(filename, entry.content or "")
    buffer.seek(0)
    return buffer.read()


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


def _detect_input_type(filename: Optional[str]) -> Optional[InputType]:
    if not filename:
        return None
    name = filename.lower()
    if name.endswith((".mmd", ".mermaid")):
        return InputType.MERMAID
    if name.endswith((".drawio", ".xml")):
        return InputType.DRAWIO
    if name.endswith(".json"):
        return InputType.THREAT_DRAGON
    if name.endswith((".png", ".jpg", ".jpeg", ".webp")):
        return InputType.IMAGE
    return None


def _input_type_value(value: object) -> str:
    if isinstance(value, InputType):
        return value.value
    return str(value)


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


def _normalize_request(req: AnalyzeRequest, config: ServeConfig) -> AnalyzeRequest:
    allowed: set[str] = {"markdown", "html", "json", "threat-dragon"}

    def _format_value(fmt: object) -> str:
        if isinstance(fmt, ReportFormat):
            return fmt.value
        return str(fmt)

    formats = [
        _format_value(fmt)
        for fmt in req.report_formats
        if _format_value(fmt) in allowed
    ]
    if not formats:
        formats = [config.engine.report.default_format]
    req.report_formats = [ReportFormat(fmt) for fmt in formats]
    if not req.language:
        req.language = config.engine.report.default_language
    return req


def _options_from_request(req: AnalyzeRequest) -> AnalyzeOptions:
    return AnalyzeOptions(
        report_formats=req.report_formats,
        language=req.language,
        infer_hints=req.infer_hints,
        require_asvs=req.require_asvs,
        min_confidence=req.min_confidence,
        topn=req.topn,
        autodetect=req.autodetect,
    )


def _analyze_request_body_schema() -> dict:
    json_schema = AnalyzeRequest.model_json_schema()
    multipart_schema = {
        "type": "object",
        "properties": {
            "file": {"type": "string", "format": "binary"},
            "type": {"type": "string", "enum": [t.value for t in InputType]},
            "options": {
                "type": "string",
                "description": "AnalyzeOptions JSON string.",
            },
        },
        "required": ["file"],
    }
    return {
        "required": True,
        "content": {
            "application/json": {"schema": json_schema},
            "multipart/form-data": {"schema": multipart_schema},
        },
    }


def create_app(config: ServeConfig) -> FastAPI:
    docs_url = "/docs" if config.server.openapi.docs_enabled else None
    redoc_url = "/redoc" if config.server.openapi.redoc_enabled else None
    openapi_url = "/openapi.json" if config.server.openapi.enabled else None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await redis.close()

    app = FastAPI(
        title="Threat Thinker Serve",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
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
        client_host = request.client.host if request.client else None
        client_ip = resolve_client_ip(
            client_host, request.headers, config.security.rate_limit
        )
        scope_key = rate_limiter.scope_key(client_ip, api_key)
        allowed = await rate_limiter.allow(scope_key)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded.",
            )
        return api_key

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.post(
        "/v1/analyze",
        response_model=JobResponse,
        status_code=status.HTTP_202_ACCEPTED,
        openapi_extra={"requestBody": _analyze_request_body_schema()},
    )
    async def analyze(
        request: Request,
        _api_key: Optional[str] = Depends(rate_dep),
    ):
        _validate_body_size(request, config.security.request_limits.max_body_bytes)

        content_type = (request.headers.get("content-type") or "").lower()
        if content_type.startswith("multipart/form-data"):
            form = await request.form()
            file = form.get("file")
            if file is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="file is required for multipart/form-data requests.",
                )
            if not isinstance(file, (UploadFile, StarletteUploadFile)):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid file payload.",
                )
            raw_type = form.get("type")
            input_type = None
            if raw_type:
                try:
                    input_type = InputType(str(raw_type))
                except ValueError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid input type: {raw_type}",
                    ) from exc
            options = form.get("options")
            parsed_options = AnalyzeOptions()
            if options is not None and str(options).strip():
                try:
                    parsed_options = AnalyzeOptions.model_validate_json(str(options))
                except Exception as exc:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid options JSON: {exc}",
                    ) from exc
            effective_autodetect = (
                config.engine.autodetect and parsed_options.autodetect
            )
            input_type = input_type or (
                _detect_input_type(file.filename) if effective_autodetect else None
            )
            if not effective_autodetect and not input_type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Input type is required.",
                )
            if not input_type:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unable to detect input type from filename.",
                )
            input_type_value = _input_type_value(input_type)
            if input_type_value not in config.engine.allowed_inputs:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Input type '{input_type_value}' is not allowed.",
                )
            raw_bytes = await file.read()
            if input_type == InputType.IMAGE:
                if (
                    file.content_type
                    not in config.security.request_limits.allowed_image_types
                ):
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

            req = AnalyzeRequest(
                input=input_payload,
                report_formats=parsed_options.report_formats,
                language=parsed_options.language,
                infer_hints=parsed_options.infer_hints,
                require_asvs=parsed_options.require_asvs,
                min_confidence=parsed_options.min_confidence,
                topn=parsed_options.topn,
                autodetect=effective_autodetect,
            )
            req = _normalize_request(req, config)
            job_payload = req
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
            options = _options_from_request(job_payload)
            job_payload.autodetect = config.engine.autodetect and options.autodetect

            input_type_value = _input_type_value(job_payload.input.type)
            if input_type_value not in config.engine.allowed_inputs:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Input type '{input_type_value}' is not allowed.",
                )

            if job_payload.input.type == "image":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Image inputs must be uploaded as multipart/form-data.",
                )

            if (
                job_payload.input.content
                and len(job_payload.input.content)
                > config.security.request_limits.max_text_chars
            ):
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="Diagram text exceeds configured limit.",
                )
            job_payload = _normalize_request(job_payload, config)

        payload_dict = job_payload.model_dump()

        job_id = await job_store.enqueue(payload_dict)
        logger.info("Enqueued job %s", job_id)
        return JobResponse(job_id=job_id, status=STATUS_QUEUED)

    @app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
    async def get_job(job_id: str, _api_key: Optional[str] = Depends(auth_dep)):
        status_payload = await job_store.get_status(job_id)
        if status_payload["status"] == STATUS_EXPIRED:
            return JobStatusResponse(job_id=job_id, status=STATUS_EXPIRED)
        return JobStatusResponse(**status_payload)

    @app.get("/v1/jobs/{job_id}/result", response_model=JobResultResponse)
    async def get_result(job_id: str, _api_key: Optional[str] = Depends(auth_dep)):
        result = await job_store.get_result(job_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Result not available.",
            )
        reports = result.get("reports") or []
        parsed_reports = [
            ReportContent(
                report_format=entry.get("report_format"),
                content=entry.get("content", ""),
            )
            for entry in reports
            if entry.get("report_format")
        ]
        if not parsed_reports and result.get("report_format"):
            parsed_reports = [
                ReportContent(
                    report_format=result.get("report_format"),
                    content=result.get("content", ""),
                )
            ]
        return JobResultResponse(
            reports=parsed_reports,
            duration_ms=int(result["duration_ms"])
            if result.get("duration_ms")
            else None,
            model=result.get("model"),
        )

    @app.get("/v1/jobs/{job_id}/result.zip")
    async def download_result(job_id: str, _api_key: Optional[str] = Depends(auth_dep)):
        result = await job_store.get_result(job_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Result not available.",
            )
        reports = result.get("reports") or []
        parsed_reports = [
            ReportContent(
                report_format=entry.get("report_format"),
                content=entry.get("content", ""),
            )
            for entry in reports
            if entry.get("report_format")
        ]
        if not parsed_reports:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No report content found for this job.",
            )
        zip_bytes = _build_zip_bytes(job_id, parsed_reports)
        headers = {
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="threat-thinker-{job_id}.zip"',
        }
        return Response(
            content=zip_bytes, media_type="application/zip", headers=headers
        )

    return app
