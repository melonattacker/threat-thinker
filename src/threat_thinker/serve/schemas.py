from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field

JobStatus = Literal["queued", "running", "succeeded", "failed", "expired"]


class InputPayload(BaseModel):
    type: Literal["mermaid", "drawio", "threat_dragon", "image"]
    content: Optional[str] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None
    data_b64: Optional[str] = Field(
        default=None, description="Base64 encoded bytes for file uploads."
    )


ReportFormat = Literal["markdown", "html", "json"]


class AnalyzeOptions(BaseModel):
    report_format: Optional[ReportFormat] = Field(
        default=None, description="Deprecated: use report_formats for multiple outputs."
    )
    report_formats: List[ReportFormat] = Field(
        default_factory=list, description="List of report formats to produce."
    )
    language: str = "en"
    infer_hints: bool = False
    require_asvs: bool = False
    min_confidence: float = 0.5
    topn: Optional[int] = 10
    autodetect: bool = True


class AnalyzeRequest(BaseModel):
    input: InputPayload
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


class JobResponse(BaseModel):
    job_id: str
    status: JobStatus


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    error: Optional[str] = None


class ReportContent(BaseModel):
    report_format: ReportFormat
    content: str


class JobResultResponse(BaseModel):
    reports: List[ReportContent]
    duration_ms: Optional[int] = None
    model: Optional[str] = None
