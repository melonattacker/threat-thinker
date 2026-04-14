from __future__ import annotations

from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from threat_thinker.rag import (
    DEFAULT_RAG_CANDIDATES,
    DEFAULT_RAG_MIN_SCORE,
    DEFAULT_RAG_RERANKER,
    DEFAULT_RAG_STRATEGY,
    DEFAULT_TOPK,
)

JobStatus = Literal["queued", "running", "succeeded", "failed", "expired"]
RagStrategy = Literal["hybrid", "dense"]
RagReranker = Literal["auto", "local", "llm", "off"]


class InputType(str, Enum):
    MERMAID = "mermaid"
    DRAWIO = "drawio"
    THREAT_DRAGON = "threat-dragon"
    IMAGE = "image"
    IR = "ir"


class InputPayload(BaseModel):
    type: InputType
    content: Optional[str] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None
    data_b64: Optional[str] = Field(
        default=None, description="Base64 encoded bytes for file uploads."
    )


class ContextPayload(BaseModel):
    content: Optional[str] = None
    filename: Optional[str] = None
    content_type: Optional[str] = None
    data_b64: Optional[str] = Field(
        default=None, description="Base64 encoded bytes for context uploads."
    )


class ReportFormat(str, Enum):
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    THREAT_DRAGON = "threat-dragon"


class AnalyzeOptions(BaseModel):
    report_formats: List[ReportFormat] = Field(
        default_factory=list, description="List of report formats to produce."
    )
    language: Optional[str] = None
    infer_hints: bool = False
    require_asvs: bool = False
    min_confidence: float = 0.5
    topn: Optional[int] = 10
    autodetect: bool = True
    use_rag: bool = False
    kb_names: List[str] = Field(default_factory=list)
    rag_topk: int = DEFAULT_TOPK
    rag_strategy: RagStrategy = DEFAULT_RAG_STRATEGY
    rag_reranker: RagReranker = DEFAULT_RAG_RERANKER
    rag_candidates: int = DEFAULT_RAG_CANDIDATES
    rag_min_score: float = DEFAULT_RAG_MIN_SCORE
    drawio_page: Optional[str] = None
    contexts: List[ContextPayload] = Field(default_factory=list)
    prompt_token_limit: Optional[int] = None


class AnalyzeRequest(BaseModel):
    input: InputPayload
    report_formats: List[ReportFormat] = Field(
        default_factory=list, description="List of report formats to produce."
    )
    language: Optional[str] = None
    infer_hints: bool = False
    require_asvs: bool = False
    min_confidence: float = 0.5
    topn: Optional[int] = 10
    autodetect: bool = True
    use_rag: bool = False
    kb_names: List[str] = Field(default_factory=list)
    rag_topk: int = DEFAULT_TOPK
    rag_strategy: RagStrategy = DEFAULT_RAG_STRATEGY
    rag_reranker: RagReranker = DEFAULT_RAG_RERANKER
    rag_candidates: int = DEFAULT_RAG_CANDIDATES
    rag_min_score: float = DEFAULT_RAG_MIN_SCORE
    drawio_page: Optional[str] = None
    contexts: List[ContextPayload] = Field(default_factory=list)
    prompt_token_limit: Optional[int] = None


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
