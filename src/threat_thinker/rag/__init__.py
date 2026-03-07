"""
Local RAG utilities for Threat Thinker.

This package exposes helper functions to build and query on-disk knowledge bases
that store chunked text documents and their embeddings.  The public API lives in
`rag.local`.
"""

from .local import (
    KnowledgeBaseError,
    DEFAULT_EMBED_MODEL,
    DEFAULT_CHUNK_TOKENS,
    DEFAULT_CHUNK_OVERLAP,
    DEFAULT_TOPK,
    DEFAULT_RAG_STRATEGY,
    DEFAULT_RAG_RERANKER,
    DEFAULT_RAG_CANDIDATES,
    DEFAULT_RAG_MIN_SCORE,
    RAG_STRATEGIES,
    RAG_RERANKERS,
    RetrievalOptions,
    build_kb,
    list_kbs,
    search_kb,
    remove_kb,
    generate_graph_query,
    generate_graph_queries,
    retrieve_context_for_graph,
    attach_rag_sources_to_threats,
    get_kb_root,
)

__all__ = [
    "KnowledgeBaseError",
    "DEFAULT_EMBED_MODEL",
    "DEFAULT_CHUNK_TOKENS",
    "DEFAULT_CHUNK_OVERLAP",
    "DEFAULT_TOPK",
    "DEFAULT_RAG_STRATEGY",
    "DEFAULT_RAG_RERANKER",
    "DEFAULT_RAG_CANDIDATES",
    "DEFAULT_RAG_MIN_SCORE",
    "RAG_STRATEGIES",
    "RAG_RERANKERS",
    "RetrievalOptions",
    "build_kb",
    "list_kbs",
    "search_kb",
    "remove_kb",
    "generate_graph_query",
    "generate_graph_queries",
    "retrieve_context_for_graph",
    "attach_rag_sources_to_threats",
    "get_kb_root",
]
