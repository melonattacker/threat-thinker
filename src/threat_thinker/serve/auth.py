from __future__ import annotations

import logging
from typing import Iterable, Optional

from fastapi import HTTPException, Request, status

from threat_thinker.serve.config import AuthConfig

logger = logging.getLogger(__name__)


class APIKeyAuthenticator:
    """
    Simple API key authenticator for FastAPI routes.
    """

    def __init__(self, config: AuthConfig) -> None:
        self.config = config
        self._keys = {k.strip() for k in config.api_keys if k.strip()}

    def _extract_token(self, request: Request) -> Optional[str]:
        header = self.config.header_name
        raw = request.headers.get(header)
        if not raw:
            return None
        if self.config.scheme == "bearer":
            if not raw.lower().startswith("bearer "):
                return None
            return raw.split(" ", 1)[-1].strip()
        return raw.strip()

    def authenticate(self, request: Request) -> Optional[str]:
        if self.config.mode == "none":
            return None
        token = self._extract_token(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid API key.",
            )
        if self._keys and token not in self._keys:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized API key.",
            )
        return token

    def add_keys(self, keys: Iterable[str]) -> None:
        for key in keys:
            cleaned = (key or "").strip()
            if cleaned:
                self._keys.add(cleaned)
