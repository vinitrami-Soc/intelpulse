"""A refusal with a stable code, answered as {"error": code, "detail": text} (spec 10).

`detail` stays a plain sentence, so 1.x clients that show it keep working.
"""
from __future__ import annotations

from fastapi import HTTPException


class ApiError(HTTPException):
    def __init__(self, status: int, error: str, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(status_code=status, detail=detail, headers=headers)
        self.error = error
