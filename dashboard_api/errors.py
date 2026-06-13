"""
dashboard_api/errors.py
One consistent error envelope + exception handlers.

Every error response is shaped as:
    {"error": {"code": "<machine_code>", "message": "<human readable>",
               "detail": <optional, structured>}}

Handlers never leak stack traces, SQL, or internal exception text to clients.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("dashboard_api")


class APIError(Exception):
    """Raised by routes/services to produce a controlled error envelope."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        detail: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail


def error_envelope(code: str, message: str, detail: Any | None = None) -> dict:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if detail is not None:
        body["error"]["detail"] = detail
    return body


def not_found(resource: str, identifier: str) -> APIError:
    return APIError(
        status_code=404,
        code="not_found",
        message=f"{resource} '{identifier}' was not found.",
    )


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _handle_api_error(_: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(exc.code, exc.message, exc.detail),
        )

    @app.exception_handler(RequestValidationError)
    async def _handle_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Surface *which* parameter is wrong, but only echo the client's own
        # input — no internals.
        detail = [
            {
                "field": ".".join(str(p) for p in err.get("loc", []) if p != "query"),
                "message": err.get("msg", "invalid value"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=error_envelope(
                "validation_error", "One or more request parameters are invalid.", detail
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _handle_http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            429: "rate_limited",
        }.get(exc.status_code, "http_error")
        message = exc.detail if isinstance(exc.detail, str) else "Request could not be completed."
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(code, message),
        )

    @app.exception_handler(Exception)
    async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Log the real cause server-side; return a generic envelope to the client.
        logger.exception("Unhandled error on %s %s: %r", request.method, request.url.path, exc)
        return JSONResponse(
            status_code=500,
            content=error_envelope(
                "internal_error", "An unexpected error occurred. Please try again later."
            ),
        )
