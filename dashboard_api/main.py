"""
dashboard_api/main.py
Application factory: middleware, CORS, exception handlers, router wiring.

Run locally:
    .venv/Scripts/python -m uvicorn dashboard_api.main:app --reload
Docs at /docs once DASHBOARD_API_KEY is set in the environment.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

from dashboard_api.config import api_settings
from dashboard_api.errors import install_exception_handlers
from dashboard_api.routers import admin_logs, cves, health, meta, stats
from dashboard_api.security import (
    SecurityHeadersMiddleware,
    rate_limit,
    require_admin_key,
    require_api_key,
)

_STATIC_DIR = Path(__file__).parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(
        title="CVE WatchDog — Dashboard API",
        version="1.0.0",
        description="Read-only, API-key-gated query layer over the enriched CVE store.",
        # Disable the CDN-backed default; we serve Swagger UI from local assets
        # so /docs works offline and behind CDN-blocking proxies/extensions.
        docs_url=None,
        redoc_url=None,
    )

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/docs", include_in_schema=False)
    def custom_swagger_ui():
        return get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title=f"{app.title} — docs",
            swagger_js_url="/static/swagger-ui-bundle.js",
            swagger_css_url="/static/swagger-ui.css",
        )

    # CORS — locked to configured origins.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=api_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["X-API-Key", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    install_exception_handlers(app)

    # Public: health/readiness (no key, no rate limit).
    app.include_router(health.router)

    # Data routes: every request needs a valid API key and passes the limiter.
    protected = [Depends(require_api_key), Depends(rate_limit)]
    app.include_router(cves.router, dependencies=protected)
    app.include_router(stats.router, dependencies=protected)
    app.include_router(meta.router, dependencies=protected)

    # Admin routes: pipeline runs + logs, gated by the stronger admin key.
    admin = [Depends(require_admin_key), Depends(rate_limit)]
    app.include_router(admin_logs.router, dependencies=admin)

    return app


app = create_app()
