"""FastAPI application factory and lifespan setup."""
import logging
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from api.routes import router
from api.user_auth import router as auth_router
from core.config import settings

_STATIC_DIR = Path(__file__).parent.parent / "static"

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit_default])


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "scans").mkdir(exist_ok=True)

    from db.database import init_db
    await init_db()
    log.info("Database initialized (url: %s)", settings.database_url.split("@")[-1])

    if not settings.require_auth:
        try:
            from api.auth import _ensure_demo_org
            from db.database import get_session
            async with get_session() as session:
                await _ensure_demo_org(session)
        except Exception as e:
            log.warning("Could not create demo org: %s", e)

    # Storage backend initialization
    try:
        from core.storage_backend import get_storage_backend
        backend = get_storage_backend()
        log.info("Storage backend ready: %s", type(backend).__name__)
    except Exception as e:
        log.warning("Storage backend initialization warning: %s", e)

    tools_status = {
        "zap": bool(shutil.which("zap.sh") or shutil.which("zaproxy") or settings.zap_api_url),
        "nmap": bool(shutil.which("nmap")),
        "nikto": bool(shutil.which("nikto")),
    }
    ai_enabled = bool(settings.anthropic_api_key or settings.gemini_api_key)
    billing_enabled = bool(settings.stripe_secret_key)

    log.info(
        "VulnAuditor ASPM starting | env=%s tools=%s ai=%s billing=%s",
        settings.app_env, tools_status, ai_enabled, billing_enabled,
    )
    yield


app = FastAPI(
    title="VulnAuditor ASPM",
    description=(
        "Application Security Posture Management platform. "
        "Orchestrates SAST, SCA, DAST, and IaC scanners with AI-powered analysis.\n\n"
        "**Authentication**: Use `Authorization: Bearer <jwt>` or `X-API-Key: <key>`.\n"
        "**API versioning**: Stable endpoints available at `/api/v1/`. Legacy endpoints at root path (deprecated)."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# ── Security headers middleware ────────────────────────────────────────────────

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


# ── CORS ───────────────────────────────────────────────────────────────────────

_cors_origins = [
    settings.frontend_url,
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:80",
    "http://localhost",
]

# Production: restrict to frontend_url. Development: allow all origins.
if settings.is_production:
    _cors_allow_origins = [settings.frontend_url]
    _cors_allow_origin_regex = None
else:
    _cors_allow_origins = ["*"]
    _cors_allow_origin_regex = None

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_allow_origins,
    allow_credentials=False if "*" in _cors_allow_origins else True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Requested-With"],
)

# ── Rate limiting ──────────────────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Session middleware (required for OIDC state) ───────────────────────────────

try:
    from starlette.middleware.sessions import SessionMiddleware
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.jwt_secret,
        same_site="lax",
        https_only=settings.is_production,
    )
except ImportError:
    log.warning("starlette[full] not installed — OIDC SSO state management unavailable")

# ── Routers ────────────────────────────────────────────────────────────────────

# Auth router (always at /auth — no version prefix for backward compat)
app.include_router(auth_router)

# Legacy API routes at root path (backward compatible, deprecated in v3)
app.include_router(router)

# Versioned API v1 — preferred path for all new integrations
from api.v1.router import v1_router
app.include_router(v1_router)

# ── Static UI ──────────────────────────────────────────────────────────────────

if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_ui() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html")


# ── Error handlers ─────────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "type": type(exc).__name__},
    )
