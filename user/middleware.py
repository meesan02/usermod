from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from .service import UserService
from .db import get_db


class AuthCodeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip authentication for docs, openapi, redoc, register, and forgot-password endpoints
        
        # if request.url.path.endswith("/docs") or request.url.path.endswith("/openapi") or request.url.path.endswith("/redoc"):
        #     return await call_next(request)

        if (
            "/docs" in request.url.path
            or "/openapi" in request.url.path
            or "/sso/" in request.url.path
            or "/redoc" in request.url.path
            or request.url.path.endswith("/register")
            or request.url.path.endswith("/login")
            or request.url.path.endswith("/forgot-password")
            or request.url.path.endswith("/reset-password")
        ):
            return await call_next(request)

        auth_code = request.headers.get("X-Auth-Code")
        if not auth_code:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing authentication headers"}
            )

        db = None
        try:
            db = get_db()
            user_service = UserService(next(db))
            user_service.validate_auth_code(auth_code)
        except Exception as e:
            return JSONResponse(
                status_code=401,
                content={"detail": str(e)}
            )
        finally:
            if db:
                db.close()

        return await call_next(request)
