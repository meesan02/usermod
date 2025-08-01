from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from services import UserService
from db import get_db


# Define public paths for more maintainable and readable code
SYSTEM_PREFIXES = {"/docs", "/redoc"}
SYSTEM_SUBSTRINGS = {"/openapi"}
PUBLIC_SUBSTRINGS = {"/sso/"}
# PUBLIC_SUBSTRINGS = {"/sso/", "/favicon.ico"}
PUBLIC_SUFFIXES = {"/register", "/login", "/forgot-password", "/reset-password"}
# ENROL_SUBSTRINGS = {"/enrol-application", "/applications"}
ENROL_SUBSTRINGS = {"/enrol-application"}


def is_public_path(path: str) -> bool:
    """Checks if a given request path is public and should skip auth."""
    if any(path.startswith(prefix) for prefix in SYSTEM_PREFIXES):
        return True
    if any(substring in path for substring in SYSTEM_SUBSTRINGS):
        return True
    if any(substring in path for substring in PUBLIC_SUBSTRINGS):
        return True
    return False

def is_public_endpoint(path: str) -> bool:
    # if any(substring in path for substring in PUBLIC_SUBSTRINGS):
    #     return True
    if any(path.endswith(suffix) for suffix in PUBLIC_SUFFIXES):
        return True
    return False

def is_enrol_endpoint(path: str) -> bool:
    if any(substring in path for substring in ENROL_SUBSTRINGS):
        return True
    return False



class AuthCodeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if is_public_path(request.url.path):
            return await call_next(request)
        
        application = request.headers.get("X-Application")
        if not application and not is_enrol_endpoint(request.url.path):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing application headers"}
                )
        db = None
        try:
            db = get_db()
            user_service = UserService(next(db))
            if not is_enrol_endpoint(request.url.path) and not user_service.fetch_application(application):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid application"}
                )
            if is_public_endpoint(request.url.path) or is_enrol_endpoint(request.url.path):
                return await call_next(request)


            auth_code = request.headers.get("X-Auth-Code")
            if not auth_code:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Missing authentication headers"}
                )

        # db = None
        # try:
            user_data = user_service.validate_auth_code(auth_code, application_name=application)
            # user = user_service.validate_auth_code(auth_code)
            # request.state.user = user  # Attach user to request state for potential use in endpoints

            # --- Authorization Logic ---
            if (user_data.applications is None) or ((user_data.applications) and (application not in user_data.applications)):
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Forbidden: You do not have access to the application '{application}'."}
                )

            # Check if the requested endpoint requires a specific permission
            # required_permission = ENDPOINT_PERMISSIONS.get(request.url.path)
            # if required_permission:
            #     user_permissions = user_service.get_user_permissions(user.id)
            #     if required_permission not in user_permissions:
            #         return JSONResponse(
            #             status_code=403,
            #             content={"detail": f"Forbidden: You do not have the required '{required_permission}' permission."}
            #         )
            # --- End Authorization Logic ---

            return await call_next(request)

        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail}
            )
        except Exception as e:
            # Catch all other exceptions and return a generic error
            return JSONResponse(
                status_code=500,
                content={"detail": f"An internal server error occurred with error {e.__class__.__name__}"}
            )
        finally:
            db.close()
