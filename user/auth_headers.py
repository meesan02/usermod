from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

def custom_openapi_authcode_header(app: FastAPI, project_name: str):
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=project_name,
        version="1.1.0",
        routes=app.routes,
    )

    # Safely add the security scheme to handle cases where 'components' is not present
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["XAuthCodeHeader"] = {
        "type": "apiKey",
        "name": "X-Auth-Code",
        "in": "header",
        "description": "A unique authentication code provided after a successful login. This must be included in the header for all protected endpoints."
    }

    # Define which paths are public and should not have security applied.
    # This logic should mirror the checks in `user.middleware.AuthCodeMiddleware`.
    public_paths = [
        app.docs_url,
        app.redoc_url,
        app.openapi_url,
    ]
    public_substrings = [
        "/sso/",
    ]
    public_suffixes = [
        "/register",
        "/login",
        "/forgot-password",
        "/reset-password",
    ]

    security_requirement = [{"XAuthCodeHeader": []}]
    
    all_paths = openapi_schema.get("paths", {})

    for path, path_item in all_paths.items():
        is_public = False
        if path in public_paths or \
           any(path.endswith(suffix) for suffix in public_suffixes) or \
           any(substring in path for substring in public_substrings):
            is_public = True
        
        if not is_public:
            for method_details in path_item.values():
                if isinstance(method_details, dict):
                    method_details.setdefault("security", []).extend(security_requirement)

    app.openapi_schema = openapi_schema
    return app.openapi_schema



# def custom_openapi_authcode_header(app: FastAPI, project_name: str):
#     if app.openapi_schema:
#         return app.openapi_schema
#     openapi_schema = get_openapi(
#         title=project_name,
#         version="1.1.0",
#         routes=app.routes,
#     )
#     # Add global security scheme for auth headers
#     openapi_schema["components"]["securitySchemes"] = {
#         "XAuthCodeHeader": {
#             "type": "apiKey",
#             "name": "X-Auth-Code",
#             "in": "header"
#         }
#     }
#     # Apply security scheme to all paths
#     for path in openapi_schema["paths"].values():
#         for method in path.values():
#             method.setdefault("security", []).append(
#                 {"XUserIdHeader": [], "XAuthCodeHeader": []}
#             )
#     app.openapi_schema = openapi_schema
#     return app.openapi_schema
