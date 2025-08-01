from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from .user import is_public_path, is_public_endpoint, is_enrol_endpoint


def custom_openapi_authcode_header(app: FastAPI, project_name: str, project_version: str, project_description: str):
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=project_name,
        version=project_version,
        description=project_description,
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
    security_schemes["XApplicationHeader"] = {
        "type": "apiKey",
        "name": "X-Application",
        "in": "header",
        "description": "The name of the application making the request. This may be used for authorization or logging purposes."
    }

    security_requirement = [{"XAuthCodeHeader": [], "XApplicationHeader": []}]
    application_security_requirement = [{"XApplicationHeader": []}]
    auth_security_requirement = [{"XAuthCodeHeader": []}]
    
    all_paths = openapi_schema.get("paths", {})

    for path, path_item in all_paths.items():
        for method_details in path_item.values():
            if isinstance(method_details, dict):
                if not is_public_path(path) and not is_public_endpoint(path) and not is_enrol_endpoint(path):
                    method_details.setdefault("security", []).extend(security_requirement)
                elif is_enrol_endpoint(path):
                    method_details.setdefault("security", []).extend(auth_security_requirement)
                else:
                    method_details.setdefault("security", []).extend(application_security_requirement)


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
