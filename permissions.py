# Define all permissions as constants
PERMISSIONS = {
    "read": "read",
    "write": "write",
    "delete": "delete",
    "manage_users": "manage_users",
    "manage_roles": "manage_roles",
    "view_reports": "view_reports",
    "edit_profile": "edit_profile",
    # Add more as needed
}

# Map endpoints to required permissions
ENDPOINT_PERMISSIONS = {
    "/api/v1/users/permissions": [PERMISSIONS["read"]],
    "/api/v1/users/assign-role": [PERMISSIONS["manage_roles"]],
    "/api/v1/users/register": [],
    "/api/v1/users/login": [],
    "/api/v1/users/forgot-password": [],
    "/api/v1/users/reset-password": [],
    "/api/v1/users/delete": [PERMISSIONS["delete"]],
    "/api/v1/users/update": [PERMISSIONS["write"]],
    # Add more endpoint-permission mappings as needed
}