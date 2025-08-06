# 👤 User Management Microservice

A modular, production-ready FastAPI microservice for user authentication, authorization, and management. Designed for seamless integration into a microservices architecture, it supports conditional activation and secure communication with your main application.

---

## ✨ Features

- 🔑 **User Authentication**: Email/password registration and login.
- 🌐 **Single Sign-On (SSO)**: OAuth2 with Google and GitHub.
- 🛡️ **Role-Based Access Control (RBAC)**: Create roles, assign permissions.
- 🔌 **Conditional Activation**: Enable/disable via a single environment variable.
- 🔒 **Secure Password Handling**: Password hashing with `passlib`.
- 🗄️ **Automated Database Management**: Table creation and session management with SQLAlchemy.
- ⚙️ **Self-Contained Configuration**: Loads its own `.env` file for isolated settings.
- 🎭 **Custom Auth Middleware**: Auth code-based authentication for all protected endpoints.

---

## 🚀 How to Use This Microservice

### 1. 📥 Clone the Repository

```bash
git clone git@github.com:meesan02/usermod.git
cd usermod
```

### 2. 🐍 Set Up a Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate   # On Windows
# Or, for Linux/macOS:
# source venv/bin/activate
```

### 3. 📦 Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. ⚙️ Configure Environment Variables

- Copy the example environment file and fill in your values:
  ```bash
  copy .env.example .env   # On Windows
  # Or, for Linux/macOS:
  # cp .env.example .env
  ```
- Edit `.env` with your database and OAuth credentials.

### 5. 🏁 Run the Microservice

```bash
python main.py
# Or using uvicorn for development:
# uvicorn main:app --reload --host 127.0.0.1 --port 8001
```

### 6. 🔗 Integrate with Your Main Application

- Ensure your main application's `.env` has:
  ```
  AUTH_ENABLED=True
  USER_SERVICE_URL="http://127.0.0.1:8001/api/v1"
  USER_SERVICE_AUTHENTICATE_ENDPOINT="/authenticate"
  ```
- Use HTTP requests from your main app to interact with the user microservice endpoints.

---

**Tip:**  
- Use `git pull` to update your local copy when changes are made to the repository.
- For development, create a new branch:  
  ```bash
  git checkout -b feature/my-new-feature
  ```

---

## 🔌 Conditional Activation

The microservice is enabled or disabled via the `AUTH_ENABLED` setting in your root `.env` file. This acts as a feature flag, allowing you to run the application with or without authentication and user management.

---

## 📁 Module Structure

```
usermod/
├── .env.example          # Example environment variables for this module
├── main.py               # Application entry point
├── permissions.py        # Defines roles and permissions constants
├── README.md
├── requirements.txt      # Python dependencies specific to this module
├── __init__.py           # Package entry point, exposes key components
│
├── api/
│   ├── __init__.py
│   └── v1/
│       ├── router.py         # Main API endpoints for user actions
│       └── sso_router.py     # API endpoints for SSO (Google, GitHub)
│
├── core/
│   ├── config.py            # Pydantic settings and configuration management
│   ├── exceptions.py        # Custom exception classes
│   └── __init__.py
│
├── db/
│   ├── db.py                # Database engine, session management, and table creation
│   └── __init__.py
│
├── helper/
│   ├── helper.py            # Utility functions (e.g., password hashing)
│   └── __init__.py
│
├── middleware/
│   ├── auth_headers.py      # Helper to customize OpenAPI docs for auth
│   ├── user.py              # Custom middleware for authentication
│   └── __init__.py
│
├── models/
│   ├── user.py              # SQLAlchemy ORM models
│   └── __init__.py
│
├── repository/
│   ├── user.py              # Data access layer (direct database queries)
│   └── __init__.py
│
├── schemas/
│   ├── user.py              # Pydantic schemas for data validation (API models)
│   └── __init__.py
│
└── services/
    ├── user.py              # Business logic
```

---

## ⚙️ Configuration & Setup

This microservice uses environment variables from two locations:

1. **Root `.env` file**: Controls whether this module is active and how the main service communicates with it.
2. **User Module `.env` file**: Contains all settings specific to this module.

### 1. Main Application Configuration

Add these variables to your project's root `.env` file (e.g., `backend/.env`):

| Variable                              | Description                                                        |
|----------------------------------------|--------------------------------------------------------------------|
| `AUTH_ENABLED`                        | Set to `True` to enable the user module and its endpoints.         |
| `USER_SERVICE_URL`                    | Base URL for the user microservice (e.g., `http://127.0.0.1:8001/api/v1`). |
| `USER_SERVICE_AUTHENTICATE_ENDPOINT`  | Path for the authentication endpoint (e.g., `/authenticate`).      |

### 2. User Module Configuration

Create a `.env` file in the `usermod/` directory. The `__init__.py` ensures these variables are loaded with precedence.

| Variable               | Description                                      |
|------------------------|--------------------------------------------------|
| `USER_DB_USER`         | Username for the user database                   |
| `USER_DB_PASSWORD`     | Password for the user database                   |
| `USER_DB_HOST`         | Host where the user database is running          |
| `USER_DB_PORT`         | Port for the user database connection            |
| `USER_DB_NAME`         | Name of the user database                        |
| `SECRET_KEY`           | Secret key for signing tokens and security ops   |
| `GOOGLE_CLIENT_ID`     | Client ID for Google OAuth2 SSO                  |
| `GOOGLE_CLIENT_SECRET` | Client Secret for Google OAuth2 SSO              |
| `GITHUB_CLIENT_ID`     | Client ID for GitHub OAuth SSO                   |
| `GITHUB_CLIENT_SECRET` | Client Secret for GitHub OAuth SSO               |

---

### 3. 📦 Dependency Management

All dependencies are managed in a dedicated `requirements.txt`:

**File (`usermod/requirements.txt`):**
```
Authlib==1.6.1
dnspython==2.7.0
email_validator==2.2.0
passlib==1.7.4
```

---

## 🚀 Integration with Main Service

The main service communicates with this microservice via HTTP and uses middleware to enforce authentication. Below is a typical integration pattern:

### 1. Feature Flags and Service URLs

**config.py**
```python
AUTH_ENABLED: bool = Field(True, env="AUTH_ENABLED")
USER_SERVICE_URL: Optional[str] = Field(None, env="USER_SERVICE_URL")
USER_SERVICE_AUTHENTICATE_ENDPOINT: Optional[str] = Field(None, env="USER_SERVICE_AUTHENTICATE_ENDPOINT")
```

**.env**
```
AUTH_ENABLED=True
USER_SERVICE_URL="http://127.0.0.1:8001/api/v1"
USER_SERVICE_AUTHENTICATE_ENDPOINT="/authenticate"
```

### 2. Authentication Middleware

**main.py**
```python
from starlette.middleware.base import BaseHTTPMiddleware
import httpx
from fastapi import Request, HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED

class MicroserviceAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        public_prefixes = ["/docs", "/redoc", f"{settings.API_V1_STR}/openapi.json"]
        if request.url.path == "/" or any(
            request.url.path.startswith(prefix) for prefix in public_prefixes
        ):
            return await call_next(request)

        auth_header = request.headers.get("X-Auth-Code")
        if not auth_header:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED, detail="Missing Authentication headers"
            )

        validate_url = f"{settings.USER_SERVICE_URL}{settings.USER_SERVICE_AUTHENTICATE_ENDPOINT}"
        headers = {"X-Auth-Code": auth_header}
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(validate_url, headers=headers)
                if response.status_code == 200:
                    return await call_next(request)
                else:
                    detail = response.json().get("detail", "Invalid token or user service error")
                    raise HTTPException(status_code=response.status_code, detail=detail)
            except httpx.RequestError as exc:
                raise HTTPException(status_code=503, detail=f"User service is unavailable: {exc}")

if settings.AUTH_ENABLED:
    app.add_middleware(MicroserviceAuthMiddleware)
```

### 3. OpenAPI Customization

**main.py**
```python
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=settings.PROJECT_NAME,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["XAuthCodeHeader"] = {
        "type": "apiKey",
        "name": "X-Auth-Code",
        "in": "header",
        "description": "A unique authentication code provided after a successful login. This must be included in the header for all protected endpoints."
    }
    public_paths = [
        "/",
        app.docs_url,
        app.redoc_url,
        app.openapi_url,
    ]
    security_requirement = [{"XAuthCodeHeader": []}]
    all_paths = openapi_schema.get("paths", {})
    for path, path_item in all_paths.items():
        if path not in public_paths:
            for method_details in path_item.values():
                if isinstance(method_details, dict):
                    method_details.setdefault("security", []).extend(security_requirement)
    app.openapi_schema = openapi_schema
    return app.openapi_schema

if settings.AUTH_ENABLED:
    app.openapi = custom_openapi
```

---

## 🛠️ Core Capabilities

- **User Registration & Login**: Standard and OAuth2 flows.
- **Role & Permission Management**: Create, assign, and remove roles/permissions.
- **Custom Middleware**: Centralized authentication using an encoded auth code.
- **Extensible**: Add new OAuth providers or permission types as needed.

---

## 💡 Suggestions for Improvement

- 📚 **Add API Documentation**: Use FastAPI's built-in docs for endpoint documentation.
- 🧪 **Unit & Integration Tests**: Expand test coverage for all service and repository methods.
- 🔄 **Refresh Token Support**: Add refresh token logic for longer-lived sessions.
- 🛑 **Rate Limiting**: Implement rate limiting for sensitive endpoints (e.g., login).
- 🔔 **Notification Hooks**: Add hooks for sending emails on registration, password reset, etc.
- 📈 **Monitoring**: Integrate logging and monitoring for authentication events.

---

## 📝 License

This microservice is intended for use as part of a larger FastAPI project. Please see your main application's license for details.
---