# 👤 User Management Module

This package provides a comprehensive, self-contained solution for user authentication, authorization, and management within a FastAPI application. It is designed to be highly modular and can be **conditionally activated** via a single environment variable in the main application.

## ✨ Features

- 🔑 **User Authentication**: Standard email/password registration and login.
- 🌐 **Single Sign-On (SSO)**: OAuth2 integration with Google and GitHub.
- 🛡️ **Role-Based Access Control (RBAC)**: Create roles and assign permissions to users.
- 🔌 **Conditional Activation**: The entire module can be enabled or disabled from the main application's `.env` file, providing a powerful feature flag for security.
- 🔒 **Secure Password Handling**: Password hashing and verification using `passlib`.
- 🗄️ **Database Management**: Automated creation of database tables and efficient session management with SQLAlchemy.
- ⚙️ **Self-Contained Configuration**: The module loads its own `.env` file with precedence, ensuring its settings are isolated and predictable.
- 🎭 **Custom Authentication**: Includes a custom middleware for authentication using a generated auth code.

---

## 🔌 Conditional Activation

The entire user module can be enabled or disabled based on the `AUTH_ENABLED` setting in your root `.env` file. This provides a powerful "feature flag" for the authentication system, making it simple to run the application in different modes (e.g., with or without security) without changing any code.

When `AUTH_ENABLED=True`, the main application will:
1.  Add the `AuthCodeMiddleware` to protect endpoints.
2.  Include the user and SSO API routers.
3.  Customize the OpenAPI (Swagger) documentation to include authentication headers.

## 📁 Module Structure

The module is organized to separate concerns, making it maintainable and scalable.

```
user/
├── .env.example         # Example environment variables for this module
├── __init__.py          # Package entry point, exposes key components
├── auth_headers.py      # Helper to customize OpenAPI docs for auth
├── config.py            # Pydantic settings and configuration management
├── db.py                # Database engine, session management, and table creation
├── helper.py            # Utility functions (e.g., password hashing)
├── middleware.py        # Custom middleware for authentication
├── models.py            # SQLAlchemy ORM models
├── permissions.py       # Defines roles and permissions constants
├── requirements.txt     # Python dependencies specific to this module
├── repository.py        # Data access layer (direct database queries)
├── router.py            # Main API endpoints for user actions
├── schemas.py           # Pydantic schemas for data validation (API models)
├── service.py           # Business logic layer
└── sso_router.py        # API endpoints for SSO (Google, GitHub)
```

---

## ⚙️ Configuration & Setup

This module's functionality is controlled by environment variables in two locations:

1.  **Root `.env` file**: The main application's `.env` file controls whether this module is active.
2.  **User Module `.env` file**: A dedicated `.env` file inside the `user/` directory contains all settings specific to this module.

### 1. Main Application Configuration

Place this variable in your project's root `.env` file (e.g., `backend/.env`).

#### **Root Environment Variable**
| Variable | Description |
|---|---|
| `AUTH_ENABLED` | Set to `True` to enable the user module and its endpoints. Set to `False` to disable it. |

### 2. User Module Configuration

Create a `.env` file in the `user/` directory. The `__init__.py` file ensures these variables are loaded with precedence over any other `.env` file. The variable names below are what the application code expects.

**Important**: The variable names below are what the application code expects. Note the `USER_` prefix for database settings, which is required for the configuration to load correctly and avoid conflicts with the main application's database settings.

#### **User Module Environment Variables**
| Variable | Description |
|---|---|
| `USER_DB_USER` | The username for the user database. |
| `USER_DB_PASSWORD` | The password for the user database. |
| `USER_DB_HOST` | The host where the user database is running. |
| `USER_DB_PORT` | The port for the user database connection. |
| `USER_DB_NAME` | The name of the user database. |
| `SECRET_KEY` | A secret key for signing tokens and security operations.|
| `GOOGLE_CLIENT_ID` | The Client ID for Google OAuth2 SSO. |
| `GOOGLE_CLIENT_SECRET` | The Client Secret for Google OAuth2 SSO. |
| `GITHUB_CLIENT_ID` | The Client ID for GitHub OAuth SSO. |
| `GITHUB_CLIENT_SECRET` | The Client Secret for GitHub OAuth SSO. |


### 3. 📦 Dependency Management

To maintain its modularity, the `user` package manages its own Python dependencies in a dedicated `requirements.txt` file. This ensures that all libraries required for user authentication and management are self-contained.

**File (`user/requirements.txt`):**
```
Authlib==1.6.1
dnspython==2.7.0
email_validator==2.2.0
passlib==1.7.4
```

These dependencies are specific to the user module's functionality:
- `Authlib`: For handling OAuth2 SSO with providers like Google and GitHub.
- `passlib`: For securely hashing and verifying user passwords.
- `email_validator`: For validating email formats during registration.

#### Integration with Main Application

The module's dependencies are seamlessly integrated into the main application's environment by referencing this file from the root `requirements.txt`.

**File (`/requirements.txt`):**
```
-r user/requirements.txt
# ... other main application dependencies
```

This approach enhances modularity by keeping feature-specific dependencies isolated, making the system cleaner and easier to maintain. It aligns perfectly with the conditional activation philosophy, as the dependencies are grouped with the feature they support.

---


## 🚀 Integration Guide

This module is designed for seamless integration into a main FastAPI application. The integration is driven by the `AUTH_ENABLED` flag, allowing you to conditionally enable all authentication and user management features. Below are the key integration points.

### 1. Activating the Module in the Main Application

The core activation logic involves conditionally including the module's routers, middleware, and OpenAPI customizations in your main application files (`main.py` and `routers.py`).

#### **Context & Functionality**
- **Router Inclusion**: The `*User module's router*` (`router.py`) contains all API endpoints for user actions like registration, login, SSO, and role management. Including it makes these endpoints available under the `/users` prefix.
- **Middleware (`AuthCodeMiddleware`)**: This middleware intercepts incoming requests to validate the `auth_code` header, providing a centralized security layer for your entire application.
- **OpenAPI Customization (`custom_openapi_authcode_header`)**: This helper function enhances the interactive API docs (Swagger/ReDoc) by adding a field for the `auth_code` header, making it easy for developers to test protected endpoints.

#### **Usage & "Why it's used"**
This conditional approach is powerful because it allows the entire security layer to be toggled on or off via a single environment variable. It keeps the main application clean and decouples it from the user management logic.

**Example (`routers.py`): Including the API Endpoints**
This code adds the user management routes to your application's main router.

```python
from app.core.config import settings

if settings.AUTH_ENABLED:
    from user import router as user_router
    router.include_router(user_router, prefix="/users", tags=["User Management"])
```

**Example (`main.py`): Adding Middleware and Customizing API Docs**
This snippet adds the authentication middleware and updates the OpenAPI schema, but only if authentication is enabled.

```python
from app.core.config import settings

if settings.AUTH_ENABLED:
    from user import AuthCodeMiddleware, custom_openapi_authcode_header

    # Add the middleware to the application pipeline
    app.add_middleware(AuthCodeMiddleware)
    
    # Define a function to customize OpenAPI
    def custom_openapi():
        return custom_openapi_authcode_header(app, settings.PROJECT_NAME)

    # Apply the custom OpenAPI schema
    app.openapi = custom_openapi
```

### 2. Initializing the Database on Startup

The module provides a `create_db_and_tables` function to set up the necessary database schema (`users` and `roles` tables).

#### **Context & Functionality**
This function inspects the SQLAlchemy models defined within the `user` module and creates the corresponding tables in the database if they do not already exist.

#### **Usage & "Why it's used"**
This is a crucial setup step that must be performed when the application starts. By calling it within a FastAPI `startup` event, you guarantee that the database schema is ready before the application begins to handle requests that interact with user data. This prevents runtime errors related to missing tables.

**Example (`main.py`): Creating Tables on Application Startup**
```python
from fastapi import FastAPI
from app.core.config import settings # Main app settings

app = FastAPI()

@app.on_event("startup")
def on_startup():
    # Create database tables for the user module only if auth is enabled
    if settings.AUTH_ENABLED:
        from user import create_db_and_tables
        print("Creating database and tables for user module...")
        create_db_and_tables()
```
