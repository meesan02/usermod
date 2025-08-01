from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware


from api import router
from middleware import AuthCodeMiddleware, custom_openapi_authcode_header
from helper import get_session_secret
from core import settings
from db import create_db_and_tables

app = FastAPI(
    title="User Microservice",
    description="A microservice for managing users.",
    version="1.0.0",
)

app.include_router(router, prefix=settings.API_V1_STR, tags=["User Management"])

app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


app.add_middleware(AuthCodeMiddleware)
app.add_middleware(SessionMiddleware, get_session_secret())
def custom_openapi():
    return custom_openapi_authcode_header(app, app.title, app.version, app.description)

app.openapi = custom_openapi

@app.on_event("startup")
async def on_startup():
    """Initialize database and perform any startup tasks"""
    create_db_and_tables()


if __name__ == "__main__":
    import uvicorn

    # To run this file: uvicorn user.main:app --reload
    uvicorn.run("main:app", host="127.0.0.1", port=8001, reload=True)
