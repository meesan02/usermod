from fastapi import APIRouter, Request, Depends, HTTPException, Query
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from .service import UserService
from .db import get_db
from sqlalchemy.orm import Session
from .config import settings
from .schemas import UserBase


router = APIRouter()

config_data = {
    "GOOGLE_CLIENT_ID": settings.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": settings.GOOGLE_CLIENT_SECRET,
    "GITHUB_CLIENT_ID": settings.GITHUB_CLIENT_ID,
    "GITHUB_CLIENT_SECRET": settings.GITHUB_CLIENT_SECRET,
    "SESSION_SECRET_KEY": settings.SESSION_SECRET_KEY,
}
config = Config(environ=config_data)
oauth = OAuth(config)

oauth.register(
    name='google',
    client_id=config_data["GOOGLE_CLIENT_ID"],
    client_secret=config_data["GOOGLE_CLIENT_SECRET"],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

oauth.register(
    name='github',
    client_id=config_data["GITHUB_CLIENT_ID"],
    client_secret=config_data["GITHUB_CLIENT_SECRET"],
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

@router.get("/providers", response_model=list[str], summary="List available SSO providers")
async def list_sso_providers():
    """
    Returns a list of dynamically registered SSO provider names.
    This can be used by a frontend to populate a login provider selection (e.g., a dropdown).
    """
    return list(oauth._clients.keys())


@router.get("/login/{provider}", summary="Redirect to SSO provider for login")
async def sso_login(request: Request, provider: str):
    """
    Initiates the SSO login flow by redirecting the user to the selected provider's authorization page.
    The provider must be one of the available providers from the /providers endpoint.
    """
    if provider not in oauth._clients:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider: '{provider}'. Supported providers are: {list(oauth._clients.keys())}"
        )
    redirect_uri = request.url_for("sso_auth", provider=provider)
    return await oauth.create_client(provider).authorize_redirect(request, redirect_uri)


@router.get("/auth/{provider}", summary="SSO authentication callback")
async def sso_auth(provider: str, request: Request, db: Session = Depends(get_db)):
    """
    Callback endpoint for the SSO provider. This should not be called directly by the user.
    The provider will redirect the user here after successful authentication.
    """
    token = await oauth.create_client(provider).authorize_access_token(request)
    if provider == "google":
        # user_info = await oauth.google.parse_id_token(request, token)
        # print(user_info,'$$$$$$$$$$$$$$$$$$$$$$$$')
        user_info = await oauth.google.userinfo(token=token)
        email = user_info.get("email")
        first_name = user_info.get("given_name")
        last_name = user_info.get("family_name")
        username = user_info.get("email").split("@")[0]

    elif provider == "github":
        resp = await oauth.github.get('user', token=token)
        profile = resp.json()
        email = profile.get("email")
        first_name = profile.get("name")
        last_name = None

        if not email:
            # GitHub may not return email, fetch from /emails endpoint
            emails_resp = await oauth.github.get('user/emails', token=token)
            emails = emails_resp.json()
            email = next((e["email"] for e in emails if e["primary"]), None)
        username = profile.get("login")
    else:
        raise HTTPException(status_code=400, detail="Unsupported provider")

    # Register or login the user
    user_service = UserService(db)
    user = user_service.get_or_create_oauth_user(email=email, username=username, first_name=first_name, last_name=last_name, provider=provider)
    # Generate your auth_code/session here as per your system
    auth_data = user_service.authenticate_user(user_data=user)
    return auth_data
