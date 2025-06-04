import secrets
import jwt
import httpx
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, FileResponse, JSONResponse
import os
from typing import Optional, cast
import time
from authlib.integrations.starlette_client import OAuth, StarletteOAuth2App


from config import FRONTEND_URL, STATIC_DIR
from dependencies import get_coder_api, get_session_domain
from coder import CoderAPI
from dependencies import optional_auth, UserSession
from domain.session import Session
from database.database import async_session
from domain.user import User

auth_router = APIRouter()
oauth = OAuth()
oauth.register(
    name="oidc",
    client_id="o9JtE0lajlN7wP7QEeUjDmQUhYiRRU5rOzIvdgYc",
    client_secret="V5qMZccoKXvkdxLSMz3iXcSwcyX6X3LJ",
    server_metadata_url="https://auth.matai.info/application/o/pad-ws/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile email",
        "response_type": "code",
    },
)
oidcClient: StarletteOAuth2App = oauth.oidc


@auth_router.get("/login")
async def login(
    request: Request,
    session_domain: Session = Depends(get_session_domain),
    kc_idp_hint: str = None,
    popup: str = None,
):

    session_id = secrets.token_urlsafe(32)
    test = request.url_for("callback")
    state = "popup" if popup == "1" else "default"
    response = await oidcClient.authorize_redirect(
        request,
        test,
        # kwargs={state, kc_idp_hint},
    )
    response.set_cookie("session_id", session_id)

    return response


@auth_router.get("/callback")
async def callback(
    request: Request,
    code: str,
    state: str = "default",
    coder_api: CoderAPI = Depends(get_coder_api),
    session_domain: Session = Depends(get_session_domain),
):
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="No session")

    token_data = await oidcClient.authorize_access_token(request)
    # Store the token data in Redis
    success = await session_domain.set(
        session_id, token_data, expiry=token_data.get("expires_in", 3600)
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to store session")

    # Track the login event
    await session_domain.track_event(session_id, "login")

    access_token: str = cast(str, token_data["access_token"])
    user_info = jwt.decode(access_token, options={"verify_signature": False})

    # Ensure user exists in database (only during login)
    async with async_session() as db_session:
        try:
            await User.ensure_exists(db_session, user_info)
        except Exception as e:
            # Handle duplicate key violations gracefully - this means user already exists
            if "duplicate key value violates unique constraint" in str(
                e
            ) or "already exists" in str(e):
                print(
                    f"User {user_info.get('sub')} already exists in database (race condition handled)"
                )
            else:
                raise e

    try:
        user_data, _ = coder_api.ensure_user_exists(user_info)
        coder_api.ensure_workspace_exists(user_data["username"])
    except Exception as e:
        print(f"Error in user/workspace setup: {str(e)}")
        # Continue with login even if Coder API fails

    if state == "popup":
        return FileResponse(os.path.join(STATIC_DIR, "auth/popup-close.html"))
    else:
        return RedirectResponse("/")


@auth_router.get("/logout")
async def logout(
    request: Request, session_domain: Session = Depends(get_session_domain)
):
    session_id = request.cookies.get("session_id")

    if not session_id:
        return RedirectResponse("/")

    session_data = await session_domain.get(session_id)
    if not session_data:
        return RedirectResponse("/")

    id_token = session_data.get("id_token", "")

    # Track logout event before deleting session
    await session_domain.track_event(session_id, "logout")

    # Delete the session from Redis
    success = await session_domain.delete(session_id)
    if not success:
        print(f"Warning: Failed to delete session {session_id}")


    request.session.pop('user', None)
    # Create the Keycloak logout URL with redirect back to our app
    logout_url = session_domain.oidc_config["end_session_endpoint"]
    full_logout_url = f"{logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={FRONTEND_URL}"

    # Create a response with the logout URL and clear the session cookie
    response = JSONResponse(
        {"status": "success", "logout_url": full_logout_url}
    )
    response.delete_cookie(
        key="session_id", path="/", secure=True, httponly=True, samesite="lax"
    )

    return response


@auth_router.get("/status")
async def auth_status(
    user_session: Optional[UserSession] = Depends(optional_auth),
):
    """Check if the user is authenticated and return session information"""
    if not user_session:
        return JSONResponse(
            {"authenticated": False, "message": "Not authenticated"}
        )

    try:
        expires_in = user_session.token_data.get("exp") - time.time()

        return JSONResponse(
            {
                "authenticated": True,
                "user": {
                    "id": str(user_session.id),
                    "username": user_session.username,
                    "email": user_session.email,
                    "name": user_session.name,
                },
                "expires_in": expires_in,
            }
        )
    except Exception as e:
        return JSONResponse(
            {
                "authenticated": False,
                "message": f"Error processing session: {str(e)}",
            }
        )


@auth_router.post("/refresh")
async def refresh_session(
    request: Request, session_domain: Session = Depends(get_session_domain)
):
    """Refresh the current session's access token"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="No session found")

    session_data = await session_domain.get(session_id)
    if not session_data:
        raise HTTPException(status_code=401, detail="Invalid session")

    # Try to refresh the token
    success, new_token_data = await session_domain.refresh_token(
        session_id, session_data
    )
    if not success:
        raise HTTPException(status_code=401, detail="Failed to refresh session")

    # Return the new expiry time
    return JSONResponse(
        {"expires_in": new_token_data.get("expires_in"), "authenticated": True}
    )
