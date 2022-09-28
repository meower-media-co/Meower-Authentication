from fastapi import APIRouter, HTTPException, Request
from util.accounts import acc_from_id, acc_from_username, acc_from_email
from util.fields import CreateAccount, LoginPassword, TOTP
import os
import jwt
import time

router = APIRouter(
    prefix="/authenticate",
    tags=["Authentication"]
)

@router.post("/register")
async def create_account(request: Request, body: CreateAccount):
    user = acc_from_username(body.username)

    try:
        user.create(body.username, body.email, body.password, body.child)
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Username already taken")
    except ValueError:
        raise HTTPException(status_code=400, detail="Illegal characters detected")
    except Exception:
        raise HTTPException(status_code=500)
    else:
        session = user.generate_session(request.headers.get("X-Client-Name"), request.headers.get("X-Client-Type"), request.headers.get("User-Agent"), request.client.host)
        return {"requires_totp": False, "access_token": session[0], "refresh_token": session[1]}

@router.post("/password")
async def auth_password(request: Request, body: LoginPassword):
    if "@" in body.username:
        user = acc_from_email(body.username)
    else:
        user = acc_from_username(body.username)

    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif not user.verify_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid password")

    if len(user.totp["authenticators"]) > 0:
        return {"requires_totp": True, "totp_token": jwt.encode({"t": "totp", "u": user.id, "iat": int(time.time())}, os.environ["JWT_PRIVATE"], algorithm="RS256").decode()}
    else:
        session = user.generate_session(request.headers.get("X-Client-Name"), request.headers.get("X-Client-Type"), request.headers.get("User-Agent"), request.client.host)
        return {"requires_totp": False, "access_token": session[0], "refresh_token": session[1]}

@router.post("/totp")
async def auth_totp(request: Request, body: TOTP):
    try:
        totp_session = jwt.decode(body.token, os.environ["JWT_PUBLIC"], verify=True)
    except:
        raise HTTPException(status_code=401, detail="Invalid TOTP token")

    if int(time.time()) > totp_session["iat"]+600:
        raise HTTPException(status_code=401, detail="Invalid TOTP token")

    user = acc_from_id(totp_session["u"])

    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif not user.verify_totp(body.code):
        raise HTTPException(status_code=401, detail="Invalid code")

    session = user.generate_session(request.headers.get("X-Client-Name"), request.headers.get("X-Client-Type"), request.headers.get("User-Agent"), request.client.host)
    return {"requires_totp": False, "access_token": session[0], "refresh_token": session[1]}