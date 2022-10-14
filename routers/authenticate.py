from util.supporter import check_username
from util.ratelimits import check_captcha, check_ratelimit, ratelimit, auto_ratelimit
from util.accounts import acc_from_username, acc_from_email, acc_from_mfa_token
from util.emails import send_email
from util.schemas.authentication import CreateAccount, LoginPassword, TOTP, PasswordRecovery, MFARecovery
from fastapi import APIRouter, HTTPException, Request


router = APIRouter(
    prefix="/authenticate",
    tags=["Authentication"]
)


@router.post("/register")
async def create_account(request:Request, body:CreateAccount):
    """
    Create a new account using a username and password.
    """

    # Make sure IP isn't being ratelimited
    if check_ratelimit("regristations", request.client.info["ip"]):
        raise HTTPException(status_code = 429, detail = "You are being ratelimited")

    # Make sure username can be used
    if check_username(body.username):
        raise HTTPException(status_code = 400, detail = "Illegal characters detected")

    # Get user object
    user = acc_from_username(body.username)

    # Make sure username isn't already taken
    if user._exists:
        raise HTTPException(status_code = 409, detail = "Username already taken")

    # Check captcha
    if not check_captcha(body.captcha):
        raise HTTPException(status_code = 403, detail = "Invalid captcha token")

    # Attempt to create account
    user.create(body.username, body.email, body.password, body.child)

    # Ratelimit IP
    ratelimit("regristations", request.client.info["ip"], 2, 300)

    # Finish login
    session = user.generate_session(request.client.info)
    return {
        "mfa_required": False,
        "auth_token": session[0],
        "main_token": session[1]
    }


@router.post("/password")
async def auth_password(request:Request, body:LoginPassword):
    # Check ratelimit
    auto_ratelimit("authentications", request.client.info["ip"], 10, 60)

    # Get user object
    if "@" in body.username:
        user = acc_from_email(body.username)
    else:
        user = acc_from_username(body.username)

    # Check account and credentials
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.lock_status > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif check_ratelimit("failed_pswd", user.id):
        raise HTTPException(status_code=429, detail="Too many attempts, please try again in a minute")
    elif not check_captcha(body.captcha):
        raise HTTPException(status_code = 403, detail = "Invalid captcha token")
    elif not user.verify_password(body.password):
        ratelimit("failed_pswd", user.id, 5, 60)
        raise HTTPException(status_code=401, detail="Invalid password")

    # Check for MFA and finish login
    if (len(user.totp) > 0) or (len(user.webauthn) > 0):
        payload = {
            "mfa_required": True,
            "mfa_token": user.generate_mfa_token(),
            "totp": (len(user.totp) > 0),
            "webauthn": (len(user.webauthn) > 0)
        }
    else:
        session = user.generate_session(request.client.info)
        payload = {
            "mfa_required": False,
            "auth_token": session[0],
            "main_token": session[1]
        }

    return payload


@router.post("/webauthn")
async def auth_webauthn():
    pass # TODO: WebAuthn


@router.post("/totp")
async def auth_totp(request:Request, body:TOTP):
    user = acc_from_mfa_token(body.token)

    # Check account and credentails
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.lock_status > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif check_ratelimit("failed_mfa", user.id):
        raise HTTPException(status_code=429, detail="Too many attempts, please try again in a minute")
    elif not user.verify_totp(body.code):
        ratelimit("failed_mfa", user.id, 5, 60)
        raise HTTPException(status_code=401, detail="Invalid code")

    # Generate session
    session = user.generate_session(request.client.info)
    payload = {
        "mfa_required": False,
        "auth_token": session[0],
        "main_token": session[1]
    }

    return payload


@router.post("/recovery/password")
async def recover_password(body:PasswordRecovery):
    # Check ratelimit
    auto_ratelimit("reset_pswd", body.email, 2, 300)

    # Check captcha
    if not check_captcha(body.captcha):
        raise HTTPException(status_code = 403, detail = "Invalid captcha token")

    # Get user
    user = acc_from_email(body.email)

    # Attempt to send email -- even if there's an error we shouldn't tell the user
    try:
        send_email(user.email, "reset_password", {"username": user.username})
    except:
        pass
    
    return "OK"


@router.post("/recovery/mfa")
async def recover_mfa(request:Request, body:MFARecovery):
    user = acc_from_mfa_token(body.token)

    # Check account and credentails
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.lock_status > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif check_ratelimit("failed_mfa", user.id):
        raise HTTPException(status_code=429, detail="Too many attempts, please try again in a minute")
    elif body.code not in user.recovery:
        ratelimit("failed_mfa", user.id, 5, 60)
        raise HTTPException(status_code=401, detail="Invalid code")

    # Remove recovery code
    user.remove_recovery(body.code)

    # Generate session
    session = user.generate_session(request.client.info)
    payload = {
        "mfa_required": False,
        "auth_token": session[0],
        "main_token": session[1]
    }

    return payload