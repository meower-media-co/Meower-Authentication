from util.supporter import Codes
from util.accounts import acc_from_username, acc_from_email, acc_from_mfa_token
from util.schemas.authentication import CreateAccount, LoginPassword, MFA
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

    # Get user object
    user = acc_from_username(body.username)

    # Attempt to create account
    status_code = user.create(body.username, body.email, body.password, body.child)
    match status_code:
        case Codes.AccountCreated: # Account was successully created
            session = user.generate_session(request.client.info)
            payload = {
                "mfa_required": False,
                "auth_token": session[0],
                "main_token": session[1]
            }

            return payload
        case Codes.Exists: # Account with the same username/email already exists
            raise HTTPException(status_code=409, detail="Username already taken")
        case Codes.IllegalCharacters: # Account username/email contains illegal characters or is malformed
            raise HTTPException(status_code=400, detail="Illegal characters detected")
        case _: # Some other bad thing happened
            raise HTTPException(status_code=500)


@router.post("/password")
async def auth_password(request:Request, body:LoginPassword):
    # Get user object
    if "@" in body.username:
        user = acc_from_email(body.username)
    else:
        user = acc_from_username(body.username)

    # Check account and credentials
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif not user.verify_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid password")

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
async def auth_totp(request:Request, body:MFA):
    user = acc_from_mfa_token(body.token)

    # Check account and credentails
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif not user.verify_totp(body.code):
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
async def recover_password():
    pass # TODO: Password recovery


@router.post("/recovery/mfa")
async def recover_mfa(request:Request, body:MFA):
    user = acc_from_mfa_token(body.token)

    # Check account and credentails
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif body.code not in user.recovery:
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