from util.supporter import check_email
from util.sessions import check_auth, check_extra_auth
from util.emails import send_email
from util.schemas.settings import ChangeEmail, ChangePassword, NewTOTP
from fastapi import APIRouter, Request, Depends, HTTPException


router = APIRouter(
    prefix="/account/auth",
    tags=["Account Settings"],
    dependencies=[Depends(check_auth), Depends(check_extra_auth)]
)


@router.post("/email")
async def change_email(req:Request, body:ChangeEmail):
    """
    Change the authorized user's email address.
    """

    # Make sure username can be used
    if check_email(body.new_email):
        raise HTTPException(status_code = 400, detail = "Illegal characters detected")

    # Generate email token
    token = req.session.user.generate_email_token("verify_email", 86400)

    # Send email
    send_email(body.new_email, "verify_email", {"username": req.session.user.username}, token)

    return "OK"


@router.post("/password")
async def change_password(req:Request, body:ChangePassword):
    """
    Change the authorized user's password.
    """

    # Update password
    req.session.user.update_password(body.new_password)

    return "OK"


@router.get("/totp")
async def get_totp_secret():
    """
    Get a TOTP base32 secret.
    """

    return "Not implemented yet"


@router.put("/totp")
async def add_totp(req:Request, body:NewTOTP):
    """
    Add a TOTP authenticator to the authorized user.
    """

    # Attempt to add TOTP authenticator
    success, authenticator_id = req.session.user.add_totp(body.nickname, body.secret, body.code)
    if not success:
        raise HTTPException(status_code = 400, detail = "Invalid TOTP code")
    
    # Generate recovery codes if there are none
    if len(req.session.user.recovery) == 0:
        req.session.user.refresh_recovery()

    return {"authenticator_id": authenticator_id, "recovery_codes": req.session.user.recovery}


@router.delete("/totp/{authenticator_id}")
async def remove_totp(req:Request, authenticator_id:str):
    """
    Remove a TOTP authenticator from the authorized user.
    """

    # Attempt to remove TOTP authenticator
    status = req.session.user.remove_totp(authenticator_id)

    if status:
        return "OK"
    else:
        raise HTTPException(status_code = 400, detail = "Unknown TOTP authenticator")


@router.get("/recovery")
async def get_recovery(req:Request):
    """
    Get recovery codes for the authorized user.
    """

    return req.session.user.recovery


@router.post("/recovery")
async def refresh_recovery(req:Request):
    """
    Refresh recovery codes for the authorized user.
    """

    req.session.user.refresh_recovery()

    return req.session.user.recovery
