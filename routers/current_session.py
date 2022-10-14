from util.supporter import check_username
from util.ratelimits import auto_ratelimit, check_ratelimit, ratelimit
from util.accounts import acc_from_username, acc_from_email, acc_from_mfa_token
from util.emails import send_email
from util.schemas.authentication import CreateAccount, LoginPassword, TOTP, PasswordRecovery, MFARecovery
from fastapi import APIRouter, HTTPException, Request


router = APIRouter(
    prefix="/session",
    tags=["Sessions"]
)


@router.get("/")
async def get_session(request:Request):
    """
    Get details about the current session.
    """


@router.delete("/refresh")
async def refresh_session(request:Request):
    """
    Refresh current session.
    """


@router.delete("/revoke")
async def revoke_session(request:Request):
    """
    Revoke current session.
    """
