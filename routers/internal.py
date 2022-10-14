from util.database import db
from util.accounts import acc_from_id
from util.emails import send_email
from fastapi import APIRouter, HTTPException, Request, Header, Depends
from util.schemas.internal import SendEmail, LockAccount
import os
import json


def check_auth(req:Request, secret_key:str = Header()):
    # Check secret key and IP whitelist
    if req.client.info["ip"] not in json.loads(os.getenv("INTERNAL_IPS")):
        raise HTTPException(status_code = 404)  # Standard 404 error code to not give the client any hints
    elif secret_key != os.getenv("SECRET_KEY"):
        raise HTTPException(status_code = 403, detail = "Invalid secret key")


router = APIRouter(
    prefix="/internal",
    tags=["Internal"],
    dependencies=[Depends(check_auth)]
)


@router.post("/send-email")
async def req_send_email(body:SendEmail):
    # Get user
    user = acc_from_id(body.user)

    # Check user
    if not user._exists:
        raise HTTPException(status_code = 404, detail = "User not found")
    elif user.email is None:
        raise HTTPException(status_code = 400, detail = "User does not have a verified email")

    # Send the email
    try:
        send_email(body.email, body.template, body.details)
        return "OK"
    except:
        raise HTTPException(status_code = 500, detail = "Failed to send email")


@router.post("/lock-account")
async def lock_account(body:LockAccount):
    # Get user
    user = acc_from_id(body.user)

    # Check user
    if not user._exists:
        raise HTTPException(status_code = 404, detail = "User not found")
    
    # Lock the account
    user.change_lock_status(body.mode)

    return "OK"
