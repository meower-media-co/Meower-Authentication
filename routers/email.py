from util.database import db
from util.accounts import acc_from_id
from util.sessions import get_email_link, revoke_email_link
from fastapi import APIRouter, HTTPException
from util.schemas.email import ResetPassword, VerifyChild


router = APIRouter(
    prefix="/email",
    tags=["Email"]
)


@router.get("/")
async def email_link_info(token:str):
    return get_email_link(token)


@router.delete("/")
async def delete_email_link(token:str):
    # Get email link info
    link_info = get_email_link(token)
    if link_info is None:
        raise HTTPException(status=401, detail="Invalid email token")

    # Revoke email link
    revoke_email_link(link_info["hash"])

    return "OK"


@router.post("/verify-email")
async def verify_email(token:str):
    # Get email link info
    link_info = get_email_link(token)
    if (link_info is None) or (link_info["action"] != "verify_email"):
        raise HTTPException(status=401, detail="Invalid email token")

    # Update user's email
    user = acc_from_id(link_info["userid"])
    user.update_email(link_info["email"])

    # Update user flags
    mongo_user = db.mongo.users.find_one({"_id": user.id})
    if (mongo_user["flags"] & (1 << 2)) == 0:
        mongo_user["flags"] |= (1 << 2)
        db.mongo.users.update_one({"_id": user.id}, {"$set": {"flags": mongo_user["flags"]}})

    # Revoke email link
    revoke_email_link(link_info["hash"])

    return "OK"


@router.post("/verify-child")
async def verify_child(token:str, body:VerifyChild):
    # Get email link info
    link_info = get_email_link(token)
    if (link_info is None) or (link_info["action"] != "verify_child"):
        raise HTTPException(status=401, detail="Invalid email token")

    # Get user
    user = acc_from_id(link_info["userid"])

    # Update user flags
    mongo_user = db.mongo.users.find_one({"_id": user.id})
    if (mongo_user["flags"] & (1 << 1)) == 0:
        mongo_user["flags"] |= (1 << 1)
        db.mongo.users.update_one({"_id": user.id}, {"$set": {"flags": mongo_user["flags"]}})
    
    # Revoke email link
    revoke_email_link(link_info["hash"])

    return "OK"

@router.post("/reset-password")
async def reset_password(token:str, body:ResetPassword):
    # Get email link info
    link_info = get_email_link(token)
    if (link_info is None) or (link_info["action"] != "reset_password"):
        raise HTTPException(status=401, detail="Invalid email token")

    # Update user's password
    user = acc_from_id(link_info["userid"])
    user.update_password(body.new_password)

    # Revoke email link
    revoke_email_link(link_info["hash"])

    return "OK"


@router.post("/revert-email")
async def revert_email(token:str):
    # Get email link info
    link_info = get_email_link(token)
    if (link_info is None) or (link_info["action"] != "revert_email"):
        raise HTTPException(status=401, detail="Invalid email token")

    # Update user's email
    user = acc_from_id(link_info["userid"])
    user.update_email(link_info["email"])

    # Revoke email link
    revoke_email_link(link_info["hash"])

    return "OK"
