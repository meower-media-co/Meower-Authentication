from util.database import db
from util.accounts import acc_from_id
from util.sessions import get_email_token
from fastapi import APIRouter, HTTPException
from util.schemas.email import ResetPassword


router = APIRouter(
    prefix="/email",
    tags=["Email"]
)


@router.get("/")
async def email_link_info(token:str):
    link_info = get_email_token(token)

    if link_info is not None:
        raise HTTPException(status=401, detail="Invalid email token.")
    else:
        return link_info


@router.post("/verify-email")
async def verify_email(token:str):
    link_info = get_email_token(token)

    if (link_info is None) or (link_info["action"] != "verify-email"):
        raise HTTPException(status=401, detail="Invalid email token.")

    user = acc_from_id(link_info["userid"])
    user.update_email(link_info["email"])

    db.cur.execute("DELETE FROM email_links WHERE token = ?", (token,))
    db.con.commit()

    return "OK"


@router.post("/reset-password")
async def reset_password(token:str, body:ResetPassword):
    link_info = get_email_token(token)

    if (link_info is None) or (link_info["action"] != "reset-password"):
        raise HTTPException(status=401, detail="Invalid email token.")

    user = acc_from_id(link_info["userid"])
    user.update_password(body.new_password)

    db.cur.execute("DELETE FROM email_links WHERE token = ?", (token,))
    db.con.commit()

    return "OK"


@router.post("/revert-email")
async def revert_email(token:str):
    link_info = get_email_token(token)

    if (link_info is None) or (link_info["action"] != "verify-email"):
        raise HTTPException(status=401, detail="Invalid email token.")

    user = acc_from_id(link_info["userid"])
    user.update_email(link_info["email"])

    db.cur.execute("DELETE FROM email_links WHERE token = ?", (token,))
    db.con.commit()

    return "OK"