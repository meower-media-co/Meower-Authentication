from fastapi import APIRouter, Request
from util.database import db
from util.sessions import get_email_link

router = APIRouter(
    prefix="/email",
    tags=["Email"],
    responses={404: {"error": True, "type": "notFound"}}
)

@router.get("/")
async def email_link_info(token: str):
    return get_email_link(token)

@router.post("/")
async def email_link_execute(req: Request, token: str):
    link = get_email_link(token)

    if link["action"] == "verify-email":
        db.cur.execute("UPDATE accounts SET email = ? WHERE id = ?", (link["email"], link["userid"],))

    db.cur.execute("DELETE FROM email_links WHERE token = ?", (token,))
    db.con.commit()

    return "OK"