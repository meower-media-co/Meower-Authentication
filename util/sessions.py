from fastapi import HTTPException
from util.database import db
from util.accounts import acc_from_id
import jwt
import os
import time

def authorize(token: str):
    try:
        session = jwt.decode(token, os.environ["JWT_PUBLIC"], verify=True)
    except:
        raise HTTPException(status_code=401, detail="Invalid authorization")
    
    if (session["t"] != "access") or (int(time.time()) > session["iat"]+600):
        raise HTTPException(status_code=401, detail="Invalid authorization")

    session_v = db.cur.execute("SELECT v FROM sessions WHERE id = ?", (session["id"],)).fetchone()
    if session["v"] != session_v[0]:
        raise HTTPException(status_code=401, detail="Invalid authorization")

    return acc_from_id(session["u"])

def get_email_link(token: str):
    row = db.cur.execute("SELECT * FROM email_links WHERE token = ?", (token,)).fetchone()
    if (row is None) or (row[2] < int(time.time())) or (row[3] != 0):
        raise HTTPException(status_code=401, detail="Authorization token is invalid")

    return {"userid": row[4], "email": row[5], "action": row[6]}