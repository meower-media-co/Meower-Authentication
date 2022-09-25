from fastapi import HTTPException
from database import db
from accounts import Account
import jwt
import os
import time

def authorize(token: str):
    try:
        session = jwt.decode(token, os.environ["JWT_PUBLIC"], verify=True)
    except:
        raise HTTPException(status_code=401, detail="Invalid authorization")
    
    if session["t"] != "access":
        raise HTTPException(status_code=401, detail="Invalid authorization")
    elif int(time.time()) > session["iat"]+600:
        raise HTTPException(status_code=401, detail="Authorization token has expired")

    session_v = db.cur.execute("SELECT (v) FROM sessions WHERE id = ?", session["id"]).fetchone()
    if session["v"] != session_v[0]:
        raise HTTPException(status_code=401, detail="Invalid authorization")

    return Account(session["u"])

def get_email_link(token: str):
    row = db.cur.execute("SELECT * FROM 'email_links' WHERE token = ?", (token,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Authorization token is invalid")
    elif row[2] < int(time.time()):
        raise HTTPException(status_code=401, detail="Authorization token has expired")
    elif row[3] == 1:
        raise HTTPException(status_code=401, detail="Authorization token has been revoked")

    return {"userid": row[4], "email": row[5], "action": row[6]}