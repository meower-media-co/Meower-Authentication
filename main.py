from fastapi import FastAPI, HTTPException, Request
from pyotp import TOTP
from database import db
from accounts import Account
from sessions import get_email_link
from dotenv import load_dotenv
import os
import jwt
import json
import time

# load environment variables
load_dotenv()

# load JWT private key
with open("jwt.pem", "r") as f:
    os.environ["JWT_PRIVATE"] = f.read().encode()

# Load JWT public key
with open("jwt.pem.pub", "r") as f:
    os.environ["JWT_PUBLIC"] = f.read().encode()

app = FastAPI()

@app.get("/email")
async def email_link_get(token: str):
    return get_email_link(token)

@app.post("/email")
async def email_link_post(req: Request, token: str):
    link = get_email_link(token)

    if link["action"] == "verify-email":
        db.cur.execute("UPDATE accounts SET email = ? WHERE id = ?", (link["email"], link["userid"],))

    db.cur.execute("DELETE FROM email_links WHERE token = ?", (token,))
    db.con.commit()

    return "OK"

@app.get("/authenticate/{userid}/methods")
async def auth_methods(userid: str):
    user = Account(userid)
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")

    return {"password": (user.password is not None), "webauthn": (len(json.loads(user.webauthn)) > 0)}

@app.post("/authenticate/{userid}/password")
async def auth_password(req: Request, userid: str):
    req_json = await req.json()

    user = Account(userid)
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")
    elif not user.verify_password(req_json.get("password")):
        raise HTTPException(status_code=401, detail="Invalid password")

    if user.totp is not None:
        return {"requires_totp": True, "totp_token": jwt.encode({"t": "totp", "u": user.id, "iat": int(time.time())}, os.environ["JWT_PRIVATE"], algorithm="RS256").decode()}
    else:
        session = user.generate_session(req.client.host, req.headers.get("User-Agent"), 0)
        return {"requires_totp": False, "access_token": session[0], "refresh_token": session[1]}

@app.post("/authenticate/totp")
async def auth_password(req: Request, token: str):
    req_json = await req.json()
    code = req_json["code"]

    try:
        totp_session = jwt.decode(token, os.environ["JWT_PUBLIC"], verify=True)
    except:
        raise HTTPException(status_code=401, detail="Invalid TOTP token")
    
    if int(time.time()) > totp_session["iat"]+600:
        raise HTTPException(status_code=401, detail="TOTP token has expired")

    user = Account(totp_session["u"])
    if not user._exists:
        raise HTTPException(status_code=404, detail="Account not found")
    elif user.locked > 0:
        raise HTTPException(status_code=403, detail="Account locked")

    valid = False
    if type(user.totp) == dict:
        if code in user.totp["recovery"]:
            user.totp["recovery"].remove(code)
            db.cur.execute("UPDATE accounts SET totp = ? WHERE id = ?", (json.dumps(user.totp), user.id,))
            db.con.commit()

            valid = True

        if not valid:
            for authenticator in user.totp["authenticators"]:
                if TOTP(authenticator["secret"]).verify(code):
                    valid = True
                    break

    if valid:
        session = user.generate_session(req.client.host, req.headers.get("User-Agent"), 0)
        return {"requires_totp": False, "access_token": session[0], "refresh_token": session[1]}
    else:
        raise HTTPException(status_code=401, detail="Invalid TOTP code")