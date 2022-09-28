from util.database import db
from util.checks import check_username
from hashlib import sha256
from passlib.hash import bcrypt
from pyotp import TOTP
from uuid import uuid4
import os
import json
import time
import jwt
import secrets

class Account:
    def __init__(self, userdata):
        if userdata is not None:
            self._exists = True

            self.id = userdata[0]
            self.username = userdata[1]
            self.display_name = userdata[2]
            self.email = userdata[3]
            self.password = userdata[4]
            self.prev_pswds = userdata[5]
            self.webauthn = json.loads(userdata[6])
            self.totp = json.loads(userdata[7])
            self.locked = userdata[8]
        else:
            self._exists = False

            self.id = str(uuid4())
            self.username = None
            self.display_name = None
            self.email = None
            self.password = None
            self.prev_pswds = json.dumps([])
            self.webauthn = json.dumps([])
            self.totp = json.dumps({"authenticators": [], "recovery": []})
            self.locked = 0

    def create(self, username, email, password, child):
        if self._exists:
            raise FileExistsError

        if check_username(username):
            raise ValueError

        self._exists = True
        self.username = username.lower()
        self.display_name = username
        self.password = bcrypt.hash(password)

        db.cur.execute("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (self.id, self.username, self.display_name, self.email, self.password, self.prev_pswds, self.webauthn, self.totp, self.locked,))
        db.con.commit()

        return True

    def update_email(self, email: str):
        if not self._exists:
            raise FileNotFoundError

        self.email = email

        db.cur.execute("UPDATE accounts SET email = ? WHERE id = ?", (self.email, self.id,))
        db.con.commit()

        return True

    def verify_password(self, password: str):
        if not self._exists:
            raise FileNotFoundError

        return bcrypt.verify(password, self.password)

    def update_password(self, password: str):
        if not self._exists:
            raise FileNotFoundError

        self.password = bcrypt.hash(password)

        db.cur.execute("UPDATE accounts SET password = ? WHERE id = ?", (self.password, self.id,))
        db.con.commit()

        return True

    def verify_totp(self, code: str):
        if not self._exists:
            raise FileNotFoundError
        
        if code in self.totp["recovery"]:
            return True

        for authenticator in self.totp["authenticators"]:
            if TOTP(authenticator["secret"]).verify(code):
                return True

        return False

    def generate_session(self, client_name, client_type, user_agent, ip, impersonating=0):
        if not self._exists:
            raise FileNotFoundError

        db.cur.execute("INSERT INTO sessions VALUES (?, 1, ?, ?, ?, ?, ?, 0)", (str(uuid4()), self.id, json.dumps({"name": client_name, "type": client_type}), user_agent, ip, impersonating,)).fetchone()
        db.con.commit()

        access_token = {"t": "access", "id": db.cur.lastrowid, "v": 1, "u": self.id, "iat": int(time.time())}
        refresh_token = {"t": "refresh", "id": db.cur.lastrowid, "v": 1, "iat": int(time.time())}

        return jwt.encode(access_token, os.environ["JWT_PRIVATE"], algorithm="RS256").decode(), jwt.encode(refresh_token, os.environ["JWT_PRIVATE"], algorithm="RS256").decode()

    def generate_email_link(self, action, ttl):
        if not self._exists:
            raise FileNotFoundError

        token = secrets.token_urlsafe(64)

        db.cur.execute("INSERT INTO email_links VALUES (?, ?, ?, ?, ?, ?)", (str(uuid4()), sha256(token.encode()).hexdigest(), int(time.time())+ttl, self.id, self.email, action))
        db.con.commit()

        return token

def acc_from_id(userid: str):
    userdata = db.cur.execute("SELECT * FROM accounts WHERE id = ?", (userid.lower(),)).fetchone()
    return Account(userdata)

def acc_from_username(username: str):
    userdata = db.cur.execute("SELECT * FROM accounts WHERE username = ?", (username.lower(),)).fetchone()
    return Account(userdata)

def acc_from_email(email: str):
    userdata = db.cur.execute("SELECT * FROM accounts WHERE email = ?", (email.lower(),)).fetchone()
    return Account(userdata)