from database import db
from hashlib import sha256
from passlib.hash import bcrypt
import os
import json
import time
import jwt
import secrets

class Account:
    def __init__(self, userid:str):
        self.id = userid
        row = db.cur.execute("SELECT * FROM accounts WHERE id = ?", (self.id,)).fetchone()
        if row is not None:
            self._exists = True

            self.id = row[0]
            self.email = row[1]
            self.password = row[2]
            self.prev_pswds = row[3]
            self.webauthn = json.loads(row[4])
            self.totp = json.loads(row[5])
            self.locked = row[6]
        else:
            self._exists = False
    
    def create(self, password):
        if not self._exists:
            self.email = None
            self.password = bcrypt.hash(password)
            self.prev_pswds = json.dumps([])
            self.webauthn = json.dumps([])
            self.totp = json.dumps({"authenticators": [], "recovery": []})
            self.locked = 0

            db.cur.execute("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?)", (self.id, self.email, self.password, self.prev_pswds, self.webauthn, self.totp, self.locked,))
            db.con.commit()

            return True

    def update_email(self, email:str):
        if self._exists:
            self.email = email

            db.cur.execute("UPDATE accounts SET email = ? WHERE id = ?", (self.email, self.id,))
            db.con.commit()

            return True

    def verify_password(self, password:str):
        if self._exists:
            return bcrypt.verify(password, self.password)

    def update_password(self, password:str):
        if self._exists:
            self.password = bcrypt.hash(password)

            db.cur.execute("UPDATE accounts SET password = ? WHERE id = ?", (self.password, self.id,))
            db.con.commit()

            return True

    def generate_session(self, ip, user_agent, impersonating=0):
        db.cur.execute("INSERT INTO sessions VALUES (null, 1, ?, ?, ?, ?, 0)", (self.id, ip, user_agent, impersonating,)).fetchone()
        db.con.commit()

        access_token = {"t": "access", "id": db.cur.lastrowid, "v": 1, "u": self.id, "iat": int(time.time())}
        refresh_token = {"t": "refresh", "id": db.cur.lastrowid, "v": 1, "iat": int(time.time())}

        return jwt.encode(access_token, os.environ["JWT_PRIVATE"], algorithm="RS256").decode(), jwt.encode(refresh_token, os.environ["JWT_PRIVATE"], algorithm="RS256").decode()

    def generate_email_link(self, action, ttl):
        token = secrets.token_urlsafe(64)

        db.cur.execute("INSERT INTO email_links VALUES (null, ?, ?, ?, ?, ?)", (sha256(token.encode()).hexdigest(), int(time.time())+ttl, self.id, self.email, action))
        db.con.commit()

        return token