from util.database import db
from util.accounts import acc_from_id
from util.schemas.settings import ExtraAuth
from fastapi import HTTPException, Request, Header
from hashlib import sha256
import time
import json
import secrets
import os


class Session:
    def __init__(self, auth_token:str):
        if auth_token is not None:
            # Hash token
            hashed_token = sha256(auth_token.encode()).hexdigest()

            # Get session data
            data = db.cur.execute("SELECT * FROM sessions WHERE auth_hash = ?", (hashed_token,)).fetchone()
        else:
            data = None

        # Unpack the session data
        if data is None:
            # Set default values
            self.id = None
            self.auth_hash = None
            self.main_hash = None
            self.user = None
            self.client = None
            self.refreshed = None
            self.expires = None
            self._valid = False
        else:
            # Unpack data
            self.id, self.auth_hash, self.main_hash, self.user, self.client, self.refreshed, self.expires = data
            self._valid = (self.expires > time.time())

            # Get user object
            self.user = acc_from_id(self.user)

    
    def refresh(self):
        if not self._valid:
            return

        # Delete old token from Mongo
        db.mongo.sessions.delete_one({"_id": self.main_hash})

        # Delete old token from Redis
        db.redis.delete(f"auth:{self.main_hash}")

        # Create new auth and main token secrets
        auth_token = ("meow-auth_" + secrets.token_urlsafe(128))
        main_token = ("meow-main_" + secrets.token_urlsafe(64))

        # Create new auth and main token hashes
        self.auth_hash = sha256(auth_token.encode()).hexdigest()
        self.main_hash = sha256(main_token.encode()).hexdigest()[:16]

        # Insert main token into Redis
        db.redis.set(f"auth:{self.main_hash}", self.user, ex = 3600)

        # Insert main token into Mongo database
        db.mongo.sessions.insert_one({
            "_id": self.main_hash,
            "user": self.id,
            "ttl": (time.time() + 3600)
        }, {"writeConcern": {"w": "majority", "wtimeout": 5000}})

        # Update values on object
        self.refreshed = time.time()
        self.expires = (time.time() + 7890000)

        # Update values in SQLite database
        db.cur.execute("UPDATE sessions SET auth_hash = ?, main_hash = ?, refreshed = ?, expires = ? WHERE id = ?", (self.auth_hash, self.main_hash, self.refreshed, self.expires, self.id,))
        db.con.commit()

        return auth_token, main_token


    def revoke(self):
        if not self._valid:
            return

        # Delete from SQLite
        db.cur.execute("DELETE FROM sessions WHERE id = ?", (self.id,))
        db.con.commit()

        # Delete from Mongo
        db.mongo.sessions.delete_one({"_id": self.id})

        # Delete from Redis and publish to pubsub
        db.redis.delete(f"auth:{self.main_hash}")
        db.redis.publish(os.getenv("REDIS_CHANNEL", "org.meower"), json.dumps({"op": "revoke_session", "val": self.id}))

        # Clear values
        self = Session(None)


def check_auth(req:Request, authorization:str = Header()):
    """
    Get authorization of a request.
    """

    req.session = Session(authorization)
    if not req.session._valid:
        raise HTTPException(status_code = 401, detail="Unauthorized")


async def check_extra_auth(req:Request, body:ExtraAuth):
    """
    Check additional authorization required for certain account settings.
    """

    if not req.session._valid:
        raise HTTPException(status_code = 401, detail = "Unauthorized")

    if (body.totp is not None) and (not req.session.user.verify_totp(body.totp)):
        raise HTTPException(status_code = 401, detail = "Invalid TOTP")
    elif (body.password is not None) and (not req.session.user.verify_password(body.password)):
        raise HTTPException(status_code = 401, detail = "Invalid password")
    else:
        raise HTTPException(status_code = 400, detail = "No way to authenticate request")


def revoke_all_sessions(userid:str):
    """
    Revoke all of a user's sessions.
    """

    # Get all session IDs and main hashes from the database
    sessions_ids = []
    main_hashes = []
    sessions = db.cur.execute("SELECT id, main_hash FROM sessions WHERE user = ?", (userid,)).fetchall()
    for item in sessions:
        sessions_ids.append(item[0])
        main_hashes.append(item[1])

    # Delete from SQLite
    for session_id in sessions_ids:
        db.cur.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
    db.con.commit()

    # Delete from Mongo
    db.mongo.sessions.delete_many({"_id": {"$in": main_hashes}})

    # Delete from Redis and publish to pubsub
    for hash in main_hashes:
        db.redis.delete(f"auth:{hash}")
        db.redis.publish(os.getenv("REDIS_CHANNEL", "org.meower"), json.dumps({"op": "revoke_session", "val": hash}))


def get_email_link(token:str):
    # Hash token
    hashed_token = sha256(token.encode()).hexdigest()

    # Get and return email link details
    email_link = db.cur.execute("SELECT * FROM email_links WHERE id = ?", (hashed_token,)).fetchone()
    if (email_link is None) or (email_link[3] > int(time.time())):
        return None
    else:
        return {"hash": email_link[0], "user": email_link[1],  "email": email_link[2],"action": email_link[3], "expires": email_link[4]}


def revoke_email_link(hashed_token:str):
    # Delete from database
    db.cur.execute("DELETE FROM email_links WHERE id = ?", (hashed_token,))
    db.con.commit()
