from util.database import db
from util.supporter import log, snowflake
from hashlib import sha256
from passlib.hash import bcrypt
from pyotp import TOTP
import json
import time
import secrets
import string
import os


RECOVERY_CODE_CHARS = (string.ascii_lowercase + string.digits)


class Account:
    def __init__(self, userdata:tuple):
        self._exists = (userdata is not None)
        
        if self._exists:
            # Unpack userdata
            self.id = userdata[0]
            self.username = userdata[1]
            self.email = userdata[2]
            self.password = userdata[3]
            self.webauthn = json.loads(userdata[4])
            self.totp = json.loads(userdata[5])
            self.recovery = json.loads(userdata[6])
            self.lock_status = userdata[7]
        else:
            # Create default userdata
            self.id = None
            self.username = None
            self.email = None
            self.password = None
            self.webauthn = []
            self.totp = []
            self.recovery = []
            self.lock_status = 0


    def create(self, username, display_name, password, child):
        # Update attributes on account object
        self._exists = True
        self.id = snowflake()
        self.username = username.lower()
        self.password = bcrypt.hash(password, salt = int(os.getenv("SALT_STRENGTH", 14)))

        # Insert account into Mongo database
        db.mongo.users.insert_one({
            "_id": self.id,
            "username": display_name,
            "username_lower": display_name.lower(),
            "created": int(time.time()),
            "flags": (1 if child else 0),
            "admin": 0,
            "config": 0,
            "custom_theme": {},
            "quote": "",
            "following": []
        }, {"writeConcern": {"w": "majority", "wtimeout": 5000}})

        # Insert account into SQLite database
        db.cur.execute("INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (self.id, self.username, self.email, self.password, self.webauthn, self.totp, self.recovery, self.lock_status,))
        db.con.commit()

        return True


    def update_email(self, email:str):
        # Update email on account object
        self.email = email

        # Update account in database
        db.cur.execute("UPDATE accounts SET email = ? WHERE id = ?", (self.email, self.id,))
        db.con.commit()

        return True


    def verify_password(self, password:str):
        # Make sure password is set
        if self.password is None:
            return False

        # Check if password is valid
        pswd_valid =  bcrypt.verify(password, self.password)

        # Return password validity
        if pswd_valid:
            return True
        else:
            return False


    def update_password(self, password:str):
        # Hash new password and update attribute
        self.password = bcrypt.hash(password, salt = int(os.getenv("SALT_STRENGTH", 14)))

        # Update password in database
        db.cur.execute("UPDATE accounts SET password = ? WHERE id = ?", (self.password, self.id,))
        db.con.commit()

        return True


    def add_totp(self, nickname:str, secret:str, code:str):
        # Verify and add TOTP code
        try:
            if TOTP(secret).verify(code):
                authenticator_id = snowflake()
                self.totp.append({"id": authenticator_id, "name": nickname, "secret": secret})
                db.cur.execute("UPDATE accounts SET totp = ? WHERE id = ?", (json.dumps(self.totp), self.id,))
                db.con.commit()
                return True
            else:
                return False
        except:
            return False


    def remove_totp(self, authenticator_id:str):
        # Loop through authenticators and find authenticator to remove
        for authenticator in self.totp:
            if authenticator["id"] == authenticator_id:
                self.totp.remove(authenticator)
                db.cur.execute("UPDATE accounts SET totp = ? WHERE id = ?", (json.dumps(self.totp), self.id,))
                db.con.commit()
                return True

        return False


    def refresh_recovery(self):
        # Create new recovery codes
        recovery_codes = []
        for i in range(8):
            # Gemerate secret code
            new_code = ""
            for i in range(4):
                new_code += secrets.choice(RECOVERY_CODE_CHARS)
            new_code += "-"
            for i in range(4):
                new_code += secrets.choice(RECOVERY_CODE_CHARS)
            
            # Append to list
            recovery_codes.append(new_code)
        
        # Update recovery attribute
        self.recovery = recovery_codes

        # Update recovery in database
        db.cur.execute("UPDATE accounts SET recovery = ? WHERE id = ?", (json.dumps(self.recovery), self.id,))
        db.con.commit()
        
        return recovery_codes


    def remove_recovery(self, code:int = None):
        # Update recovery attribute
        if code is None:
            self.recovery = []
        else:
            self.recovery.remove(code)

        # Update recovery in database
        db.cur.execute("UPDATE accounts SET recovery = ? WHERE id = ?", (json.dumps(self.recovery), self.id,))
        db.con.commit()

        return True


    def verify_totp(self, code:str):
        # Loop through authenticators and check authenticator secret
        for authenticator in self.totp:
            if TOTP(authenticator["secret"]).verify(code):
                return True

        return False


    def change_lock_status(self, mode:int):
        self.lock_status = mode
        db.cur.execute("UPDATE accounts SET lock_status = ? WHERE id = ?", (self.lock_status, self.id,))
        db.con.commit()

        return True


    def generate_session(self, client):
        # Create session snowflake
        session_id = snowflake()

        # Create auth and main token secrets
        auth_token = ("meow-auth_" + secrets.token_urlsafe(128))
        main_token = ("meow-main_" + secrets.token_urlsafe(64))

        # Create auth and main token hashes
        hashed_auth_token = sha256(auth_token.encode()).hexdigest()
        hashed_main_token = sha256(main_token.encode()).hexdigest()[:16]

        # Insert auth token into SQLite database
        db.cur.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)", (session_id, hashed_auth_token, hashed_main_token, self.id, json.dumps(client), time.time(), (time.time() + 7890000),))
        db.con.commit()

        # Insert main token into Redis
        db.redis.set(f"auth:{hashed_main_token}", self.user, ex = 3600)

        # Insert main token into Mongo database
        db.mongo.sessions.insert_one({
            "_id": hashed_main_token,
            "user": self.id,
            "ttl": (time.time() + 3600)
        }, {"writeConcern": {"w": "majority", "wtimeout": 5000}})

        # Return auth and main token
        return auth_token, main_token


    def generate_mfa_token(self):
        # Create token secret
        token = ("meow-mfa_" + secrets.token_urlsafe(128))

        # Create token hash
        hashed_token = sha256(token.encode()).hexdigest()

        # Insert token into in-memory database
        db.mem.execute("INSERT INTO mfa VALUES (?, ?, ?)", (hashed_token, self.id, (time.time() + 600),))

        # Return token
        return token


    def generate_email_token(self, action, ttl):
        # Create token secret
        token = ("meow-email_" + secrets.token_urlsafe(128))

        # Create token hash
        hashed_token = sha256(token.encode()).hexdigest()

        # Insert token into SQLite database
        db.cur.execute("INSERT INTO email_links VALUES (?, ?, ?, ?, ?)", (hashed_token, self.id, self.email, action, (int(time.time()) + ttl)))
        db.con.commit()

        # Return token
        return token


def acc_from_id(userid:str):
    # Get account data
    userdata = db.cur.execute("SELECT * FROM accounts WHERE id = ?", (userid,)).fetchone()

    # Add log
    log.store("got_account", {"method": "id", "user": userdata[0]})

    # Return account
    return Account(userdata)


def acc_from_username(username:str):
    # Get account data
    userdata = db.cur.execute("SELECT * FROM accounts WHERE username = ?", (username.lower(),)).fetchone()

    # Add log
    log.store("got_account", {"method": "username", "user": userdata[0]})

    # Return account
    return Account(userdata)


def acc_from_email(email:str):
    # Get account data
    userdata = db.cur.execute("SELECT * FROM accounts WHERE email = ?", (email.lower(),)).fetchone()

    # Add log
    log.store("got_account", {"method": "email", "user": userdata[0]})

    # Return account
    return Account(userdata)


def acc_from_mfa_token(token:str):
    # Hash token
    hashed_token = sha256(token.encode()).hexdigest()

    # Get session data
    token_data = db.mem.execute("SELECT * FROM mfa WHERE id = ?", (hashed_token,)).fetchone()
    if int(time.time()) > token_data[2]:
        return Account(None)

    # Get account data
    userdata = db.cur.execute("SELECT * FROM accounts WHERE id = ?", (token_data[1],)).fetchone()

    # Add log
    log.store("got_account", {"method": "mfa_token", "user": userdata[0]})

    # Return account
    return Account(userdata)
