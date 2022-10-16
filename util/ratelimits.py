from util.supporter import log
from util.database import db
from fastapi import HTTPException
import time
from threading import Thread
import requests
import os


"""
Ratelimits specifically for the authentication server.

These ratelimits only use SQLite in-memory since the auth server
doesn't have a fast connection to the Redis cluster and doesn't 
need to be super fast. 

The expired ratelimit entries get cleaned out every minute.


Buckets:
* global
* registrations
* failed_pswd
* failed_webauthn
* failed_mfa
* reset_pswd
* get_user
* get_settings
* update_email
* update_pswd
* update_webauthn
* update_totp
* get_sessions
"""


def check_captcha(token:str):
    # Set captcha provider
    captcha_provider = os.getenv("CAPTCHA_PROVIDER", None)
    if captcha_provider is None:
        log.warning("No captcha provider set! Please set one to help stop bots.")
        return True
    elif captcha_provider == "turnstile":
        api_uri = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    elif captcha_provider == "recaptcha":
        api_uri = "https://www.google.com/recaptcha/api/siteverify"
    elif captcha_provider == "hcaptcha":
        api_uri = "https://hcaptcha.com/siteverify"

    # Validate token with API
    resp = requests.post(api_uri, data = {
        "secret": os.getenv("CAPTCHA_SECRET"),
        "response": token
    })
    if (resp.status_code == 200) and resp.json()["success"]:
        return True
    else:
        return False


def check_ratelimit(bucket:str, identifier:str):
    """
    Check a ratelimit.

    Returns boolean which indicates if the identifier is ratelimited.
    """

    # Initialize variables
    ratelimit_id = (str(bucket) + str(identifier))
    ratelimit_obj = db.mem.execute("SELECT * FROM ratelimits WHERE id = ?", (ratelimit_id,)).fetchone()

    # Return status
    if (ratelimit_obj is None) or (ratelimit[2] <= time.time()):
        return False
    elif ratelimit_obj[1] <= 0:
        return True
    else:
        return False


def ratelimit(bucket:str, identifier:str, limit:int, ttl:int):
    """
    Create/update a ratelimit.

    Returns boolean which indicates if ratelimit creation/update succeeded.
    """

    # Initialize variables
    ratelimit_id = (str(bucket) + str(identifier))
    ratelimit_obj = db.mem.execute("SELECT * FROM ratelimits WHERE id = ?", (ratelimit_id,)).fetchone()

    # Check ratelimit status
    if (ratelimit_obj is None) or (ratelimit[2] <= (time.time() + ttl)):  # Check if ratelimit doesn't exist or has expired
        ratelimit_obj = (ratelimit_id, (limit - 1), (time.time() + ttl))
        db.mem.execute("INSERT INTO ratelimits VALUES (?, ?, ?)", ratelimit_obj)

        return True
    elif ratelimit_obj[1] > 0:  # Check if limit has been reached
        ratelimit_obj[1] -= 1
        db.mem.execute("UPDATE ratelimits SET remaining = ? WHERE id = ?", (ratelimit_obj[1], ratelimit_id,))

        return True
    else:
        return False


def auto_ratelimit(bucket:str, identifier:str, limit:int, ttl:int):
    """
    Automatically check and update ratelimit, raise HTTPException if identifier is ratelimited.
    """

    if check_ratelimit(bucket, identifier):
        raise HTTPException(status_code = 429, detail = "You are being ratelimited.")
    else:
        ratelimit(bucket, identifier, limit, ttl)
