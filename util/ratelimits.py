from util.supporter import log
from util.database import db
from fastapi import HTTPException
from time import time
from threading import Thread


"""
Ratelimits specifically for the authentication server.

These ratelimits only use SQLite in-memory since the auth server
doesn't have a fast connection to the Redis cluster and doesn't 
need to be super fast. 

The expired ratelimit entries get cleaned out every minute.


Buckets:
* global
* invalid_username
* failed_pswd
* failed_webauthn
* failed_mfa
* get_user
* get_settings
* update_email
* update_pswd
* update_webauthn
* update_totp
* get_sessions
"""


# Attempt to create the in-memory ratelimits table
try:
    db.mem.execute("""
        CREATE TABLE ratelimits (
            id TEXT NOT NULL PRIMARY KEY,
            count INTEGER NOT NULL,
            limit INTEGER NOT NULL,
            reset REAL NOT NULL
        )
    """)
    db.mem.execute("""
        CREATE INDEX ratelimit_id ON ratelimits (
            id
        )
    """)
except Exception as err:
    log("Memory DB", 1, f"Error making table: {str(err)}")


def background_cleanup():
    while True:
        time.sleep(60)
        db.mem.execute("DELETE FROM ratelimits WHERE reset <= ?", (time(),))
        log("Memory DB", 1, "Cleared expired ratelimits.")


def check_ratelimit(bucket:str, identifier:str):
    """
    Check a ratelimit.

    Returns boolean which indicates if the identifier is ratelimited.
    """

    # Initialize variables
    ratelimit_id = (str(bucket) + str(identifier))
    ratelimit_obj = db.mem.execute("SELECT * FROM ratelimits WHERE id = ?", (ratelimit_id,)).fetchone()

    # Return status
    if (ratelimit_obj is None) or (ratelimit[3] <= time()):
        return False
    elif ratelimit_obj[1] >= ratelimit_obj[2]:
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
    if (ratelimit_obj is None) or (ratelimit[3] <= (time() + ttl)):  # Check if ratelimit doesn't exist or has expired
        ratelimit_obj = (ratelimit_id, 1, (time() + ttl))
        db.mem.execute("INSERT INTO ratelimits VALUES (?, ?, ?)", ratelimit_obj)
        return True
    elif ratelimit_obj[1] < limit:  # Check if limit has been reached
        ratelimit_obj[1] += 1
        db.mem.execute("UPDATE ratelimits SET count = ? WHERE id = ?", (ratelimit_obj[1], ratelimit_id,))
        return True
    else:
        return False


def auto_ratelimit(bucket:str, identifier:str, limit:int, ttl:int):
    """
    Automatically check and update ratelimit, raise HTTPException if identifier is ratelimited.
    """

    if check_ratelimit(bucket, identifier):
        raise HTTPException(status_code=429, detail="You are being ratelimited.")
    else:
        ratelimit(bucket, identifier, limit, ttl)


# Start cleanup thread
cleanup_thread = Thread(target=background_cleanup)
cleanup_thread.daemon = True
cleanup_thread.start()