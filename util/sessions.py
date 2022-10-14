from util.database import db
from hashlib import sha256
import time


def get_email_link(token:str):
    # Hash token
    hashed_token = sha256(token.encode()).hexdigest()

    # Get and return email link details
    email_link = db.cur.execute("SELECT * FROM email_links WHERE id = ?", (hashed_token,)).fetchone()
    if (email_link is None) (email_link[3] > int(time.time())):
        return None
    else:
        return {"hash": email_link[0], "user": email_link[1],  "email": email_link[2],"action": email_link[3], "expires": email_link[4]}


def revoke_email_link(hashed_token:str):
    # Delete from database
    db.cur.execute("DELETE FROM email_links WHERE id = ?", (hashed_token,))
    db.con.commit()
