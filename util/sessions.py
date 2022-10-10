from util.database import db
import time


def get_email_token(token: str):
    row = db.cur.execute("SELECT * FROM email_links WHERE token = ?", (token,)).fetchone()
    if (row is None) or (row[2] < int(time.time())) or (row[3] != 0):
        return None

    return {"userid": row[4], "email": row[5], "action": row[6]}