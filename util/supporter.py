from util.database import db
from datetime import datetime
from threading import Thread
import os
import time
import json
import string

# Allowed characters within usernames
ALLOWED_USERNAME_CHARS = ["-", "_", "."]
ALLOWED_USERNAME_CHARS += string.ascii_letters
ALLOWED_USERNAME_CHARS += string.digits

# Incremental counter for snowflakes
id_increment = 0

class PrintColors:
    """
    Nice colors used for when printing logs to the console.
    """

    HEADER = "\033[95m"
    OK = "\033[92m"
    INFO = "\033[93m"
    ERROR = "\033[91m"
    END = "\033[0m"

def log(prefix:str, log_type:int, msg:str):
    # Create prefix
    prefix = f"{[PrintColors.OK, PrintColors.INFO, PrintColors.ERROR][log_type]}[{['SUCCESS', 'INFO', 'ERROR'][log_type]}]{PrintColors.END} {PrintColors.HEADER}[{prefix}]{PrintColors.END}"

    # Create timestamp
    timestamp = datetime.now().strftime("%m/%d/%Y %H:%M.%S")

    # Print log
    print(f"{prefix} {timestamp}: {msg}")

def add_log(action:str, details:dict, user:str = None, email:str = None, ip:str = None):
    def run():
        db.cur.execute("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?)", (snowflake(), int(time.time()), json.dumps(details), action, details, user, email, ip,))
        db.con.commit()
    
    # Thread the main runner so it doesn't hold up the main process
    Thread(target=run).start()

def snowflake():
    """
    Generates a unique snowflake for indentifying entities within Meower.

    Format:
    1) Milliseconds since unix epoch
    2) The ID of the server it was created on
    3) The process ID of the server instance
    4) An incremental counter
    """

    # Add increment
    id_increment += 1

    # Generate and return uid
    return (str(time()) + str(os.getenv("SERVER_ID", "0")) + str(os.getpid()) + str(id_increment))

def check_username(username:str):
    """
    Make sure length of username is within range and the username doesn't contain any illegal characters.
    """

    # Check if username is not within length limits
    if (len(username) < 1) or (len(username) > 20):
        return True

    # Check if username has illegal characters
    for char in username:
        if char not in ALLOWED_USERNAME_CHARS:
            return True

    return False