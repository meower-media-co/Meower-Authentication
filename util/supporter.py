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

    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"


class log:
    def success(event:str):
        print(PrintColors.GREEN, "[{0}]".format(datetime.now().strftime("%m/%d/%Y %H:%M.%S")), "[ERROR]", event, PrintColors.END)


    def info(event:str):
        print("[{0}]".format(datetime.now().strftime("%m/%d/%Y %H:%M.%S")), "[INFO]", event)


    def warning(event:str):
        print(PrintColors.YELLOW, "[{0}]".format(datetime.now().strftime("%m/%d/%Y %H:%M.%S")), "[WARNING]", event, PrintColors.END)


    def error(event:str):
        print(PrintColors.RED, "[{0}]".format(datetime.now().strftime("%m/%d/%Y %H:%M.%S")), "[ERROR]", event, PrintColors.END)


    def store(event:str, details:dict = {}):
        """
        Stores a log in the database, these logs are not meant
        to be easily filtered by humans and are there just in case
        something goes bad and someone needs to review them.
        """

        def run():
            db.cur.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (None, int(time.time()), event, json.dumps(details),))
            db.con.commit()
        
        # Thread the main runner so it doesn't hold up the main process
        Thread(target = run).start()


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
