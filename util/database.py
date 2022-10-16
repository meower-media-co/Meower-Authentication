from util.supporter import log
from pymongo import MongoClient
from redis import Redis
import sqlite3
import os
import time


class Database:
    def __init__(self):
        # Initialize Mongo database connection
        try:
            mongo_client = MongoClient(
                os.getenv("MONGODB_URI", "mongodb://localhost:27017"), 
                serverSelectionTimeoutMS = int(os.getenv("MONGODB_TIMEOUT", 30))
            )
            self.mongo = mongo_client[os.getenv("MONGODB_NAME", "meowerserver")]
            self.mongo.command("ping")
            log.success("MongoDB Connected!")
        except Exception as err:
            log.error(f"MongoDB failed to connect: {str(err)}")
            exit()

        # Initialize Redis database connection
        try:
            self.redis = Redis(
                host = os.getenv("REDIS_HOST", "localhost"),
                port = int(os.getenv("REDIS_PORT", 6379)),
                username = os.getenv("REDIS_USERNAME", None),
                password = os.getenv("REDIS_PASSWORD", None),
                db = int(os.getenv("REDIS_DB", 0))
            )
            log.success("Redis Connected!")
        except Exception as error:
            log.error(f"Redis failed to connect: {str(err)}")
            exit()

        # Initialize SQLite persistent database connection
        try:
            self.con = sqlite3.connect(os.environ.get("DB", "meowerauth.db"))
            self.cur = self.con.cursor()
            log.success("SQLite Connected!")
        except Exception as err:
            log.error(f"SQLite failed to connect: {str(err)}")
            exit()

        # Initialize SQLite in-memory database connection
        try:
            self.mem = sqlite3.connect("file::memory:?cache=shared").cursor()
            log.success("Memory DB Connected!")
        except Exception as err:
            log.error(f"Memory DB failed to connect: {str(err)}")
            exit()


    def _setup_mongo(self):
        # Create users collection
        if "users" not in self.mongo.list_collection_names():
            for index_name in [
                "_id",
                "lower_username"
            ]:
                self.mongo.users.create_index(index_name)
        
        # Create sessions collection
        if "sessions" not in self.mongo.list_collection_names():
            for index_name in [
                "_id"
            ]:
                self.mongo.sessions.create_index(index_name)


    def _setup_sqlite(self):
        # Attempt to create the accounts table
        try:
            self.cur.execute("""
                CREATE TABLE accounts (
                    id TEXT NOT NULL UNIQUE PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT UNIQUE,
                    password TEXT,
                    webauthn TEXT NOT NULL,
                    totp_secret TEXT NOT NULL,
                    mfa_recovery TEXT NOT NULL,
                    lock_status INTEGER NOT NULL
                )
            """)
            self.cur.execute("""
                CREATE INDEX account_id ON accounts (
                    id
                )
            """)
            self.cur.execute("""
                CREATE INDEX account_username ON accounts (
                    username
                )
            """)
            self.cur.execute("""
                CREATE INDEX account_email ON accounts (
                    email
                )
            """)
            log.success("Created 'accounts' table")
        except Exception as err:
            log.error(f"Error making 'accounts' table: {str(err)}")

        # Attempt to create the sessions table
        try:
            self.cur.execute("""
                CREATE TABLE sessions (
                    id TEXT NOT NULL UNIQUE PRIMARY KEY,
                    auth_hash TEXT NOT NULL UNIQUE,
                    main_hash TEXT NOT NULL UNIQUE,
                    user TEXT NOT NULL,
                    client TEXT NOT NULL,
                    refreshed REAL NOT NULL,
                    expires REAL NOT NULL
                )
            """)
            self.cur.execute("""
                CREATE INDEX session_id ON sessions (
                    id
                )
            """)
            self.cur.execute("""
                CREATE INDEX session_token ON sessions (
                    token
                )
            """)
            self.cur.execute("""
                CREATE INDEX session_user ON sessions (
                    user
                )
            """)
            log.success("Created 'sessions' table")
        except Exception as err:
            log.error(f"Error making 'sessions' table: {str(err)}")

        # Attempt to create the email links table
        try:
            self.cur.execute("""
                CREATE TABLE email_links (
                    id TEXT NOT NULL UNIQUE PRIMARY KEY,
                    user TEXT NOT NULL,
                    email TEXT NOT NULL,
                    action TEXT NOT NULL,
                    expires INTEGER NOT NULL
                )
            """)
            self.cur.execute("""
                CREATE INDEX email_link_id ON email_links (
                    id
                )
            """)
            log.success("Created 'email_links' table")
        except Exception as err:
            log.error(f"Error making 'email_links' table: {str(err)}")

        # Attempt to create the logs table
        try:
            self.cur.execute("""
                CREATE TABLE logs (
                    id TEXT NOT NULL UNIQUE PRIMARY KEY,
                    timestamp INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    user TEXT,
                    email TEXT,
                    ip TEXT
                )
            """)
            log.success("Created 'logs' table")
        except Exception as err:
            log.error(f"Error making 'logs' table: {str(err)}")

        # Attempt to create the ratelimits table
        try:
            db.mem.execute("""
                CREATE TABLE ratelimits (
                    id TEXT NOT NULL PRIMARY KEY,
                    remaining INTEGER NOT NULL,
                    reset REAL NOT NULL
                )
            """)
            log.success("Created 'ratelimits' table")
        except Exception as err:
            log.error(f"Error making 'ratelimits' table: {str(err)}")
            exit()
        
        # Attempt to create the mfa table (in-memory)
        try:
            db.mem.execute("""
                CREATE TABLE mfa (
                    id TEXT NOT NULL PRIMARY KEY,
                    user TEXT NOT NULL,
                    expires REAL NOT NULL
                )
            """)
            log.success("Created 'mfa' table")
        except Exception as err:
            log.error(f"Error making 'mfa' table: {str(err)}")
            exit()
    

    def background_cleanup(db):
        while True:
            time.sleep(60)

            db.mem.execute("DELETE FROM ratelimits WHERE reset <= ?", (time.time(),))
            db.mem.execute("DELETE FROM mfa WHERE expires <= ?", (time.time(),))

            users_to_purge = db.cur.execute("SELECT id FROM pending_deletion WHERE after <= ?", (time.time(),)).fetchall()
            for row in users_to_purge:
                userid = row[0]
                db.mongo.users.update_one({"_id": userid}, {"$set": {
                    "username": f"Deleted-{userid}",
                    "username_lower": f"deleted-{userid}",
                    "flags": 0,
                    "admin": 0,
                    "config": 0,
                    "custom_theme": {},
                    "quote": ""
                }}, {"writeConcern": {"w": "majority", "wtimeout": 5000}})
                db.cur.execute("DELETE FROM accounts WHERE id = ?", (userid,))
                db.con.commit()


db = Database()
