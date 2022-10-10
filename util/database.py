from pymongo import MongoClient
from redis import Redis
import sqlite3
import os

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
        except:
            print("Failed to connect to the MongoDB server.")
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
        except Exception as error:
            print(f"Failed to connect to the Redis server\n{str(error)}")
            exit()

        # Initialize SQLite persistent database connection
        try:
            self.con = sqlite3.connect(os.environ.get("DB", "meowerauth.db"))
            self.cur = self.con.cursor()
        except:
            print("Failed to connect to the persistent SQLite database.")
            exit()

        # Initialize SQLite in-memory database connection
        try:
            self.mem = sqlite3.connect("file::memory:?cache=shared").cursor()
        except:
            print("Failed to connect to the in-memory SQLite database.")
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
                "_id",
                "token"
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
                    mfa_recovery TEXT NOT NULL
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
            self.con.commit()
            print("Created 'accounts' table!")
        except:
            pass

        # Attempt to create the sessions table
        try:
            self.cur.execute("""
                CREATE TABLE sessions (
                    id TEXT NOT NULL UNIQUE PRIMARY KEY,
                    token TEXT NOT NULL UNIQUE,
                    user TEXT NOT NULL,
                    client TEXT NOT NULL,
                    created INTEGER NOT NULL,
                    ttl INTEGER NOT NULL
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
            self.con.commit()
            print("Created 'sessions' table!")
        except:
            pass

        # Attempt to create the email links table
        try:
            self.cur.execute("""
                CREATE TABLE email_links (
                    id TEXT NOT NULL UNIQUE PRIMARY KEY,
                    token TEXT NOT NULL UNIQUE,
                    expires INTEGER NOT NULL,
                    revoked INTEGER NOT NULL,
                    user TEXT NOT NULL,
                    email TEXT NOT NULL,
                    action TEXT NOT NULL
                )
            """)
            self.cur.execute("""
                CREATE INDEX email_token ON email_links (
                    token
                )
            """)
            self.con.commit()
            print("Created 'email_links' table!")
        except:
            pass
        
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
            self.cur.execute("""
                CREATE INDEX logs_action ON logs (
                    action
                )
            """)
            self.cur.execute("""
                CREATE INDEX logs_user ON logs (
                    user
                )
            """)
            self.cur.execute("""
                CREATE INDEX logs_email ON logs (
                    email
                )
            """)
            self.cur.execute("""
                CREATE INDEX logs_ip ON logs (
                    ip
                )
            """)
            self.con.commit()
            print("Created 'logs' table!")
        except:
            pass

db = Database()