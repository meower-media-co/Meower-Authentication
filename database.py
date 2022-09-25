import sqlite3
import os

class Database:
    def __init__(self, file:str):
        # Initialize database connection
        self.con = sqlite3.connect(file)
        self.cur = self.con.cursor()

        # Attempt to create the accounts table
        try:
            self.cur.execute("""
                    CREATE TABLE 'accounts' (
                        'id' TEXT NOT NULL UNIQUE,
                        'email' TEXT UNIQUE,
                        'password' TEXT,
                        'prev_pswds' TEXT,
                        'webauthn' TEXT,
                        'totp' TEXT,
                        'locked' INTEGER NOT NULL,
                        PRIMARY KEY('id')
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX 'account_id' ON 'accounts' (
                        'id'
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX 'account_email' ON 'accounts' (
                        'email'
                    )
                """)
            self.con.commit()
            print("Created 'accounts' table!")
        except:
            pass

        # Attempt to create the sessions table
        try:
            self.cur.execute("""
                    CREATE TABLE 'sessions' (
                        'id' INTEGER NOT NULL UNIQUE,
                        'version' INTEGER NOT NULL,
                        'user' TEXT NOT NULL,
                        'ip' TEXT NOT NULL,
                        'user_agent' TEXT NOT NULL,
                        'impersonating' INTEGER NOT NULL,
                        'revoked' INTEGER NOT NULL,
                        PRIMARY KEY('id' AUTOINCREMENT)
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX 'session_id' ON 'sessions' (
                        'id'
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX 'session_user' ON 'sessions' (
                        'user'
                    )
                """)
            self.con.commit()
            print("Created 'sessions' table!")
        except:
            pass

        # Attempt to create the email links table
        try:
            self.cur.execute("""
                    CREATE TABLE 'email_links' (
                        'id' INTEGER NOT NULL UNIQUE,
                        'token' TEXT NOT NULL UNIQUE,
                        'expires' INTEGER NOT NULL,
                        'revoked' INTEGER NOT NULL,
                        'user' TEXT NOT NULL,
                        'email' TEXT NOT NULL,
                        'action' TEXT NOT NULL,
                        PRIMARY KEY('id' AUTOINCREMENT)
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX 'email_token' ON 'email_links' (
                        'token'
                    )
                """)
            self.con.commit()
            print("Created 'email_links' table!")
        except:
            pass

db = Database(os.environ.get("DB", "meowerauth.db"))