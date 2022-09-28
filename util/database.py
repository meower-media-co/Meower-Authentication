import sqlite3
import os

class Database:
    def __init__(self, file: str):
        # Initialize database connection
        self.con = sqlite3.connect(file)
        self.cur = self.con.cursor()

        # Attempt to create the accounts table
        try:
            self.cur.execute("""
                    CREATE TABLE accounts (
                        id TEXT NOT NULL UNIQUE PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        display_name TEXT NOT NULL UNIQUE,
                        email TEXT UNIQUE,
                        password TEXT,
                        prev_pswds TEXT,
                        webauthn TEXT,
                        totp TEXT,
                        locked INTEGER NOT NULL
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
                        version INTEGER NOT NULL,
                        user TEXT NOT NULL,
                        client TEXT NOT NULL,
                        user_agent TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        impersonating INTEGER NOT NULL,
                        revoked INTEGER NOT NULL
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX session_id ON sessions (
                        id
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX session_user ON sessions (
                        user
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX session_client ON sessions (
                        client
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

        # Attempt to create the OAuth2 clients table
        try:
            self.cur.execute("""
                    CREATE TABLE oauth2_clients (
                        id TEXT NOT NULL UNIQUE PRIMARY KEY,
                        created INTEGER NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT,
                        icon TEXT,
                        owner TEXT NOT NULL,
                        secret TEXT NOT NULL,
                        allowed_redirects TEXT NOT NULL,
                        first_party INTEGER NOT NULL
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX oauth2_clients_id ON oauth2_clients (
                        id
                    )
                """)
            self.con.commit()
            print("Created 'oauth2_clients' table!")
        except:
            pass

        # Attempt to create the OAuth2 sessions table
        try:
            self.cur.execute("""
                    CREATE TABLE oauth2_sessions (
                        id TEXT NOT NULL UNIQUE PRIMARY KEY,
                        version INTEGER NOT NULL,
                        user TEXT NOT NULL,
                        client TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        revoked INTEGER NOT NULL
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX oauth2_session_id ON oauth2_sessions (
                        id
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX oauth2_session_user ON oauth2_sessions (
                        user
                    )
                """)
            self.cur.execute("""
                    CREATE INDEX oauth2_session_client ON oauth2_sessions (
                        client
                    )
                """)
            self.con.commit()
            print("Created 'oauth2_sessions' table!")
        except:
            pass

db = Database(os.environ.get("DB", "meowerauth.db"))