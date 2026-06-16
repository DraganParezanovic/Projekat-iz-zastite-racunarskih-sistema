"""
models.py
---------
Sloj za rad sa bazom podataka (SQLite). Ovde se nalaze:
  - inicijalizacija šeme baze (tabele),
  - pomoćne funkcije za rad sa korisnicima i evidencijom pokušaja prijave.

Koristimo standardnu Python biblioteku `sqlite3` (bez dodatnih ORM zavisnosti)
kako bi bilo potpuno transparentno ŠTA se i KAKO čuva u bazi — što je važno
za bezbednosnu analizu.
"""

import sqlite3
import time
from contextlib import contextmanager
from config import Config


@contextmanager
def get_db():
    """
    Kontekst-menadžer koji otvara konekciju ka bazi, vraća redove kao rečnike
    (sqlite3.Row) i garantuje da se konekcija uredno zatvori.
    """
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row          # pristup kolonama po imenu: row["username"]
    conn.execute("PRAGMA foreign_keys = ON")  # uključi referencijalni integritet
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Kreira tabele ako ne postoje. Poziva se pri startu aplikacije."""
    with get_db() as conn:
        conn.executescript(
            """
            -- Korisnici. Lozinka se NIKADA ne čuva u čistom tekstu, samo heš.
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                email         TEXT NOT NULL,             -- koristi se kao oznaka naloga u authenticator aplikaciji
                password_hash TEXT NOT NULL,
                totp_secret   TEXT,                       -- deljena tajna za TOTP (Base32)
                totp_enabled  INTEGER NOT NULL DEFAULT 0, -- da li je korisnik aktivirao TOTP
                created_at    INTEGER NOT NULL
            );

            -- Evidencija pokušaja prijave (za detekciju napada grubom silom).
            CREATE TABLE IF NOT EXISTS login_attempts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT NOT NULL,
                success   INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            );
            """
        )


# ---------------------------------------------------------------------------
# KORISNICI
# ---------------------------------------------------------------------------

def create_user(username, email, password_hash):
    """Upisuje novog korisnika i vraća njegov ID."""
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, email, password_hash, int(time.time())),
        )
        return cur.lastrowid


def get_user_by_username(username):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row


def get_user_by_id(user_id):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return row


def set_totp_secret(user_id, secret):
    """Pamti TOTP tajnu (još nije aktivirana dok korisnik ne potvrdi prvi kod)."""
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id)
        )


def enable_totp(user_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET totp_enabled = 1 WHERE id = ?", (user_id,)
        )


# ---------------------------------------------------------------------------
# POKUŠAJI PRIJAVE (zaštita od brute force napada)
# ---------------------------------------------------------------------------

def record_attempt(username, success):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, success, timestamp) VALUES (?, ?, ?)",
            (username, 1 if success else 0, int(time.time())),
        )


def count_recent_failures(username, window_seconds):
    """Broji neuspešne pokušaje za korisnika unutar zadatog vremenskog prozora."""
    since = int(time.time()) - window_seconds
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM login_attempts "
            "WHERE username = ? AND success = 0 AND timestamp > ?",
            (username, since),
        ).fetchone()
        return row["c"]


def clear_failures(username):
    """Briše neuspešne pokušaje (poziva se nakon uspešne prijave)."""
    with get_db() as conn:
        conn.execute(
            "DELETE FROM login_attempts WHERE username = ? AND success = 0",
            (username,),
        )
