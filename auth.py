"""
auth.py
-------
Jezgro autentifikacije. Sadrži svu kriptografsku i bezbednosnu logiku,
odvojenu od web sloja (app.py) radi preglednosti i ponovne upotrebe.

Implementirane metode (samo dva faktora):
  1) Lozinka      -> faktor "nešto što znaš"
  2) TOTP (app)   -> faktor "nešto što imaš" (RFC 6238, npr. Google Authenticator)
"""

import io
import base64

import pyotp
import qrcode

from config import Config
import models


# ===========================================================================
# 1) LOZINKE — heširanje i provera
# ===========================================================================
# Koristimo PBKDF2-HMAC-SHA256 (preko Werkzeug-a). To je spor (namerno) algoritam
# sa "salt"-om, što napad rečnikom/grubom silom čini neisplativim. Lozinka se
# nikada ne čuva u čistom tekstu.
from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password: str) -> str:
    # method="pbkdf2:sha256" + automatski nasumičan salt po korisniku
    return generate_password_hash(password, method="pbkdf2:sha256")


def verify_password(password_hash: str, password: str) -> bool:
    # Werkzeug interno koristi poređenje otporno na timing napade.
    return check_password_hash(password_hash, password)


# ===========================================================================
# 2) TOTP — Time-based One-Time Password (RFC 6238)
# ===========================================================================
# TOTP generiše 6-cifreni kod na osnovu DELJENE TAJNE i TRENUTNOG VREMENA.
# Server i aplikacija (Google Authenticator/Authy) dele istu tajnu i nezavisno
# računaju isti kod svakih 30 sekundi pomoću HMAC-SHA1. Kod se NIKADA ne prenosi
# mrežom pri prijavi — server ga samostalno izračuna i uporedi sa unetim.

def generate_totp_secret() -> str:
    """Generiše nasumičnu Base32 tajnu (deli se sa authenticator aplikacijom)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, account_name: str) -> str:
    """
    Vraća 'otpauth://' URI koji authenticator aplikacija prepoznaje.
    Ovaj URI se kodira u QR kod koji korisnik skenira.
    """
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_name, issuer_name=Config.TOTP_ISSUER
    )


def get_totp_qr_base64(secret: str, account_name: str) -> str:
    """
    Pravi QR kod od TOTP URI-ja i vraća ga kao base64 PNG (za <img> u HTML-u),
    tako da ne moramo da čuvamo slike na disku.
    """
    uri = get_totp_uri(secret, account_name)
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def verify_totp(secret: str, code: str) -> bool:
    """
    Proverava da li uneti kod odgovara tajni za trenutni vremenski interval.
    valid_window=1 dozvoljava +/- jedan interval (30s) zbog moguće razlike u satovima.
    """
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=Config.TOTP_VALID_WINDOW)


# ===========================================================================
# ZAŠTITA OD NAPADA GRUBOM SILOM (brute force / lockout)
# ===========================================================================
# 6-cifreni TOTP kod ima samo milion kombinacija. Bez ograničenja broja pokušaja,
# napadač bi imao realnu šansu da ga pogodi. Zato evidentiramo neuspele pokušaje
# i privremeno zaključavamo nalog.

def is_locked_out(username: str) -> bool:
    """True ako je nalog privremeno zaključan zbog previše neuspešnih pokušaja."""
    failures = models.count_recent_failures(username, Config.LOCKOUT_SECONDS)
    return failures >= Config.MAX_FAILED_ATTEMPTS
