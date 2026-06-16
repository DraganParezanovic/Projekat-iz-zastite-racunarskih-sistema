"""
config.py
---------
Centralna konfiguracija aplikacije. Sve podesive vrednosti su na jednom mestu.

VAZNO: U produkciji SECRET_KEY NIKADA ne sme biti u kodu — mora se učitavati
iz promenljive okruženja (environment variable).
"""

import os


class Config:
    # --- Sesija / kriptografski potpis kolačića ---
    # Ako postoji promenljiva okruženja koristi nju, u suprotnom nasumičnu vrednost.
    # os.urandom(24) generiše kriptografski jaku tajnu za potpisivanje sesije.
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())

    # --- Baza podataka ---
    DATABASE = os.environ.get("DATABASE", "mfa.db")

    # --- Bezbednosna podešavanja kolačića sesije ---
    SESSION_COOKIE_HTTPONLY = True      # JavaScript ne može da čita kolačić (zaštita od XSS krađe sesije)
    SESSION_COOKIE_SAMESITE = "Lax"     # Osnovna zaštita od CSRF napada
    # U produkciji preko HTTPS-a obavezno: SESSION_COOKIE_SECURE = True

    # --- TOTP (Time-based One-Time Password) parametri ---
    TOTP_ISSUER = "MFA Demo - Zastita RS"   # Ime koje se prikazuje u authenticator aplikaciji
    TOTP_VALID_WINDOW = 1                    # Tolerancija +/- 1 interval (30s) zbog razlike u satovima

    # --- Zaštita od napada grubom silom (brute force) ---
    MAX_FAILED_ATTEMPTS = 5         # Broj dozvoljenih neuspešnih pokušaja
    LOCKOUT_SECONDS = 300           # Trajanje zaključavanja naloga (5 minuta)
