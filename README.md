# MFA Demo — Multifaktorska autentifikacija (TOTP)

Demonstracioni projekat za predmet **Zaštita računarskih sistema**.
Implementira prijavu u dva koraka sa dva nezavisna faktora:

- **Lozinka** (nešto što znaš)
- **TOTP** preko authenticator aplikacije — RFC 6238 (nešto što imaš)

Dodatno je ugrađena zaštita od napada grubom silom (privremeno zaključavanje
naloga posle više neuspešnih pokušaja).

## Pokretanje (3 koraka)

```bash
# 1. Napravi i aktiviraj virtuelno okruženje
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Instaliraj zavisnosti
pip install -r requirements.txt

# 3. Pokreni aplikaciju
python app.py
```

Otvori u pregledaču: **http://127.0.0.1:5000**

## Kako testirati

1. **Registruj se** (`/register`) — unesi korisničko ime, email i lozinku.
2. **Podesi TOTP** — skeniraj QR kod aplikacijom Google Authenticator/Authy i unesi kod.
3. **Prijavi se** — unesi lozinku (korak 1), pa 6-cifreni kod iz aplikacije (korak 2).
4. Za demonstraciju zaštite, unesi pogrešan kod 5 puta i vidi zaključavanje naloga.

Automatski testovi:

```bash
python test_core.py     # jezgro: lozinka, TOTP, lockout, QR
python test_flow.py     # ceo web tok prijave
```

## Struktura

```
mfa_app/
├── app.py              # Flask rute i tok prijave
├── auth.py             # Jezgro: TOTP, heširanje lozinke, lockout
├── models.py           # Sloj baze (SQLite)
├── config.py           # Konfiguracija
├── requirements.txt    # Zavisnosti
├── templates/          # HTML šabloni
└── static/             # CSS
```
