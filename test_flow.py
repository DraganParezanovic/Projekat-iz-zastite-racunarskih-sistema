"""
test_flow.py — end-to-end provera web toka preko Flask test klijenta.
Pokretanje:  python test_flow.py
"""
import os, tempfile
os.environ["DATABASE"] = tempfile.mktemp(suffix=".db")

import pyotp
from app import app
import models

app.config["TESTING"] = True
client = app.test_client()

print("1) Registracija...")
r = client.post("/register", data={
    "username": "ana", "email": "ana@test.rs",
    "password": "Lozinka12345"
}, follow_redirects=True)
assert r.status_code == 200
user = models.get_user_by_username("ana")
assert user is not None
print("   korisnik kreiran, preusmeren na TOTP setup")

print("2) Aktivacija TOTP-a (potvrda kodom)...")
secret = user["totp_secret"]
code = pyotp.TOTP(secret).now()
r = client.post("/mfa/setup", data={"code": code}, follow_redirects=True)
assert r.status_code == 200
user = models.get_user_by_username("ana")
assert user["totp_enabled"] == 1
print("   TOTP aktiviran")

print("3) Prijava lozinkom (korak 1)...")
r = client.post("/login", data={"username": "ana", "password": "Lozinka12345"},
                follow_redirects=True)
body = r.get_data(as_text=True)
assert "Korak 2" in body or "Verifikacija" in body
print("   lozinka prihvaćena, traži se TOTP kod")

print("4) Pokušaj sa POGREŠNIM TOTP kodom...")
r = client.post("/mfa/verify", data={"code": "000000"}, follow_redirects=True)
assert "Pogrešan kod" in r.get_data(as_text=True)
with client.session_transaction() as sess:
    assert sess.get("user_id") is None   # i dalje NIJE prijavljen
print("   odbijen — pristup i dalje zaključan")

print("5) Verifikacija ISPRAVNIM TOTP kodom...")
code = pyotp.TOTP(secret).now()
r = client.post("/mfa/verify", data={"code": code}, follow_redirects=True)
assert "Dobrodošli" in r.get_data(as_text=True)
with client.session_transaction() as sess:
    assert sess.get("user_id") == user["id"]   # SADA je prijavljen
print("   uspešna prijava — pristup dashboard-u odobren")

print("\nSVI E2E TESTOVI PROŠLI ✓")
os.remove(os.environ["DATABASE"])
