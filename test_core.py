"""
test_core.py — brza provera jezgra logike (ne menja produkcionu bazu).
Pokretanje:  python test_core.py
"""
import os, tempfile

# Koristi privremenu bazu da ne diramo mfa.db
os.environ["DATABASE"] = tempfile.mktemp(suffix=".db")

import models, auth
models.init_db()

print("=" * 55)
print("TEST 1: Heširanje lozinke")
h = auth.hash_password("TajnaLozinka123")
assert h != "TajnaLozinka123", "Lozinka mora biti heširana!"
assert auth.verify_password(h, "TajnaLozinka123") is True
assert auth.verify_password(h, "pogresna") is False
print("  OK — ispravna lozinka prolazi, pogrešna ne; heš != čist tekst")

print("=" * 55)
print("TEST 2: TOTP (RFC 6238)")
secret = auth.generate_totp_secret()
import pyotp
current = pyotp.TOTP(secret).now()         # kod kakav bi aplikacija prikazala
assert auth.verify_totp(secret, current) is True
assert auth.verify_totp(secret, "000000") is False
print(f"  OK — tajna={secret[:6]}..., trenutni kod={current} prihvaćen, lažni odbijen")

print("=" * 55)
print("TEST 3: Generisanje QR koda")
qr = auth.get_totp_qr_base64(secret, "pera@test.rs")
assert qr.startswith("data:image/png;base64,")
print(f"  OK — QR kod generisan ({len(qr)} bajtova base64)")

print("=" * 55)
print("TEST 4: Zaštita od grube sile (lockout)")
for i in range(5):
    models.record_attempt("meta", success=False)
assert auth.is_locked_out("meta") is True
assert auth.is_locked_out("neko_drugi") is False
print("  OK — nalog zaključan posle 5 neuspeha")

print("=" * 55)
print("SVI TESTOVI PROŠLI ✓")
os.remove(os.environ["DATABASE"])
