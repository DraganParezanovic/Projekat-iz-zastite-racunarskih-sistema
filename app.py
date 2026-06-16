"""
app.py
------
Web sloj (Flask). Definiše rute i upravlja TOKOM PRIJAVE u dva koraka:

    [1] korisnik unese username + lozinku
         |
         v  (lozinka ispravna, ali nalog ima MFA)
    [PRELAZNO STANJE: 'pending_user_id' u sesiji — korisnik JOŠ NIJE prijavljen]
         |
         v  korisnik unese TOTP kod iz aplikacije (Google Authenticator)
    [2] kod ispravan -> puna prijava ('user_id' u sesiji)

Ovaj dvostepeni tok je suština MFA: ni lozinka ni TOTP kod sami po sebi
ne daju pristup — potrebna su oba.
"""

from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash,
)

from config import Config
import models
import auth

app = Flask(__name__)
app.config.from_object(Config)

# Inicijalizuj bazu pri pokretanju.
with app.app_context():
    models.init_db()


# ---------------------------------------------------------------------------
# POMOĆNI DEKORATORI
# ---------------------------------------------------------------------------

def login_required(view):
    """Dozvoljava pristup samo POTPUNO prijavljenim korisnicima (oba faktora)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Morate biti prijavljeni.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_pending_user():
    """Vraća korisnika koji je prošao 1. korak (lozinku) ali ne i 2. (TOTP)."""
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return None
    return models.get_user_by_id(pending_id)


# ---------------------------------------------------------------------------
# POČETNA / DASHBOARD
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = models.get_user_by_id(session["user_id"])
    return render_template("dashboard.html", user=user)


# ---------------------------------------------------------------------------
# REGISTRACIJA
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Osnovna validacija ulaza.
        if not username or not email or not password:
            flash("Korisničko ime, email i lozinka su obavezni.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Lozinka mora imati najmanje 8 karaktera.", "error")
            return render_template("register.html")
        if models.get_user_by_username(username):
            flash("Korisničko ime je zauzeto.", "error")
            return render_template("register.html")

        # Lozinka se odmah hešuje — čist tekst ne napušta ovu funkciju.
        pw_hash = auth.hash_password(password)
        user_id = models.create_user(username, email, pw_hash)

        # Posle registracije vodimo korisnika na podešavanje TOTP-a (2. faktor).
        session["pending_user_id"] = user_id
        flash("Nalog je kreiran. Podesite drugi faktor (TOTP).", "success")
        return redirect(url_for("mfa_setup"))

    return render_template("register.html")


# ---------------------------------------------------------------------------
# PODEŠAVANJE TOTP-a (skeniranje QR koda + potvrda)
# ---------------------------------------------------------------------------

@app.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    # Korisnik mora biti bar u prelaznom stanju (upravo registrovan) ili prijavljen.
    user = get_pending_user() or (
        models.get_user_by_id(session["user_id"]) if session.get("user_id") else None
    )
    if not user:
        return redirect(url_for("login"))

    # Generiši tajnu jednom i zapamti je dok korisnik ne potvrdi prvi kod.
    if not user["totp_secret"]:
        secret = auth.generate_totp_secret()
        models.set_totp_secret(user["id"], secret)
        user = models.get_user_by_id(user["id"])  # osveži podatke

    secret = user["totp_secret"]
    qr = auth.get_totp_qr_base64(secret, account_name=user["email"])

    if request.method == "POST":
        code = request.form.get("code", "")
        if auth.verify_totp(secret, code):
            models.enable_totp(user["id"])
            # TOTP je aktiviran. Korisnik se sada prijavljuje normalno (oba faktora).
            session.pop("pending_user_id", None)
            flash("TOTP je uspešno aktiviran! Prijavite se.", "success")
            return redirect(url_for("login"))
        flash("Pogrešan kod. Pokušajte ponovo.", "error")

    return render_template("mfa_setup.html", secret=secret, qr=qr)


# ---------------------------------------------------------------------------
# PRIJAVA — KORAK 1: lozinka
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Zaštita od grube sile: zaključavanje posle previše neuspeha.
        if auth.is_locked_out(username):
            flash("Previše neuspešnih pokušaja. Pokušajte kasnije.", "error")
            return render_template("login.html")

        user = models.get_user_by_username(username)

        # Namerno ista poruka za pogrešno ime i pogrešnu lozinku
        # (da se ne otkriva da li korisnik postoji — user enumeration zaštita).
        if not user or not auth.verify_password(user["password_hash"], password):
            models.record_attempt(username, success=False)
            flash("Pogrešno korisničko ime ili lozinka.", "error")
            return render_template("login.html")

        # Lozinka ispravna. Ako korisnik nema aktiviran TOTP, pošalji ga da ga podesi.
        if not user["totp_enabled"]:
            session["pending_user_id"] = user["id"]
            return redirect(url_for("mfa_setup"))

        # PRELAZ u drugi korak: korisnik JOŠ NIJE prijavljen.
        session["pending_user_id"] = user["id"]
        session.pop("user_id", None)
        return redirect(url_for("mfa_verify"))

    return render_template("login.html")


# ---------------------------------------------------------------------------
# PRIJAVA — KORAK 2: drugi faktor (TOTP)
# ---------------------------------------------------------------------------

@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    user = get_pending_user()
    if not user:
        flash("Sesija je istekla. Prijavite se ponovo.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        ok = auth.verify_totp(user["totp_secret"], code)

        if ok:
            # USPEH: prevedi prelazno stanje u punu prijavu.
            models.record_attempt(user["username"], success=True)
            models.clear_failures(user["username"])
            session.pop("pending_user_id", None)
            session["user_id"] = user["id"]
            flash("Uspešno ste prijavljeni!", "success")
            return redirect(url_for("dashboard"))
        else:
            models.record_attempt(user["username"], success=False)
            # I drugi korak podleže zaključavanju (sprečava brute force TOTP koda).
            if auth.is_locked_out(user["username"]):
                session.pop("pending_user_id", None)
                flash("Previše neuspešnih pokušaja. Prijavite se ponovo kasnije.", "error")
                return redirect(url_for("login"))
            flash("Pogrešan kod.", "error")

    return render_template("mfa_verify.html", user=user)


# ---------------------------------------------------------------------------
# ODJAVA
# ---------------------------------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    flash("Odjavljeni ste.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    # debug=True samo za razvoj; u produkciji koristiti WSGI server (npr. gunicorn).
    app.run(debug=True, port=5000)
