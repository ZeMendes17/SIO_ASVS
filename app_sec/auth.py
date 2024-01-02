from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    current_app,
)
from flask_login import login_user, logout_user, login_required, current_user
from .models import Cart, User, Wishlist
from sqlalchemy import text
from . import db
from werkzeug.security import check_password_hash
import requests
import pyotp
from . import encryption as E
import uuid
import logging
import time
from datetime import datetime, timedelta

auth = Blueprint("auth", __name__)

# Initialize a TOTP object
totp = pyotp.TOTP(pyotp.random_base32())

logger = logging.getLogger(__name__)


@auth.route("/login", methods=["GET", "POST"])
def login():
    try:
        if current_user.is_authenticated:
            current_user.last_activity_time = time.time()
            db.session.commit()
            return redirect(url_for("main.index"))
        else:
            if request.method == "POST":
                username = request.form["username"]
                verification_code = request.form["otp"]

                user = User.query.filter_by(username=username).first()

                if user.verification_code == verification_code:
                    if (
                        user.verification_timestamp
                        and (int(time.time()) - user.verification_timestamp) < 600
                    ):
                        login_user(user)
                        return redirect(url_for("main.index"))
                else:
                    flash("Invalid Verification Code", category="danger")
                    return redirect(url_for("auth.login"))
            else:
                return render_template("login.html")
    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@auth.route("/form_login", methods=["POST"])
def form_login():
    try:
        username = request.form["username"]
        key = request.form["password"]
        recaptcha_response = request.form["g-recaptcha-response"]

        recaptcha_request = requests.post(
            "https://recaptchaenterprise.googleapis.com/v1/projects/deti-store-1703363018508/assessments?key=AIzaSyDHxOKFmFzw4ijJ-pUmTDRLFLvrnJtOxzw",
            json={
                "event": {
                    "token": recaptcha_response,
                    "expectedAction": "register",
                    "siteKey": "6LeFQDkpAAAAABKdp4pinNyxhov9pQeL493lwh1_",
                }
            },
            headers={"Content-Type": "application/json"},
        ).json()

        if not recaptcha_request["tokenProperties"]["valid"]:
            flash("Recaptcha inválido!", category="danger")
            return redirect(url_for("auth.login"))

        user = User.query.filter_by(username=username).first()

        # Check username and password
        if not user or not check_password_hash(user.password, key):
            flash("Invalid username or password.", category="danger")
            return redirect(url_for("auth.login"))

        # get the user's email key
        email_key = E.get_key(f"{username.upper()}_EMAIL_KEY")
        # decrypt the user's email
        email = E.chacha20_decrypt(user.email, email_key)
        if email is None:
            flash("Erro ao obter email do utilizar!", category="danger")
            return redirect(url_for("auth.login"))

        # Assuming generate_verification_code is a function to generate a unique code
        verification_code = totp.now()

        try:
            # Save the verification code and timestamp in the database
            user.verification_code = verification_code
            user.verification_timestamp = int(time.time())
            db.session.commit()
            # Send the verification code via email
            send_otp_via_email(verification_code, email)
            return render_template("enter_otp.html", username=username)
        except Exception as e:
            flash("Erro ao guardar código de verificação!", category="danger")
            return redirect(url_for("auth.login"))

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@auth.route("/logout", methods=["GET"])
@login_required
def logout():
    try:
        logout_user()
        return redirect(url_for("main.index"))
    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


def send_otp_via_email(otp_code, email):
    try:
        email_server = current_app.config["EMAIL_SERVER"]

        subject = "Verification Code"
        body = f"Your verification code is: {otp_code}"

        message = f"From: detiStore@outlook.com\r\nTo: {email}\r\nSubject: {subject}\r\n\r\n{body}"

        # Sending email
        email_server.sendmail("detiStore@outlook.com", [email], message)
    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@auth.route("/login_google")
def login_google():
    try:
        google = current_app.config["oauth"].create_client("google")
        redirect_uri = url_for("auth.authorize_google", _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@auth.route("/authorize_google")
def authorize_google():
    try:
        google = current_app.config["oauth"].create_client("google")
        token = google.authorize_access_token()
        user_info = google.get("https://www.googleapis.com/oauth2/v3/userinfo").json()

        email = user_info["email"]
        username = email.split("@")[0]
        picture = user_info["picture"]
        name = user_info["name"]

        user = User.query.filter_by(email=email).first()
        # Check if user exists with that email

        # All users
        users = User.query.all()

        # Check if the email already exists
        for u in users:
            # get the user's email key
            email_key = E.get_key(f"{u.username.upper()}_EMAIL_KEY")
            # decrypt the user's email
            u_email = E.chacha20_decrypt(u.email, email_key)
            if email == u_email:
                flash("Email já existe!", category="danger")
                return redirect(url_for("auth.login"))

        # create a new user
        key = E.generate_key()
        # store the key
        E.store_key(key, f"{username.upper()}_EMAIL_KEY")
        # encrypt the email
        email = E.chacha20_encrypt(email, key)
        if email is None:
            flash("Erro ao encriptar email do utilizador!", category="danger")
            return redirect(url_for("auth.login"))
        new_user = User(
            username=username,
            email=email,
            image=picture,
            name=name,
            google_account=True,
        )

        try:
            db.session.add(new_user)
            db.session.commit()

            new_cart = Cart(customer_id=new_user.id)
            db.session.add(new_cart)
            db.session.commit()

            new_wishlist = Wishlist(customer_id=new_user.id)
            db.session.add(new_wishlist)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for("main.index"))
        except Exception as e:
            db.session.rollback()
            flash("Erro ao criar utilizador ou carrinho!")
            return redirect(url_for("auth.login"))
    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


def handle_error(e):
    error_id = generate_unique_error_id()
    # check if datetime as atribute utcnow
    if hasattr(datetime, "utcnow"):
        timestamp = datetime.utcnow().isoformat()
    else:
        timestamp = datetime.datetime.now().isoformat()
    user_info = (
        f"User: {current_user.username}"
        if current_user.is_authenticated
        else "User: Not authenticated"
    )
    logger.error(
        "Error ID: %s\nTimestamp: %s\n%s\n%s", error_id, timestamp, user_info, str(e)
    )

    flash(
        "Ocorreu um erro inesperado. Por favor, entre em contato com o suporte com o ID do erro: "
        + error_id,
        category="danger",
    )
    return redirect(url_for("main.index"))


def generate_unique_error_id():
    return str(uuid.uuid4())


@login_required
def recheck_login():
    # Check if re-authentication is needed based on the configured periods
    idle_period_limit = datetime.utcnow() - timedelta(days=30)  # L1: 30 days
    actively_used_limit = datetime.utcnow() - timedelta(hours=12)  # L2: 12 hours

    if current_user.last_activity_time < idle_period_limit:
        # Re-authenticate for idle period
        flash("Please re-enter your password to continue.", "danger")

        logout_user()

        return redirect(url_for("auth.login"))

    if current_user.last_activity_time < actively_used_limit:
        # Re-authenticate for actively used period
        flash("Please re-enter your password to continue.", "danger")

        logout_user()

        return redirect(url_for("auth.login"))
