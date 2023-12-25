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
from .models import Cart, User
from sqlalchemy import text
from . import db
from werkzeug.security import check_password_hash
import requests
import pyotp

auth = Blueprint("auth", __name__)

# Initialize a TOTP object
totp = pyotp.TOTP(pyotp.random_base32())


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    else:
        if request.method == "POST":
            username = request.form["username"]
            otp = request.form["otp"]

            user = User.query.filter_by(username=username).first()

            # Verify OTP
            if not totp.verify(otp):
                flash("Invalid Verification Code", category="danger")
                return redirect(url_for("auth.login"))
            else:
                # Log in the user
                login_user(user)
                return redirect(url_for("main.index"))
        else:
            return render_template("login.html")


@auth.route("/form_login", methods=["POST"])
def form_login():
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

    # Send OTP via email
    send_otp_via_email(user.email)

    return render_template("enter_otp.html", username=username)


@auth.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


def send_otp_via_email(email):
    otp_code = totp.now()
    email_server = current_app.config["EMAIL_SERVER"]
    # Constructing email message
    message = """From: %s\r\nTo: %s\r\nSubject: %s\r\n\
    \r\n\n
    %s
    """ % (
        "detiStore@outlook.com",
        ", ".join([email]),
        "Verification Code",
        f"Your verification code is: {otp_code}",
    )

    # Sending email
    email_server.sendmail("detiStore@outlook.com", [email], message)


@auth.route("/login_google")
def login_google():
    google = current_app.config["oauth"].create_client("google")
    redirect_uri = url_for("auth.authorize_google", _external=True)
    return google.authorize_redirect(redirect_uri)


@auth.route("/authorize_google")
def authorize_google():
    google = current_app.config["oauth"].create_client("google")
    token = google.authorize_access_token()
    user_info = google.get("https://www.googleapis.com/oauth2/v3/userinfo").json()

    email = user_info["email"]
    username = email.split("@")[0]
    picture = user_info["picture"]
    name = user_info["name"]

    user = User.query.filter_by(email=email).first()
    if not user:
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

            login_user(new_user)
            flash("Conta criada com sucesso! Pode completar os dados que faltam")
            return redirect(url_for("profile.changeProfile"))
        except Exception as e:
            db.session.rollback()
            flash("Erro ao criar usuário ou carrinho!")
            return redirect(url_for("auth.login"))

    login_user(user)
    return redirect(url_for("main.index"))
