import uuid
from sqlalchemy.exc import IntegrityError
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
)
from flask_login import login_user
from .models import User, Cart, Wishlist
from . import db
import os
from werkzeug.security import generate_password_hash
from sqlalchemy import text
import re
import requests
import hashlib
from . import encryption as E
import logging
from datetime import datetime

register = Blueprint("register", __name__)

logger = logging.getLogger(__name__)


@register.route("/register")
def regist():
    return render_template("signin.html")


@register.route("/form_signin", methods=["POST"])
def form_signin():
    nome = request.form["name"]
    email = request.form["email"]
    phone = request.form["phone"]
    user = request.form["username"]
    key = request.form["password"]
    conf_key = request.form["confirm_password"]
    profile_picture = request.files.get("image")
    security_question = (
        request.form["security_question"] + "-" + request.form["security_answer"]
    )
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

    # All users
    users = User.query.all()

    # Check if the email already exists
    for u in users:
        # get the user's email key
        email_key = E.get_key(f"{u.username.upper()}_EMAIL_KEY")
        # decrypt the user's email
        email = E.chacha20_decrypt(u.email, email_key)
        if email == request.form["email"]:
            flash("Email já existe!", category="danger")
            return redirect(url_for("register.regist"))

    if not recaptcha_request["tokenProperties"]["valid"]:
        flash("Recaptcha inválido!", category="danger")
        return redirect(url_for("register.regist"))

    processed_key = re.sub(" +", " ", key)
    if not is_valid_password(processed_key):
        return redirect(url_for("register.regist"))

    if key != conf_key:
        flash("Passwords não coincidem!", "error")
        return redirect(url_for("register.regist"))

    # Verifique se o nome de usuário já existe
    phone_pattern = r"^\d{9}$|^\d{3}[-\s]?\d{2}[-\s]?\d{4}$"
    if not re.match(phone_pattern, phone):
        flash("Número de telefone inválido!", category="danger")
        return redirect(url_for("register.regist"))

    # Verifique se a imagem é válida
    if profile_picture:
        if (
            profile_picture.filename.endswith(".png")
            or profile_picture.filename.endswith(".jpeg")
            or profile_picture.filename.endswith(".jpg")
        ):
            try:
                upload_folder = "static/images/profile_pictures"
                file_name = email + "_" + profile_picture.filename
                os.makedirs(upload_folder, exist_ok=True)

                # Save the file to the directory
                profile_picture.save(os.path.join(upload_folder, file_name))

                #  check if picture is bigger than 5MB
                if os.path.getsize(upload_folder + "/" + file_name) / (1024 * 1024) > 5:
                    # remove the file
                    os.remove(upload_folder + "/" + file_name)
                    flash("A imagem não pode ter mais de 5MB!", category="danger")
                    return redirect(url_for("register.regist"))

                # encrypt email and phone number
                email_key = E.generate_key()
                phone_key = E.generate_key()
                # store the keys
                E.store_key(email_key, f"{user.upper()}_EMAIL_KEY")
                E.store_key(phone_key, f"{user.upper()}_PHONE_KEY")
                email_enc = E.chacha20_encrypt(email, email_key)
                phone_enc = E.chacha20_encrypt(phone, phone_key)
                if email_enc is None or phone_enc is None:
                    flash("Erro ao encriptar email ou número de telefone!")
                    return redirect(url_for("register.regist"))

                new_user = User(
                    username=user,
                    password=generate_password_hash(key),
                    name=nome,
                    email=email_enc,
                    phone=phone_enc,
                    image=upload_folder + "/" + file_name,
                    security_question=security_question,
                    google_account=False,
                )
            except Exception as e:
                print(e)
                flash("Erro ao fazer upload da imagem!", category="danger")
                return redirect(url_for("register.regist"))
        else:
            flash(
                "Por favor insira uma imagem com extensão .png ou .jpeg ou .jpg",
                category="danger",
            )
            return redirect(url_for("register.regist"))
    else:
        # encrypt email and phone number
        email_key = E.generate_key()
        phone_key = E.generate_key()
        # store the keys
        E.store_key(email_key, f"{user.upper()}_EMAIL_KEY")
        E.store_key(phone_key, f"{user.upper()}_PHONE_KEY")
        email_enc = E.chacha20_encrypt(email, email_key)
        phone_enc = E.chacha20_encrypt(phone, phone_key)
        if email_enc is None or phone_enc is None:
            flash("Erro ao encriptar email ou número de telefone!")
            return redirect(url_for("register.regist"))

        new_user = User(
            username=user,
            password=generate_password_hash(key),
            name=nome,
            email=email_enc,
            phone=phone_enc,
            security_question=security_question,
            google_account=False,
        )

    try:
        # Adicione o usuário ao banco de dados
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

    except IntegrityError:
        db.session.rollback()
        flash("Username already exists!", "error")
        return redirect(url_for("register.regist"))

    except Exception as e:
        # Handle unexpected errors
        db.session.rollback()
        return handle_error(e)


def is_valid_password(password):
    # Check if the password is breached
    if check_breached_password(password):
        flash("A senha foi comprometida, tente outra")
        return False
    # Ensure password length is within the allowed range
    elif len(password) < 12:
        flash("A senha deve ter pelo menos 12 caracteres (espaços não incluídos)")
        return False
    elif len(password) > 128:
        flash("A senha deve ter no máximo 128 caracteres (espaços não incluídos)")
        return False
    # Check if all characters in the password are printable Unicode characters
    elif not all(c.isprintable() for c in password):
        flash("A senha deve conter apenas caracteres Unicode imprimíveis")
        return False

    return True


def check_breached_password(password):
    # Hash the password using SHA-1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # Send the first 5 characters of the hashed password to the HIBP API
    api_url = f"https://api.pwnedpasswords.com/range/{sha1_hash[:5]}"
    response = requests.get(api_url)

    if response.status_code == 200:
        # Check if the remaining part of the hashed password appears in the response
        tail = sha1_hash[5:]
        if tail in response.text:
            return True  # Password is breached
    return False  # Password is not breached


def handle_error(e):
    error_id = generate_unique_error_id()
    # check if datetime as atribute utcnow
    if hasattr(datetime, "utcnow"):
        timestamp = datetime.utcnow().isoformat()
    else:
        timestamp = datetime.datetime.now().isoformat()
    logger.error("Error ID: %s\nTimestamp: %s\n%s\n%s", error_id, timestamp, str(e))

    flash(
        "Ocorreu um erro inesperado. Por favor, entre em contato com o suporte com o ID do erro: "
        + error_id,
        category="danger",
    )
    return redirect(url_for("register.regist"))


def generate_unique_error_id():
    return str(uuid.uuid4())
