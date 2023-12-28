import uuid
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    current_app,
)
from flask_login import login_required, current_user
from sqlalchemy import text
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
import os
import re
from sqlalchemy.exc import IntegrityError
import requests
import hashlib
from . import encryption as E
import logging
from datetime import datetime
from .auth import recheck_login

logger = logging.getLogger(__name__)

profile = Blueprint("profile", __name__)


@profile.route("/profile")
@login_required
def perfil():
    try:
        action = recheck_login()

        if action is not None:
            return action

        user = User.query.filter_by(id=current_user.id).first()

        # get number of items in cart
        query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))

        cart = db.session.execute(query).fetchone()

        if cart is not None:
            query = text(
                "SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id)
            )
            number_of_items = db.session.execute(query).fetchone()[0]
        else:
            number_of_items = 0

        return render_template(
            "my-account.html", user=user, number_of_items=number_of_items
        )

    except Exception as e:
        # Handle unexpected errors
        handle_error(e)


@profile.route("/edit_profile", methods=["GET"])
@login_required
def changeProfile():
    try:
        user = User.query.filter_by(id=current_user.id).first()

        # get number of items in cart
        query = text("SELECT * FROM cart WHERE customer_id =" + str(user.id))

        cart = db.session.execute(query).fetchone()

        if cart is not None:
            query = text(
                "SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id)
            )
            number_of_items = db.session.execute(query).fetchone()[0]
        else:
            number_of_items = 0

        return render_template(
            "profile.html", user=user, number_of_items=number_of_items
        )

    except Exception as e:
        # Handle unexpected errors
        handle_error(e)


@profile.route("/edit_profile", methods=["POST"])
@login_required
def changeProfileForm():
    try:
        if current_user.google_account:
            flash("Não é possível alterar o perfil de uma conta Google!")
            return redirect(url_for("profile.changeProfile", id=current_user.id))

        user = User.query.filter_by(id=current_user.id).first()
        name = request.form.get("name")
        username = request.form.get("username")
        phone = request.form.get("phone")
        image = request.files.get("image")
        currentPassword = request.form.get("currentPassword")
        newPassword = request.form.get("newPassword")
        confirmNewPassword = request.form.get("confirmNewPassword")
        security_question = (
            request.form.get("security_question")
            + "-"
            + request.form.get("security_answer")
        )

        if currentPassword:
            if not check_password_hash(user.password, currentPassword):
                flash("Password atual errada!", category="danger")
                return redirect(url_for("profile.changeProfile", id=user.id))
        else:
            flash("Password atual não foi inserida!", category="danger")
            return redirect(url_for("profile.changeProfile", id=user.id))

        if security_question:
            if security_question != user.security_question:
                flash("Pergunta de segurança errada!", category="danger")
                return redirect(url_for("profile.changeProfile", id=user.id))
        else:
            flash("Pergunta de segurança não foi inserida!", category="danger")
            return redirect(url_for("profile.changeProfile", id=user.id))

        if name:
            user.name = name

        if username:
            user.username = username

        if phone:
            phone_pattern = r"^\d{9}$|^\d{3}[-\s]?\d{2}[-\s]?\d{4}$"
            if not re.match(phone_pattern, phone):
                flash("Número de telefone inválido!", category="danger")
                return redirect(url_for("profile.changeProfile", id=user.id))
            # encrypt phone number
            key = E.generate_key()
            # store the key
            E.store_key(key, f"{user.username}_PHONE_KEY")
            user.phone = E.chacha20_encrypt(phone, key)
            if user.phone is None:
                flash("Erro ao encriptar número de telefone!", category="danger")
                return redirect(url_for("profile.changeProfile", id=user.id))

        if image:
            if (
                image.filename.endswith(".png")
                or image.filename.endswith(".jpeg")
                or image.filename.endswith(".jpg")
            ):
                try:
                    user.image = "../static/images/" + image.filename
                    image.save(os.path.join("static/images", image.filename))
                except:
                    flash("Erro ao fazer upload da imagem!", category="danger")
                    return redirect(url_for("profile.changeProfile"))
            else:
                flash(
                    "Por favor insira uma imagem com extensão .png ou .jpeg ou .jpg",
                    category="danger",
                )
                return redirect(url_for("profile.changeProfile"))

        if newPassword:
            if newPassword == confirmNewPassword:
                processed_key = re.sub(" +", " ", newPassword)
                if not is_valid_password(processed_key):
                    return redirect(url_for("profile.changeProfile"))

                user.password = generate_password_hash(newPassword)
            else:
                flash("Passwords novas não coincidem!", category="danger")
                return redirect(url_for("profile.changeProfile", id=user.id))

        db.session.commit()
        flash("Perfil atualizado com sucesso!", category="success")

        return redirect(url_for("profile.changeProfile", id=user.id))

    except Exception as e:
        # Handle unexpected errors
        handle_error(e)


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
    try:
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
    except Exception as e:
        # Handle unexpected errors
        handle_error(e)


def handle_error(e):
    error_id = generate_unique_error_id()
    timestamp = datetime.utcnow().isoformat()
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
    return redirect(url_for("profile.changeProfile"))


def generate_unique_error_id():
    return str(uuid.uuid4())
