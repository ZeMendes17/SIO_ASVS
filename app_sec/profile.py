from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from sqlalchemy import text
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
import os
import re
from sqlalchemy.exc import IntegrityError

profile = Blueprint("profile", __name__)


@profile.route("/profile")
@login_required
def perfil():
    user = User.query.filter_by(id=current_user.id).first()

    # get number of items in cart
    query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))

    cart = db.session.execute(query).fetchone()

    if cart is not None:
        query = text("SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id))
        number_of_items = db.session.execute(query).fetchone()[0]
    else:
        number_of_items = 0

    return render_template(
        "my-account.html", user=user, number_of_items=number_of_items
    )


@profile.route("/edit_profile", methods=["GET"])
@login_required
def changeProfile():
    user = User.query.filter_by(id=current_user.id).first()

    # get number of items in cart
    query = text("SELECT * FROM cart WHERE customer_id =" + str(user.id))

    cart = db.session.execute(query).fetchone()

    if cart is not None:
        query = text("SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id))
        number_of_items = db.session.execute(query).fetchone()[0]
    else:
        number_of_items = 0

    return render_template("profile.html", user=user, number_of_items=number_of_items)


@profile.route("/edit_profile", methods=["POST"])
@login_required
def changeProfileForm():
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
        user.phone = phone

    if image:
        if image.filename.endswith(".png") or image.filename.endswith(".jpeg"):
            try:
                user.image = image.filename
                image.save(os.path.join("app_sec/static/images", image.filename))
            except:
                flash("Erro ao fazer upload da imagem!", category="danger")
        else:
            flash(
                "Por favor insira uma imagem com extensão .png ou .jpeg",
                category="danger",
            )
            return redirect(url_for("profile.changeProfile"))

    if newPassword:
        if newPassword == confirmNewPassword:
            if len(newPassword) < 8:
                flash("A senha deve ter pelo menos 8 caracteres")
                return redirect(url_for("profile.changeProfile"))
            elif not any(char.isdigit() for char in newPassword):
                flash("A senha deve ter pelo menos um número")
                return redirect(url_for("profile.changeProfile"))
            elif not any(char.isupper() for char in newPassword):
                flash("A senha deve ter pelo menos uma letra maiúscula")
                return redirect(url_for("profile.changeProfile"))
            elif not any(char.islower() for char in newPassword):
                flash("A senha deve ter pelo menos uma letra minúscula")
                return redirect(url_for("profile.changeProfile"))
            elif not any(
                char in "~`! @#$%^&*()_-+={[}]|\:;\"'<,>.?/" for char in newPassword
            ):
                flash("A senha deve ter pelo menos um caractere especial")
                return redirect(url_for("profile.changeProfile"))
            user.password = generate_password_hash(newPassword)
        else:
            flash("Passwords novas não coincidem!", category="danger")
            return redirect(url_for("profile.changeProfile", id=user.id))

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Username já existe!", "error")
        return redirect(url_for("profile.changeProfile", id=user.id))

    flash("Perfil atualizado com sucesso!", category="success")

    return redirect(url_for("profile.changeProfile", id=user.id))
