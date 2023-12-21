from sqlalchemy.exc import IntegrityError
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user
from .models import User, Cart
from . import db
import os
from werkzeug.security import generate_password_hash
from sqlalchemy import text
import re

register = Blueprint("register", __name__)


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

    if len(key) < 8:
        flash("A senha deve ter pelo menos 8 caracteres")
        return redirect(url_for("register.regist"))
    elif not any(char.isdigit() for char in key):
        flash("A senha deve ter pelo menos um número")
        return redirect(url_for("register.regist"))
    elif not any(char.isupper() for char in key):
        flash("A senha deve ter pelo menos uma letra maiúscula")
        return redirect(url_for("register.regist"))
    elif not any(char.islower() for char in key):
        flash("A senha deve ter pelo menos uma letra minúscula")
        return redirect(url_for("register.regist"))
    elif not any(char in "~`! @#$%^&*()_-+={[}]|\:;\"'<,>.?/" for char in key):
        flash("A senha deve ter pelo menos um caractere especial")
        return redirect(url_for("register.regist"))

    if key != conf_key:
        flash("Passwords não coincidem!", "error")
        return redirect(url_for("register.regist"))

    # Verifique se o nome de usuário já existe
    phone_pattern = r"^\d{9}$|^\d{3}[-\s]?\d{2}[-\s]?\d{4}$"
    if not re.match(phone_pattern, phone):
        flash("Número de telefone inválido!", category="danger")
        return redirect(url_for("register.regist"))
    user.phone = phone

    # Verifique se a imagem é válida
    if profile_picture:
        if profile_picture.filename.endswith(
            ".png"
        ) or profile_picture.filename.endswith(".jpeg"):
            try:
                profile_picture.save(
                    os.path.join("app_sec/static/images", profile_picture.filename)
                )
                new_user = User(
                    username=user,
                    password=generate_password_hash(key),
                    name=nome,
                    email=email,
                    phone=phone,
                    image=profile_picture.filename,
                    security_question=security_question,
                )
            except:
                flash("Erro ao fazer upload da imagem!", category="danger")
                return redirect(url_for("register.regist"))
        else:
            flash(
                "Por favor insira uma imagem com extensão .png ou .jpeg",
                category="danger",
            )
            return redirect(url_for("register.regist"))
    else:
        new_user = User(
            username=user,
            password=generate_password_hash(key),
            name=nome,
            email=email,
            phone=phone,
            security_question=security_question,
        )

    try:
        # Adicione o usuário ao banco de dados
        db.session.add(new_user)
        db.session.commit()

        new_cart = Cart(customer_id=new_user.id)
        db.session.add(new_cart)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("main.index"))

    except IntegrityError:
        db.session.rollback()
        flash("Username or email already exists!", "error")
        return redirect(url_for("register.regist"))

    except Exception as e:
        db.session.rollback()
        flash("Erro ao criar usuário ou carrinho!", "danger")
        return redirect(url_for("register.regist"))
