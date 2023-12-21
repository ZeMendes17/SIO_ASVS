from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from .models import User
from sqlalchemy import text
from . import db
from werkzeug.security import check_password_hash

auth = Blueprint("auth", __name__)


@auth.route("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    else:
        return render_template("login.html")


@auth.route("/form_login", methods=["POST"])
def form_login():
    username = request.form["username"]
    key = request.form["password"]

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, key):
        flash("Please check your login details and try again.")
        return redirect(url_for("auth.login"))

    login_user(user)

    return redirect(url_for("main.index"))


@auth.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))
