from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from .models import User
from sqlalchemy import text
from . import db
from werkzeug.security import check_password_hash
import requests

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
