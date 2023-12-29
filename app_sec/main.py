from datetime import datetime, timedelta
import uuid
from flask import Blueprint, redirect, render_template, flash, current_app, url_for
from flask_login import current_user, login_required
from sqlalchemy import text
from . import db
from flask_login import current_user
import logging
from .auth import recheck_login

main = Blueprint("main", __name__)

logger = logging.getLogger(__name__)


@main.route("/")
def index():
    try:
        if current_user.is_authenticated:
            action = recheck_login()

            if action is not None:
                return action

            query = text("SELECT * FROM product")
            products = db.session.execute(query).fetchall()

            query = text("SELECT * FROM cart")
            carts = db.session.execute(query).fetchall()

            # get number of items in cart
            query = text(
                "SELECT * FROM cart WHERE customer_id =" + str(current_user.id)
            )

            cart = db.session.execute(query).fetchone()

            if cart is not None:
                query = text(
                    "SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id)
                )
                number_of_items = db.session.execute(query).fetchone()[0]
            else:
                number_of_items = 0

            return render_template(
                "index.html", products=products, number_of_items=number_of_items
            )
        else:
            logger.info("User is not authenticated")
            print("User is not authenticated")
            query = text("SELECT * FROM product")
            products = db.session.execute(query).fetchall()

            return render_template("index.html", products=products)
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
    return render_template("index.html")


def generate_unique_error_id():
    return str(uuid.uuid4())
