from flask import Blueprint, render_template
from sqlalchemy import text
from . import db
from flask_login import current_user

main = Blueprint("main", __name__)


@main.route("/")
def index():
    if current_user.is_authenticated:
        query = text("SELECT * FROM product")
        products = db.session.execute(query).fetchall()

        query = text("SELECT * FROM cart")
        carts = db.session.execute(query).fetchall()

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
            "index.html", products=products, number_of_items=number_of_items
        )
    else:
        query = text("SELECT * FROM product")
        products = db.session.execute(query).fetchall()

        return render_template("index.html", products=products)
