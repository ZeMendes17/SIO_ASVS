from datetime import datetime
import uuid
from flask import (
    Blueprint,
    render_template,
    redirect,
    request,
    flash,
    current_app,
    url_for,
)
from flask_login import current_user, login_required
from .models import Comment
from sqlalchemy import text
from . import db
import logging
from .auth import recheck_login

logger = logging.getLogger(__name__)
products = Blueprint("product", __name__)


@products.route("/product/<int:id>", methods=["GET"])
def product(id):
    try:
        if current_user.is_authenticated:
            action = recheck_login()

            if action is not None:
                return action

            query = text("SELECT * FROM product WHERE id =" + str(id))
            product = db.session.execute(query).fetchone()

            # get the comments for the product
            query = text("SELECT * FROM comment WHERE product_id =" + str(id))
            comments = db.session.execute(query).fetchall()

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
                "product.html",
                product=product,
                comments=comments,
                number_of_items=number_of_items,
            )
        else:
            query = text("SELECT * FROM product WHERE id =" + str(id))
            product = db.session.execute(query).fetchone()

            # get the comments for the product
            query = text("SELECT * FROM comment WHERE product_id =" + str(id))
            comments = db.session.execute(query).fetchall()

            return render_template("product.html", product=product, comments=comments)

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@products.route("/product/add_to_cart/<int:id>", methods=["POST"])
@login_required
def add_to_cart(id):
    try:
        query = text("SELECT * FROM product WHERE id =" + str(id))
        product = db.session.execute(query).fetchone()

        query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))
        cart = db.session.execute(query).fetchone()

        query = text(
            "SELECT * FROM cart_product WHERE cart_id ="
            + str(cart.id)
            + " AND product_id ="
            + str(product.id)
        )
        product_in_cart = db.session.execute(query).fetchone()

        if product_in_cart is None:
            query = text(
                "INSERT INTO cart_product (cart_id, product_id, quantity) VALUES ("
                + str(cart.id)
                + ","
                + str(product.id)
                + ","
                + str(1)
                + ")"
            )
            db.session.execute(query)
            db.session.commit()
            flash("Product added to cart!", "success")
        else:
            flash("Product already in cart!", "error")

        return redirect("/product/" + str(id))

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@products.route("/product/<int:id>/addcomment", methods=["POST"])
@login_required
def addcomment(id):
    try:
        # get the comment data
        comment = request.form["comment_input"]
        rating = int(request.form["rating_input"])

        # if the option is clear it will just refresh

        if "add_comment" in request.form:
            new_comment = Comment(
                user_name=current_user.username,
                date=datetime.today().strftime("%d/%m/%Y"),
                comment=comment,
                product_id=id,
                rating=rating,
            )
            db.session.add(new_comment)
            db.session.commit()

            # update the product rating
            query = text("SELECT AVG(rating) FROM comment WHERE product_id =" + str(id))
            rating = db.session.execute(query).fetchone()[0]
            query = text(
                "UPDATE product SET rating = "
                + str(round(rating, 1))
                + " WHERE id ="
                + str(id)
            )
            db.session.execute(query)
            db.session.commit()

        return redirect("/product/" + str(id))

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@products.route("/product/add_to_wishlist/<int:id>", methods=["POST"])
@login_required
def add_to_wishlist(id):
    try:
        query = text("SELECT * FROM product WHERE id =" + str(id))
        product = db.session.execute(query).fetchone()

        query = text(
            "SELECT * FROM wishlist WHERE customer_id =" + str(current_user.id)
        )
        wishlist = db.session.execute(query).fetchone()

        query = text(
            "SELECT * FROM wishlist_product WHERE wishlist_id ="
            + str(wishlist.id)
            + " AND product_id ="
            + str(product.id)
        )
        product_in_wishlist = db.session.execute(query).fetchone()

        if product_in_wishlist is None:
            query = text(
                "INSERT INTO wishlist_product (wishlist_id, product_id) VALUES ("
                + str(wishlist.id)
                + ","
                + str(product.id)
                + ")"
            )
            db.session.execute(query)
            db.session.commit()
            flash("Product added to wishlist!", "success")
        else:
            flash("Product already in wishlist!", "error")

        return redirect("/product/" + str(id))

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
    return redirect(url_for("product.product"))


def generate_unique_error_id():
    return str(uuid.uuid4())
