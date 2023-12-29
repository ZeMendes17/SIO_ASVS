from datetime import datetime, timedelta
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
from sqlalchemy import text
from flask_login import current_user, login_required, logout_user
from . import db
import logging
from .auth import recheck_login

shops = Blueprint("shops", __name__)

logger = logging.getLogger(__name__)


def handle_error(e, redirect_route, flash_message):
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
    return redirect(url_for(redirect_route))


def generate_unique_error_id():
    return str(uuid.uuid4())


@shops.route("/shop", methods=["GET", "POST"])
def shop():
    try:
        if request.method == "GET":
            if current_user.is_authenticated:
                action = recheck_login()

                if action is not None:
                    return action

                search = request.args.get("search")
                if search:
                    query = text("SELECT * FROM product WHERE name LIKE :search")
                    products = db.session.execute(
                        query, {"search": "%" + search + "%"}
                    ).fetchall()
                    return render_template(
                        "shop.html", products=products, default_value=search.strip()
                    )
                query = text("SELECT * FROM product")
                products = db.session.execute(query).fetchall()

                # get number of items in cart
                query = text(
                    "SELECT * FROM cart WHERE customer_id =" + str(current_user.id)
                )

                cart = db.session.execute(query).fetchone()

                if cart is not None:
                    query = text(
                        "SELECT COUNT(*) FROM cart_product WHERE cart_id ="
                        + str(cart.id)
                    )
                    number_of_items = db.session.execute(query).fetchone()[0]
                else:
                    number_of_items = 0

                return render_template(
                    "shop.html", products=products, number_of_items=number_of_items
                )
            else:
                search = request.args.get("search")
                if search:
                    query = text("SELECT * FROM product WHERE name LIKE :search")
                    products = db.session.execute(
                        query, {"search": "%" + search + "%"}
                    ).fetchall()
                    return render_template(
                        "shop.html", products=products, default_value=search.strip()
                    )
                query = text("SELECT * FROM product")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products)

        else:  # POST
            if "search" in request.form:
                search_value = request.form["search_value"]
                return redirect(url_for("shops.shop", search=search_value))

            elif "option" in request.form:
                op = int(request.form["option"])
                options = [
                    "nothing",
                    "rating",
                    "priceDesc",
                    "priceAsc",
                    "clothing",
                    "accessories",
                    "miscellaneous",
                ]
                selected = options[op]

                return selected
    except Exception as e:
        return handle_error(
            e, "shops.shop", "An unexpected error occurred. Please try again later."
        )


@shops.route("/shop/<option>", methods=["GET", "POST"])
def sort(option):
    try:
        if request.method == "GET":
            if option == "nothing":
                return redirect(url_for("shops.shop"))

            elif option == "rating":
                query = text("SELECT * FROM product ORDER BY rating DESC")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products, option=option)

            elif option == "priceDesc":
                query = text("SELECT * FROM product ORDER BY price DESC")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products, option=option)

            elif option == "priceAsc":
                query = text("SELECT * FROM product ORDER BY price ASC")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products, option=option)

            elif option == "clothing":
                query = text("SELECT * FROM product WHERE categorie = 'clothing'")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products, option=option)

            elif option == "accessories":
                query = text("SELECT * FROM product WHERE categorie = 'accessories'")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products, option=option)

            elif option == "miscellaneous":
                query = text("SELECT * FROM product WHERE categorie = 'miscellaneous'")
                products = db.session.execute(query).fetchall()

                return render_template("shop.html", products=products, option=option)

            else:
                return redirect(url_for("shops.shop"))

        elif request.method == "POST":
            if "search" in request.form:
                search_value = request.form["search_value"]

                if option == "rating":
                    query = text(
                        "SELECT * FROM product WHERE name LIKE :search ORDER BY rating DESC"
                    )
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

                elif option == "priceDesc":
                    query = text(
                        "SELECT * FROM product WHERE name LIKE :search ORDER BY price DESC"
                    )
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

                elif option == "priceAsc":
                    query = text(
                        "SELECT * FROM product WHERE name LIKE :search ORDER BY price ASC"
                    )
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

                elif option == "clothing":
                    query = text(
                        "SELECT * FROM product WHERE name LIKE :search AND categorie = 'clothing'"
                    )
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

                elif option == "accessories":
                    query = text(
                        "SELECT * FROM product WHERE name LIKE :search AND categorie = 'accessories'"
                    )
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

                elif option == "miscellaneous":
                    query = text(
                        "SELECT * FROM product WHERE name LIKE :search AND categorie = 'miscellaneous'"
                    )
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

                else:
                    query = text("SELECT * FROM product WHERE name LIKE :search")
                    products = db.session.execute(
                        query, {"search": "%" + search_value + "%"}
                    ).fetchall()

                    return render_template(
                        "shop.html",
                        products=products,
                        option=option,
                        default_value=search_value.strip(),
                    )

            else:
                return redirect(url_for("shops.shop"))
    except Exception as e:
        return handle_error(
            e, "shops.shop", "An unexpected error occurred. Please try again later."
        )


@shops.route("/shop/add_to_cart/<int:id>", methods=["POST", "GET"])
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

        return redirect("/shop")
    except Exception as e:
        return handle_error(
            e, "shops.shop", "An unexpected error occurred. Please try again later."
        )


@shops.route("/shop/add_to_wishlist/<int:id>", methods=["GET"])
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

        return redirect("/shop")
    except Exception as e:
        return handle_error(
            e, "shops.shop", "An unexpected error occurred. Please try again later."
        )
