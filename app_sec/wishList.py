from datetime import datetime
from flask import Blueprint, render_template, redirect, request, flash, url_for
from flask_login import current_user, login_required
from .models import Comment, Product, Cart
from sqlalchemy import text
from . import db

wish_list = Blueprint("wishList", __name__)


@wish_list.route("/wishlist", methods=["GET"])
@login_required
def wishlist():
    query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))
    cart = db.session.execute(query).fetchone()

    if cart is not None:
        query = text("SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id))
        number_of_items = db.session.execute(query).fetchone()[0]
    else:
        number_of_items = 0

    query = text("SELECT * FROM wishlist WHERE customer_id =" + str(current_user.id))
    WishList = db.session.execute(query).fetchone()

    print(WishList)

    query = text(
        "SELECT * FROM product WHERE id IN (SELECT product_id FROM wishlist_product WHERE wishlist_id = "
        + str(WishList.id)
        + ")"
    )
    products = db.session.execute(query).fetchall()
    print(products)
    return render_template(
        "wishlist.html", products=products, number_of_items=number_of_items
    )


@wish_list.route("/wishlist/remove_product/<int:product_id>", methods=["GET"])
@login_required
def remove_product(product_id):
    if not current_user.is_authenticated:
        flash("Você precisa estar logado para gerenciar sua lista de desejos.", "error")
        return redirect(url_for("auth.login"))

    query = text("SELECT * FROM wishlist WHERE customer_id =" + str(current_user.id))
    WishList = db.session.execute(query).fetchone()

    if WishList is None:
        flash("Sua lista de desejos está vazia.", "info")
        return redirect(url_for("wishList.wishlist"))

    query = text(
        "DELETE FROM wishlist_product WHERE wishlist_id = :wishlist_id AND product_id = :product_id"
    )
    db.session.execute(query, {"wishlist_id": WishList.id, "product_id": product_id})
    db.session.commit()

    flash("Product removed from wishlist!", "info")
    return redirect(url_for("wishList.wishlist"))


@wish_list.route("/wishlist/add_to_cart/<int:product_id>", methods=["GET"])
@login_required
def add_to_cart(product_id):
    if not current_user.is_authenticated:
        flash(
            "Você precisa estar logado para adicionar itens ao seu carrinho.", "error"
        )
        return redirect(url_for("auth.login"))

    query = text("SELECT * FROM product WHERE id =" + str(product_id))
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
            "INSERT INTO cart_product (cart_id, product_id) VALUES ("
            + str(cart.id)
            + ","
            + str(product.id)
            + ")"
        )
        db.session.execute(query)
        db.session.commit()
        flash("Product added to cart!", "success")
    else:
        flash("Product already in cart!", "error")

    return redirect("/wishlist")


@login_required
@wish_list.route("/wishlist", methods=["POST"])
def whishlist_search():
    if 'search' in request.form:
        search_value = request.form['search_value']
        
        # gets the eproducts from the users wishlist
        query = text("SELECT * FROM wishlist WHERE customer_id =" + str(current_user.id))
        WishList = db.session.execute(query).fetchone()
        query = text(
            "SELECT * FROM product WHERE id IN (SELECT product_id FROM wishlist_product WHERE wishlist_id = "
            + str(WishList.id)
            + ")"
        )
        products = db.session.execute(query).fetchall()

        # filters the products by the search value
        filtered_products = []
        for product in products:
            if search_value.lower() in product.name.lower():
                filtered_products.append(product)

        return render_template("wishlist.html", products=filtered_products, default_value=search_value)
        

    else:
        return redirect("/wishlist")
