import datetime
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
from . import db
import logging

logger = logging.getLogger(__name__)

orders = Blueprint("orders", __name__)


@orders.route("/orders", methods=["GET"])
@login_required
def orders_page():
    try:
        query = text(
            "SELECT * FROM [order] WHERE customer_id ="
            + str(current_user.id)
            + " ORDER BY order_number DESC"
        )
        orders = db.session.execute(query).fetchall()

        all_order_products = {}
        product_names = {}
        final_prices = {}
        for order in orders:
            query = text("SELECT * FROM order_product WHERE order_id =" + str(order.id))
            order_products = db.session.execute(query).fetchall()
            all_order_products[order.id] = order_products

            final_price = order.tax + order.shipping_cost
            for order_product in order_products:
                final_price += order_product.price_each * order_product.quantity

            final_prices[order.id] = final_price
            # get names
            for order_product in order_products:
                query = text(
                    "SELECT name FROM product WHERE id ="
                    + str(order_product.product_id)
                )
                product_name = db.session.execute(query).fetchone()
                product_names[order_product.product_id] = product_name[0]

        # get product names

        return render_template(
            "orders.html",
            orders=orders,
            all_order_products=all_order_products,
            product_names=product_names,
            final_prices=final_prices,
        )

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@orders.route("/orders", methods=["POST"])
@login_required
def orders_page_post():
    try:
        for key in request.form:
            if key.startswith("order_again_"):
                order_id = key.split("_")[2]
                query = text(
                    "SELECT * FROM order_product WHERE order_id =" + str(order_id)
                )
                order_products = db.session.execute(query).fetchall()

                # get the shipping cost and tax
                query = text("SELECT * FROM [order] WHERE id =" + str(order_id))
                order = db.session.execute(query).fetchone()

                shipping_cost = order.shipping_cost
                tax = order.tax
                subtotal = 0
                grand_total = shipping_cost + tax
                number_of_items = 0
                product_list = []
                product_quantities = {}

                for product in order_products:
                    subtotal += product.price_each * product.quantity
                    grand_total += product.price_each * product.quantity
                    number_of_items += 1

                    query = text(
                        "SELECT * FROM product WHERE id =" + str(product.product_id)
                    )
                    p = db.session.execute(
                        query
                    ).fetchone()  # to get the most recent price

                    product_dict = {
                        "product_name": p.name,
                        "price": p.price,
                        "quantity": product.quantity,
                        "image_name": p.image_name,
                    }
                    product_list.append(product_dict)
                    product_quantities[product.product_id] = product.quantity

                return render_template(
                    "checkout.html",
                    product_list=product_list,
                    subtotal=subtotal,
                    total=grand_total,
                    shipping_cost=shipping_cost,
                    number_of_items=number_of_items,
                    product_quantities=product_quantities,
                )

        return redirect(url_for("orders.orders_page"))

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
    return redirect(url_for("orders.orders_page"))


def generate_unique_error_id():
    return str(uuid.uuid4())
