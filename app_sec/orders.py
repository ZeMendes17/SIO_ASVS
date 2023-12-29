from datetime import datetime
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
from . import encryption as E
from .auth import recheck_login

logger = logging.getLogger(__name__)

orders = Blueprint("orders", __name__)


@orders.route("/orders", methods=["GET"])
@login_required
def orders_page():
    try:
        action = recheck_login()

        if action is not None:
            return action

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

        disp_orders = {}
        count = 0
        for order in orders:
            if order.customer_id != current_user.id:
                continue
            count += 1
            disp_orders[order.id] = []
            # get the tracking number
            key = E.get_key(
                f"{current_user.username.upper()}{count}_TRACKING_NUMBER_KEY"
            )
            tracking_number = E.chacha20_decrypt(order.tracking_number, key)
            disp_orders[order.id].append(tracking_number)
            # same for the billing and shipping addresses
            key = E.get_key(
                f"{current_user.username.upper()}{count}_BILLING_ADDRESS_KEY"
            )
            billing_address = E.chacha20_decrypt(order.billing_address, key)
            disp_orders[order.id].append(billing_address)

            key = E.get_key(
                f"{current_user.username.upper()}{count}_SHIPPING_ADDRESS_KEY"
            )
            shipping_address = E.chacha20_decrypt(order.shipping_address, key)
            disp_orders[order.id].append(shipping_address)

            if tracking_number is None or billing_address is None or shipping_address is None:
                flash(
                    "Erro ao desencriptar informação da encomenda!",
                    category="danger",
                )
                return redirect(url_for("orders.orders_page"))

        # get product names

        return render_template(
            "orders.html",
            orders=orders,
            disp_orders=disp_orders,
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
