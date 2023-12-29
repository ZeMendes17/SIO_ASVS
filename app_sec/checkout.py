import datetime
from sqlite3 import IntegrityError
from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    current_app,
)
from flask_login import current_user, login_required
from .models import Order, OrderProduct
from sqlalchemy import text
from . import db
from datetime import date
import string
import random
from . import encryption as E
import uuid
import logging
from .auth import recheck_login

logger = logging.getLogger(__name__)

checkout = Blueprint("checkout", __name__)
order_id = 1


@checkout.route("/checkout", methods=["GET"])
@login_required
def check():
    try:
        action = recheck_login()

        if action is not None:
            return action

        query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))
        cart = db.session.execute(query).fetchone()

        if cart is not None:
            query = text(
                "SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id)
            )
            number_of_items = db.session.execute(query).fetchone()[0]
        else:
            number_of_items = 0

        query = text(
            "SELECT * FROM product WHERE id IN (SELECT product_id FROM cart_product WHERE cart_id = "
            + str(cart.id)
            + ")"
        )
        products = db.session.execute(query).fetchall()

        product_quantities = {}

        for product in products:
            query = text(
                "SELECT quantity FROM cart_product WHERE cart_id = "
                + str(cart.id)
                + " AND product_id = "
                + str(product.id)
            )
            product_quantity = db.session.execute(query).fetchone()

            # Store the product quantity in the dictionary using the product id as the key
            if product_quantity:
                product_quantities[product.id] = product_quantity[0]
            else:
                # If the product doesn't exist in the cart_product table, assume a quantity of 0
                product_quantities[product.id] = 0

        subtotal = sum(
            product.price * product_quantities[product.id]
            if product_quantities[product.id] is not None
            else 0
            for product in products
        )
        grand_total = subtotal + 3.99 + 4.99  # tax + shipping

        product_list = []
        for product in products:
            product_dict = {
                "id": product[0],
                "product_name": product[1],
                "price": product[2],
                "quantity": product[3] / 10,
                "image_name": product[4],
            }
            product_list.append(product_dict)

        return render_template(
            "checkout.html",
            product_list=product_list,
            subtotal=subtotal,
            total=grand_total,
            shipping_cost=4.99,
            number_of_items=number_of_items,
            product_quantities=product_quantities,
        )

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


@checkout.route("/form_checkout", methods=["POST"])
@login_required
def form_checkout():
    try:
        if request.method == "POST":
            address = request.form["address"]
            address2 = request.form["address2"]

            query = text(
                "SELECT * FROM cart WHERE customer_id =" + str(current_user.id)
            )
            cart = db.session.execute(query).fetchone()
            query = text(
                "SELECT * FROM product WHERE id IN (SELECT product_id FROM cart_product WHERE cart_id = "
                + str(cart.id)
                + ")"
            )
            products = db.session.execute(query).fetchall()

            product_quantities = {}

            for product in products:
                query = text(
                    "SELECT quantity FROM cart_product WHERE cart_id = "
                    + str(cart.id)
                    + " AND product_id = "
                    + str(product.id)
                )
                product_quantity = db.session.execute(query).fetchone()

                # Store the product quantity in the dictionary using the product id as the key
                if product_quantity:
                    product_quantities[product.id] = product_quantity[0]
                else:
                    # If the product doesn't exist in the cart_product table, assume a quantity of 0
                    product_quantities[product.id] = 0

            # get the number of existing orders from this customer
            query = text(
                "SELECT COUNT(*) FROM [order] WHERE customer_id ="
                + str(current_user.id)
            )
            number_of_orders = db.session.execute(query).fetchone()[0]

            # Criar um novo Order
            # Criar um novo Order
            # encrypt the tracking number
            key = E.generate_key()
            E.store_key(
                key,
                f"{current_user.username.upper()}{number_of_orders+1}_TRACKING_NUMBER_KEY",
            )
            tracking_number_enc = E.chacha20_encrypt(generate_tracking_number(), key)
            if tracking_number_enc is None:
                flash("Erro ao encriptar tracking number!", category="danger")
                return redirect(url_for("checkout.check"))
            
            # encrypt the shipping address
            key = E.generate_key()
            E.store_key(
                key,
                f"{current_user.username.upper()}{number_of_orders+1}_SHIPPING_ADDRESS_KEY",
            )
            shipping_address_enc = E.chacha20_encrypt(address, key)
            if shipping_address_enc is None:
                flash("Erro ao encriptar shipping address!", category="danger")
                return redirect(url_for("checkout.check"))
            
            # encrypt the billing address
            key = E.generate_key()
            E.store_key(
                key,
                f"{current_user.username.upper()}{number_of_orders+1}_BILLING_ADDRESS_KEY",
            )
            billing_address_enc = E.chacha20_encrypt(address2, key)
            if billing_address_enc is None:
                flash("Erro ao encriptar billing address!", category="danger")
                return redirect(url_for("checkout.check"))

            new_order = Order(
                order_number=number_of_orders + 1,
                customer_id=current_user.id,
                date=date.today().strftime("%d/%m/%Y"),
                tax=3.99,
                shipping_cost=4.99,
                tracking_number=tracking_number_enc,
                shipping_address=shipping_address_enc,
                billing_address=billing_address_enc,
            )

            try:
                # Verificar se há stock suficiente de cada produto
                for product in products:
                    if product.quantity < product_quantities[product.id]:
                        flash(
                            "Not enough stock for product " + product.name + "!",
                            "error",
                        )
                        info = {"Not enough stock for product " + product.name + "!"}
                        return redirect(url_for("checkout.check"))

                # Adicionar o Order ao banco de dados
                db.session.add(new_order)
                db.session.commit()

                for product in products:
                    order_product = OrderProduct(
                        order_id=new_order.id,
                        product_id=product.id,
                        quantity=product_quantities[product.id],
                        price_each=product.price,
                    )
                    db.session.add(order_product)
                    db.session.commit()

                query = text(
                    "SELECT * FROM cart WHERE customer_id =" + str(current_user.id)
                )
                cart = db.session.execute(query).fetchone()

                # Retirar ao stock a quantidade de cada produto
                for product in products:
                    new_quantity = product.quantity - product_quantities[product.id]
                    query = text(
                        "UPDATE product SET quantity = "
                        + str(new_quantity)
                        + " WHERE id = "
                        + str(product.id)
                    )
                    db.session.execute(query)
                    db.session.commit()

                # Remover os produtos do carrinho
                query = text("DELETE FROM cart_product WHERE cart_id =" + str(cart.id))
                db.session.execute(query)
                db.session.commit()

                # Mensagem de sucesso
                flash("Order placed successfully!", "success")

                return redirect(url_for("main.index"))
            except IntegrityError:
                db.session.rollback()
                flash("Shipping Information incorrect!", "error")
                info = {"Shipping Information incorrect!"}
                return redirect(url_for("checkout.check"))

        flash("Method not allowed!", "error")
        return redirect(url_for("checkout.check"))

    except Exception as e:
        # Handle unexpected errors
        return handle_error(e)


def generate_tracking_number(length=12):
    characters = (
        string.ascii_letters + string.digits
    )  # All upper and lower case letters plus digits
    return "".join(random.choice(characters) for _ in range(length))


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
    return redirect(url_for("checkout.check"))


def generate_unique_error_id():
    return str(uuid.uuid4())
