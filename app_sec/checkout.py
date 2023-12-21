from sqlite3 import IntegrityError
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import current_user, login_required
from .models import Order, OrderProduct
from sqlalchemy import text
from . import db
from datetime import date
import string
import random


checkout = Blueprint("checkout", __name__)
order_id = 1


@checkout.route("/checkout", methods=["GET"])
@login_required
def check():
    query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))
    cart = db.session.execute(query).fetchone()

    if cart is not None:
        query = text("SELECT COUNT(*) FROM cart_product WHERE cart_id =" + str(cart.id))
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
        print(product.id)
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

    # orders = Order.query.all()

    # for order in orders:
    #     print(f"Order ID: {order.id}")
    #     print(f"Customer ID: {order.customer_id}")
    #     print(f"Order Date: {order.order_date}")
    #     # Print other relevant fields from the Order table

    subtotal = sum(
        product.price * product_quantities[product.id]
        if product_quantities[product.id] is not None
        else 0
        for product in products
    )
    grand_total = subtotal + 3.99 + 4.99  # tax + shipping
    # shipping = request.form["shipping-option"]

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


@checkout.route("/form_checkout", methods=["POST"])
@login_required
def form_checkout():
    if request.method == "POST":
        address = request.form["address"]
        address2 = request.form["address2"]

        query = text("SELECT * FROM cart WHERE customer_id =" + str(current_user.id))
        cart = db.session.execute(query).fetchone()
        query = text(
            "SELECT * FROM product WHERE id IN (SELECT product_id FROM cart_product WHERE cart_id = "
            + str(cart.id)
            + ")"
        )
        products = db.session.execute(query).fetchall()


        product_quantities = {}

        for product in products:
            print(product.id)
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
        query = text("SELECT COUNT(*) FROM [order] WHERE customer_id =" + str(current_user.id))
        number_of_orders = db.session.execute(query).fetchone()[0]

        # Criar um novo Order
        new_order = Order(
            order_number=number_of_orders + 1,
            customer_id=current_user.id,
            date=date.today().strftime("%d/%m/%Y"),
            tax=3.99,
            shipping_cost=4.99,
            tracking_number=generate_tracking_number(),
            shipping_address=address,
            billing_address=address2,
        )

        try:
            # Verificar se há stock suficiente de cada produto
            for product in products:
                if product.quantity < product_quantities[product.id]:
                    flash("Not enough stock for product " + product.name + "!", "error")
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
                query = text("UPDATE product SET quantity = " + str(new_quantity) + " WHERE id = " + str(product.id))
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


def generate_tracking_number(length=12):
    characters = (
        string.ascii_letters + string.digits
    )  # All upper and lower case letters plus digits
    return "".join(random.choice(characters) for _ in range(length))
