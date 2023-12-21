from flask import Blueprint, jsonify
from . import db
from .models import User, Product, Comment, Cart, Wishlist, Order, OrderProduct
from sqlalchemy import text
from werkzeug.security import generate_password_hash

utl = Blueprint("util", __name__)


@utl.route("/generate/database", methods=["GET"])
def generate_database():
    try:
        generate_users()
        generate_products()
        generate_comments()
        generate_carts()
        generate_wish_list()
        generate_orders()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/generate/users", methods=["GET"])
def generate_users():
    query = text("DELETE FROM user")
    db.session.execute(query)
    db.session.commit()
    users = [
        {
            "username": "admin",
            "password": generate_password_hash("admin1234"),
            "isAdmin": True,
            "name": "Admin",
            "email": "admin@gmail.com",
            "phone": "123456789",
            "security_question": "question1-Orange",
        },
        {
            "username": "user",
            "password": generate_password_hash("user1234"),
            "isAdmin": False,
            "name": "User",
            "email": "user@gmail.com",
            "phone": "987654321",
            "security_question": "question1-Black",
        },
    ]
    try:
        db.session.bulk_insert_mappings(User, users)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/generate/products", methods=["GET"])
def generate_products():
    query = text("DELETE FROM product")
    db.session.execute(query)
    db.session.commit()
    products = [
        {
            "name": "Mug",
            "price": 9.99,
            "quantity": 30,
            "image_name": "../static/images/products/mug.jpg",
            "description": "DETI mug for coffee or tea",
            "categorie": "miscellaneous",
        },
        {
            "name": "T-Shirt",
            "price": 19.99,
            "quantity": 20,
            "image_name": "../static/images/products/tshirt.jpg",
            "description": "DETI t-shirt for all occasions",
            "categorie": "clothing",
        },
        {
            "name": "Hoodie",
            "price": 29.99,
            "quantity": 10,
            "image_name": "../static/images/products/hoodie.jpg",
            "description": "DETI hoodie for all occasions",
            "categorie": "clothing",
        },
        {
            "name": "Polo",
            "price": 24.99,
            "quantity": 15,
            "image_name": "../static/images/products/polo.jpg",
            "description": "DETI polo for all occasions",
            "categorie": "clothing",
        },
        {
            "name": "Tote Bag",
            "price": 14.99,
            "quantity": 25,
            "image_name": "../static/images/products/tote.jpg",
            "description": "DETI tote bag, combines style and functionality, perfect for everyday use",
            "categorie": "accessories",
        },
    ]
    try:
        db.session.bulk_insert_mappings(Product, products)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/generate/comments", methods=["GET"])
def generate_comments():
    query = text("DELETE FROM comment")
    db.session.execute(query)
    db.session.commit()
    comments = [
        {
            "user_name": "António Mendes",
            "date": "01/10/2021",
            "comment": "I absolutely love my new mug! The design "
            + "is even more vibrant in person, and it's the perfect size for my morning coffee. Plus, it arrived quickly and was well-packaged!",
            "product_id": 1,
            "rating": 5,
        },
        {
            "user_name": "Leonor",
            "date": "14/02/2022",
            "comment": "The mug I received is nice, but there was a small chip on the rim. It might have happened during shipping. It would be great if the packaging could be improved to prevent this in the future. Otherwise, I like the design and the quality of the mug itself.",
            "product_id": 1,
            "rating": 3,
        },
        {
            "user_name": "CoffeeAddict007",
            "date": "03/01/2023",
            "comment": "I had an issue with my order, but the customer service was amazing. They responded promptly to my email and quickly resolved the problem. I now have my perfect mug, and I'm really impressed with their service. Thanks for going above and beyond!",
            "product_id": 1,
            "rating": 5,
        },
        {
            "user_name": "Maria",
            "date": "03/01/2021",
            "comment": "I'm so proud to wear this t-shirt with our department's logo. The quality of the shirt is fantastic, and the logo looks sharp. It's a great way to show my department pride and strike up conversations with fellow students. I'm very happy with this purchase!",
            "product_id": 2,
            "rating": 5,
        },
        {
            "user_name": "User122",
            "date": "04/03/2023",
            "comment": "I graduated from the engineering department a few years ago, and I had to get this t-shirt to reminisce about my university days. The shirt is comfortable, and the department's logo brings back some wonderful memories.",
            "product_id": 2,
            "rating": 4,
        },
        {
            "user_name": "John",
            "date": "05/08/2022",
            "comment": "This hoodie is a must-have! The warmth and comfort are perfect for those late-night study sessions. The department's logo looks fantastic!",
            "product_id": 3,
            "rating": 3,
        },
        {
            "user_name": "Mário",
            "date": "06/11/2022",
            "comment": "I couldn't resist getting this hoodie. It's a cozy reminder of my university days. The department's logo still holds a special place in my heart, and this hoodie lets me wear that pride. Great quality and very comfortable.",
            "product_id": 3,
            "rating": 2,
        },
        {
            "user_name": "Ana",
            "date": "07/09/2021",
            "comment": "I love this polo! It's perfect for casual Fridays at the office. The logo is subtle but still lets me show my department pride. The quality is excellent, and the shirt is very comfortable.",
            "product_id": 4,
            "rating": 5,
        },
        {
            "user_name": "Rui",
            "date": "08/12/2022",
            "comment": "I'm very happy with this polo. The quality is great, and the logo looks sharp.",
            "product_id": 4,
            "rating": 4,
        },
        {
            "user_name": "João",
            "date": "09/02/2023",
            "comment": "This tote bag is great! It's very spacious and sturdy. I use it for my groceries, and it can hold a lot of weight. The logo is a nice touch.",
            "product_id": 5,
            "rating": 5,
        },
    ]
    try:
        db.session.bulk_insert_mappings(Comment, comments)
        db.session.commit()

        query = text("SELECT * FROM product")
        products = db.session.execute(query).fetchall()
        for i in range(len(products)):
            product = Product.query.filter_by(id=products[i].id).first()
            comments = Comment.query.filter_by(product_id=product.id).all()
            num_ratings = len(comments)

            if num_ratings > 0:
                total_rating = sum(comment.rating for comment in comments)
                new_product_rating = total_rating / num_ratings

                product.rating = round(new_product_rating, 1)
                db.session.commit()

        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/generate/carts", methods=["GET", "POST"])
def generate_carts():
    query = text("DELETE FROM cart")
    db.session.execute(query)
    db.session.commit()
    carts = [
        {
            "customer_id": 1,
        },
        {
            "customer_id": 2,
        },
    ]
    try:
        db.session.bulk_insert_mappings(Cart, carts)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/generate/wish_list", methods=["GET", "POST"])
def generate_wish_list():
    query = text("DELETE FROM wishlist")
    db.session.execute(query)
    db.session.commit()
    wish_list = [
        {
            "customer_id": 1,
        },
        {
            "customer_id": 2,
        },
    ]
    try:
        db.session.bulk_insert_mappings(Wishlist, wish_list)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/generate/orders", methods=["GET", "POST"])
def generate_orders():
    # e orders for user
    query = text("DELETE FROM [order]")
    db.session.execute(query)
    db.session.commit()
    query = text("DELETE FROM order_product")
    db.session.execute(query)
    db.session.commit()
    orders = [
        {
            "order_number": 1,
            "customer_id": 2,
            "date": "01/10/2022",
            "tax": 3.99,
            "shipping_cost": 4.99,
            "tracking_number": "T5rLgPq3W7Yv",
            "shipping_address": "Rua do Campo Alegre, 1021, 4150-180 Porto",
            "billing_address": "Rua do Campo Alegre, 1021, 4150-180 Porto",
        },
        {
            "order_number": 2,
            "customer_id": 2,
            "date": "12/03/2023",
            "tax": 3.99,
            "shipping_cost": 4.99,
            "tracking_number": "aR6NpHj2MzFy",
            "shipping_address": "Rua do Campo Alegre, 1021, 4150-180 Porto",
            "billing_address": "Rua do Campo Alegre, 1021, 4150-180 Porto",
        },
    ]

    orderProducts = [
        {
            "order_id": 1,
            "product_id": 1,
            "quantity": 2,
            "price_each": 9.99,
        },
        {
            "order_id": 1,
            "product_id": 3,
            "quantity": 1,
            "price_each": 29.99,
        },
        {
            "order_id": 1,
            "product_id": 4,
            "quantity": 1,
            "price_each": 24.99,
        },
        {
            "order_id": 2,
            "product_id": 1,
            "quantity": 3,
            "price_each": 9.99,
        },
        {
            "order_id": 2,
            "product_id": 2,
            "quantity": 2,
            "price_each": 19.99,
        },
    ]

    try:
        db.session.bulk_insert_mappings(Order, orders)
        db.session.commit()
        db.session.bulk_insert_mappings(OrderProduct, orderProducts)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})


@utl.route("/clear/database", methods=["GET"])
def clear_database():
    query = text("DELETE FROM user;")
    db.session.execute(query)
    query = text("DELETE FROM product;")
    db.session.execute(query)
    query = text("DELETE FROM comment;")
    db.session.execute(query)
    query = text("DELETE FROM cart;")
    db.session.execute(query)
    query = text("DELETE FROM cart_product;")
    db.session.execute(query)
    query = text("DELETE FROM cart;")
    db.session.execute(query)
    query = text("DELETE FROM wishlist_product;")
    db.session.execute(query)
    query = text("DELETE FROM wishlist;")
    db.session.execute(query)
    query = text("DELETE FROM [order];")
    db.session.execute(query)
    query = text("DELETE FROM order_product;")
    db.session.execute(query)

    try:
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"success": False})
