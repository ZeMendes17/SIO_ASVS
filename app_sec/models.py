from flask_login import UserMixin
from . import db

cart_product = db.Table(
    "cart_product",
    db.Column("cart_id", db.Integer, db.ForeignKey("cart.id")),
    db.Column("product_id", db.Integer, db.ForeignKey("product.id")),
    db.Column("quantity", db.Integer, default=1),
)

wishlist_product = db.Table(
    "wishlist_product",
    db.Column("wishlist_id", db.Integer, db.ForeignKey("wishlist.id")),
    db.Column("product_id", db.Integer, db.ForeignKey("product.id")),
)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(100))
    isAdmin = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(100))
    image = db.Column(db.String(20), nullable=False, default="default.jpg")
    security_question = db.Column(db.String(100))
    cart = db.relationship("Cart", backref="user")
    wishlist = db.relationship("Wishlist", backref="user")


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    products = db.relationship(
        "Product", secondary="cart_product", back_populates="carts"
    )


class Wishlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    products = db.relationship(
        "Product", secondary="wishlist_product", back_populates="wishlists"
    )


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    image_name = db.Column(db.String(100))
    description = db.Column(db.String(100))
    rating = db.Column(db.Float)
    categorie = db.Column(db.String(100))
    carts = db.relationship("Cart", secondary=cart_product, back_populates="products")
    wishlists = db.relationship(
        "Wishlist", secondary=wishlist_product, back_populates="products"
    )


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.Integer)
    customer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    date = db.Column(db.String(100))
    tax = db.Column(db.Float)
    shipping_cost = db.Column(db.Float)
    tracking_number = db.Column(db.String(100))
    shipping_address = db.Column(db.String(100))
    billing_address = db.Column(db.String(100))


class OrderProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"))
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    quantity = db.Column(db.Integer)
    price_each = db.Column(
        db.Float
    )  # as the price can change over time, we need to store it here


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    user_name = db.Column(db.String(100))
    date = db.Column(db.String(100))
    comment = db.Column(db.String(100))
    rating = db.Column(db.Integer)
