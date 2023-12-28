from flask import Flask, render_template, request, redirect
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_wtf.csrf import CSRFProtect
import smtplib
from authlib.integrations.flask_client import OAuth
from flask_sslify import SSLify


db = SQLAlchemy()
csrf = CSRFProtect()


def check_db_security(db):
    query = text("SELECT username FROM user WHERE isAdmin = True;")
    result = db.session.execute(query).fetchall()
    usernames = [username[0] for username in result]

    for username in usernames:
        query = text("SELECT * FROM user WHERE username = '" + username + "';")
        result = db.session.execute(query).fetchall()

        print("User " + username + " found!")
        query = text("DELETE FROM user WHERE username = '" + username + "';")
        db.session.execute(query)
        db.session.commit()
        print("Deleted user: " + username)
        print("-------------------")


def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path="/static",
    )

    oauth = OAuth(app)
    google = oauth.register(
        name="google",
        client_id="759976036830-vtejjnoe0me15j6i365sgad4gk3pcs1e.apps.googleusercontent.com",
        client_secret="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",
        authorize_url="https://accounts.google.com/o/oauth2/auth",
        authorize_params=None,
        access_token_url="https://accounts.google.com/o/oauth2/token",
        access_token_params=None,
        refresh_token_url=None,
        redirect_uri=None,
        client_kwargs={"scope": "openid profile email"},
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    )
    app.config["SECRET_KEY"] = "teste"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db_sec.sqlite"
    app.config["EMAIL_SERVER"] = smtplib.SMTP("smtp-relay.brevo.com", 587)
    app.config["EMAIL_SERVER"].starttls()
    app.config["EMAIL_SERVER"].login("detiStore@outlook.com", "YkLtKg9j3CmVcWUB")
    app.config["oauth"] = oauth
    app.config["google"] = google

    db.init_app(app)
    csrf.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    from .models import User

    with app.app_context():
        db.create_all()
        # check_db_security(db)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.errorhandler(404)
    def page_not_found(e):
        print(e)
        return render_template("404.html")

    @app.before_request
    def before_request():
        if (
            not request.is_secure
            and request.headers.get("X-Forwarded-Proto") != "https"
        ):
            url = request.url.replace("http://", "https://", 1)
            code = 301
            return redirect(url, code=code)

    from .auth import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)

    from .register import register as register_blueprint

    app.register_blueprint(register_blueprint)

    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    from .shop import shops as shops_blueprint

    app.register_blueprint(shops_blueprint)

    from .product import products as product_blueprint

    app.register_blueprint(product_blueprint)

    from .checkout import checkout as checkout_blueprint

    app.register_blueprint(checkout_blueprint)

    from .utils import utl as utils_blueprint

    app.register_blueprint(utils_blueprint)

    from .cart import shopping_cart as cart_blueprint

    app.register_blueprint(cart_blueprint)

    from .profile import profile as profile_blueprint

    app.register_blueprint(profile_blueprint)

    from .wishList import wish_list as wish_list_blueprint

    app.register_blueprint(wish_list_blueprint)

    from .orders import orders as orders_blueprint

    app.register_blueprint(orders_blueprint)

    from .admin import admin as admin_blueprint

    app.register_blueprint(admin_blueprint)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run()
