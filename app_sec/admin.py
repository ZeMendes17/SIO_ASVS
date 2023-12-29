import datetime
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
import uuid
import logging
from .auth import recheck_login

logger = logging.getLogger(__name__)

admin = Blueprint("admin", __name__)


@login_required
@admin.route("/admin", methods=["GET", "POST"])
def admin_page():
    try:
        action = recheck_login()

        if action is not None:
            return action

        if not current_user.isAdmin:
            return render_template("404.html")

        if request.method == "GET":
            query = text("SELECT * FROM product")
            products = db.session.execute(query).fetchall()

            return render_template("admin.html", products=products)

        elif request.method == "POST":
            if "sub_quant" in request.form:
                # how many different products are in the database
                query = text("SELECT COUNT(*) FROM product")
                count = db.session.execute(query).fetchone()[0]
                for i in range(1, count + 1):
                    add_qtt = request.form["quantity_" + str(i)]

                    if not add_qtt == "" and not int(add_qtt) <= 0:
                        query = text(
                            "UPDATE product SET quantity = quantity + :add_qtt WHERE id = :id"
                        )
                        db.session.execute(query, {"add_qtt": add_qtt, "id": i})
                        db.session.commit()
                        flash("Quantity updated for product " + str(i), "success")

                    elif not add_qtt == "":
                        flash("Invalid quantity in product " + str(i), "danger")

                return redirect(url_for("admin.admin_page"))

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
    return redirect(url_for("main.index"))


def generate_unique_error_id():
    return str(uuid.uuid4())
