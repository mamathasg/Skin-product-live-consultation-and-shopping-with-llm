import os
import time
import json
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

import bcrypt
import pymysql.cursors
import requests
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    session, flash, jsonify, url_for
)
from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VideoGrant

from config import (
    get_db_connection,
    TWILIO_ACCOUNT_SID,
    TWILIO_API_KEY_SID,
    TWILIO_API_KEY_SECRET,
    GROQ_API_KEY,
)

# --------------------------------------------------
# BASIC APP & CONFIG
# --------------------------------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# Auto-reload templates in dev
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.cache = {}

# ---- Email (Mailtrap demo, plus Gmail for real reset) ----
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "sandbox.smtp.mailtrap.io")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "2525"))
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Gmail-based reset (you already configured this)
GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")


# --------------------------------------------------
# GENERIC HELPERS
# --------------------------------------------------
@app.after_request
def add_header(response):
    """Disable caching (useful while actively developing)."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.context_processor
def override_url_for():
    """Append timestamp to static URLs to bust cache."""
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == "static":
        filename = values.get("filename")
        if filename:
            values["v"] = int(time.time())
    return url_for(endpoint, **values)


def send_password_reset_email(user_email, reset_link):
    """Send reset link via Gmail SMTP."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "GlowCare Password Reset Request"
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = user_email

    text = f"""
Hi,
We received a request to reset your GlowCare account password.
Please click the link below to reset it:
{reset_link}

If you didn't request this, please ignore this email.
"""
    msg.attach(MIMEText(text, "plain", "utf-8"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, user_email, msg.as_string())
        print(f"✅ Email sent successfully to {user_email}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")


# --------------------------------------------------
# HOME
# --------------------------------------------------
@app.route("/")
def home():
    print(">>> Rendering home.html <<<")
    return render_template("home.html")


# --------------------------------------------------
# CUSTOMER AUTH (SIGNUP / LOGIN / FORGOT / RESET)
# --------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"].encode("utf-8")
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO customer (cust_name, cust_email, cust_password) "
                "VALUES (%s, %s, %s)",
                (name, email, hashed_pw),
            )
            conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect("/login")
        except Exception as e:
            flash("Error: " + str(e), "danger")
        finally:
            cursor.close()
            conn.close()
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode("utf-8")

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM customer WHERE cust_email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password, user["cust_password"].encode("utf-8")):
            session["user"] = user["cust_name"]
            session["email"] = user["cust_email"]
            session["user_id"] = user["cust_id"]
            flash(f"Welcome back, {user['cust_name']}!", "success")
            return redirect("/browse")
        else:
            flash("Invalid credentials. Try again.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect("/login")


@app.route("/forgot_password_customer", methods=["GET", "POST"])
def forgot_password_customer():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM customer WHERE cust_email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            flash("No account found with that email.", "warning")
            return redirect(url_for("forgot_password_customer"))

        token = serializer.dumps(email, salt="password-reset-salt")
        reset_link = url_for("reset_password_customer", token=token, _external=True)
        send_password_reset_email(email, reset_link)
        flash("Password reset link has been sent to your email!", "success")

    return render_template("forgot_password.html")


@app.route("/reset_password_customer/<token>", methods=["GET", "POST"])
def reset_password_customer(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=900)
    except (SignatureExpired, BadSignature):
        flash("Invalid or expired password reset link.", "danger")
        return redirect(url_for("forgot_password_customer"))

    if request.method == "POST":
        new_password = request.form["password"].encode("utf-8")
        hashed_pw = bcrypt.hashpw(new_password, bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE customer SET cust_password=%s WHERE cust_email=%s",
            (hashed_pw, email),
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Password updated successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", email=email)


# --------------------------------------------------
# PRODUCT BROWSING & DETAILS
# --------------------------------------------------
@app.route("/browse")
def browse():
    search = request.args.get("search", "").strip()
    skin_type = request.args.get("skin_type", "")
    product_type = request.args.get("product_type", "")
    brand = request.args.get("brand", "")

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    query = "SELECT * FROM product WHERE 1=1"
    params = []

    if search:
        query += " AND (title LIKE %s OR brand LIKE %s)"
        params.extend([f"%{search}%", f"%{search}%"])
    if skin_type and skin_type != "All":
        query += " AND skin_type LIKE %s"
        params.append(f"%{skin_type}%")
    if product_type and product_type != "All":
        query += " AND product_type = %s"
        params.append(product_type)
    if brand and brand != "All":
        query += " AND brand = %s"
        params.append(brand)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.execute("SELECT DISTINCT product_type FROM product")
    product_types = [row["product_type"] for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT brand FROM product")
    brands = [row["brand"] for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT skin_type FROM product")
    skin_types = [row["skin_type"] for row in cursor.fetchall()]

    cursor.close()
    conn.close()

    return render_template(
        "browse.html",
        products=products,
        search=search,
        product_types=product_types,
        brands=brands,
        skin_types=skin_types,
        selected_filters={
            "product_type": product_type,
            "brand": brand,
            "skin_type": skin_type,
        },
    )


@app.route("/product/<int:prod_id>")
def product_detail(prod_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT * FROM product WHERE prod_id=%s", (prod_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect("/browse")

    return render_template("product_detail.html", product=product)


@app.route("/product_names")
def product_names():
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT DISTINCT title, brand FROM product LIMIT 100")
    results = cursor.fetchall()
    cursor.close()
    conn.close()

    suggestions = []
    for row in results:
        if row["title"]:
            suggestions.append(row["title"])
        if row["brand"] and row["brand"] not in suggestions:
            suggestions.append(row["brand"])

    return jsonify(suggestions)


# --------------------------------------------------
# CART + CHECKOUT + ORDERS
# --------------------------------------------------
@app.route("/add_to_cart/<int:prod_id>")
def add_to_cart(prod_id):
    if "user_id" not in session:
        flash("Please log in to add products to your cart.", "warning")
        return redirect(url_for("login"))

    if "cart" not in session:
        session["cart"] = []
    if "quantities" not in session:
        session["quantities"] = {}

    quantities = session["quantities"]

    if prod_id not in session["cart"]:
        session["cart"].append(prod_id)
        quantities[str(prod_id)] = 1
        flash("Product added to cart!", "success")
    else:
        quantities[str(prod_id)] = quantities.get(str(prod_id), 0) + 1
        flash("Quantity updated in cart.", "info")

    session["quantities"] = quantities
    session.modified = True
    return redirect(url_for("product_detail", prod_id=prod_id))


@app.route("/remove_item/<int:prod_id>", methods=["POST"])
def remove_item(prod_id):
    if "cart" in session and prod_id in session["cart"]:
        session["cart"].remove(prod_id)
        if "quantities" in session and str(prod_id) in session["quantities"]:
            del session["quantities"][str(prod_id)]
        session.modified = True
    flash("Item removed from cart.", "info")
    return redirect("/cart")


@app.route("/cart")
def cart():
    if "cart" not in session or not session["cart"]:
        return render_template("cart.html", cart_items=[])

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    format_strings = ",".join(["%s"] * len(session["cart"]))
    cursor.execute(
        f"SELECT * FROM product WHERE prod_id IN ({format_strings})",
        tuple(session["cart"]),
    )
    cart_items = cursor.fetchall()
    cursor.close()
    conn.close()

    quantities = session.get("quantities", {})
    total = 0
    for item in cart_items:
        qty = quantities.get(str(item["prod_id"]), 1)
        item["quantity"] = qty
        total += float(item["price"]) * qty

    return render_template("cart.html", cart_items=cart_items, total=total)


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    if "user_id" not in session:
        flash("Please log in to continue checkout.", "warning")
        return redirect("/login")

    if "cart" not in session or not session["cart"]:
        flash("Your cart is empty!", "warning")
        return redirect("/browse")

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    format_strings = ",".join(["%s"] * len(session["cart"]))
    cursor.execute(
        f"SELECT * FROM product WHERE prod_id IN ({format_strings})",
        tuple(session["cart"]),
    )
    cart_items = cursor.fetchall()
    cursor.close()
    conn.close()

    quantities = session.get("quantities", {})
    subtotal = sum(
        float(item["price"]) * quantities.get(str(item["prod_id"]), 1)
        for item in cart_items
    )
    shipping = 6.99 if subtotal < 50 else 0.00
    discount = 1.40 if subtotal > 30 else 0.00
    tax = round(subtotal * 0.1, 2)
    total = round(subtotal + shipping - discount + tax, 2)
    total_items = sum(quantities.values())

    if request.method == "POST":
        customer_id = session.get("user_id")
        if not customer_id:
            flash("Error: Unable to identify your account. Please re-login.", "danger")
            return redirect("/login")

        full_name = request.form["full_name"]
        street_address = request.form["street"]
        city = request.form["city"]
        state = request.form["state"]
        zip_code = request.form["zip"]
        country = request.form["country"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO orders 
            (cust_id, total_amount, ord_quantity, full_name, street_address, city, 
             state, zip_code, country, ord_date, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
        """,
            (
                customer_id,
                total,
                total_items,
                full_name,
                street_address,
                city,
                state,
                zip_code,
                country,
                "Placed",
            ),
        )
        conn.commit()
        conn.close()

        flash("Order placed successfully! You’ll receive an email confirmation soon.", "success")
        session.pop("cart", None)
        session.pop("quantities", None)
        return redirect("/browse")

    return render_template(
        "checkout.html",
        cart_items=cart_items,
        subtotal=subtotal,
        shipping=shipping,
        discount=discount,
        tax=tax,
        total=total,
    )


@app.route("/my_orders")
def my_orders():
    if "user_id" not in session:
        flash("Please log in to view your orders.", "warning")
        return redirect("/login")

    cust_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute(
        """
        SELECT ord_id, total_amount, ord_quantity, full_name, street_address, city, 
               state, zip_code, country, ord_date, status
        FROM orders 
        WHERE cust_id = %s 
        ORDER BY ord_date DESC
    """,
        (cust_id,),
    )
    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("my_orders.html", orders=orders)


# --------------------------------------------------
# CONSULTATION BOOKING (CUSTOMER SIDE)
# --------------------------------------------------
@app.route("/consultation", methods=["GET", "POST"])
def consultation():
    if "user_id" not in session:
        flash("Please log in to book a consultation.", "warning")
        return redirect(url_for("login"))

    # ------ BOOKING ------
    if request.method == "POST":
        customer_id = session["user_id"]
        dermatologist_id = int(request.form["dermatologist_id"])
        selected_date = request.form["consult_date"]  # YYYY-MM-DD
        selected_time = request.form["consult_time"]  # HH:MM
        pay_method = request.form["pay_method"]
        amount = 20.00

        try:
            consult_datetime = datetime.strptime(
                f"{selected_date} {selected_time}", "%Y-%m-%d %H:%M"
            )
        except ValueError:
            flash("Invalid date or time selected.", "danger")
            return redirect(url_for("consultation"))

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        cursor.execute(
            """
            SELECT consult_id
            FROM consultation
            WHERE dermatologist_id = %s
              AND consult_date = %s
        """,
            (dermatologist_id, consult_datetime),
        )
        existing = cursor.fetchone()
        if existing:
            cursor.close()
            conn.close()
            flash("That time slot has just been booked. Please choose another.", "warning")
            return redirect(url_for("consultation"))

        cursor.execute(
            """
            INSERT INTO consultation 
                (customer_id, dermatologist_id, payment_status, consult_date)
            VALUES (%s, %s, %s, %s)
        """,
            (customer_id, dermatologist_id, "Pending", consult_datetime),
        )
        conn.commit()
        consult_id = cursor.lastrowid

        transaction_id = f"TXN{random.randint(100000, 999999)}"
        paid_at = datetime.now()
        payment_status = "Paid"

        cursor.execute(
            """
            INSERT INTO payment
            (pay_method, cust_id, consult_id, amount, payment_status, paid_at, transaction_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
            (
                pay_method,
                customer_id,
                consult_id,
                amount,
                payment_status,
                paid_at,
                transaction_id,
            ),
        )
        conn.commit()

        cursor.execute(
            "UPDATE consultation SET payment_status=%s WHERE consult_id=%s",
            (payment_status, consult_id),
        )
        conn.commit()

        cursor.execute(
            "SELECT dermatologist_name FROM dermatologist WHERE dermatologist_id=%s",
            (dermatologist_id,),
        )
        derm = cursor.fetchone()

        cursor.close()
        conn.close()

        live_link = url_for("live_consultation", consult_id=consult_id, _external=True)
        flash(
            f"Payment successful (${amount}). Consultation confirmed with "
            f"{derm['dermatologist_name']} at {selected_time}. "
            f"<a href='{live_link}' class='btn btn-success btn-sm mt-2'>Join Live Session</a>",
            "success",
        )
        return redirect(url_for("consultation"))

    # ------ PAGE RENDER ------
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute(
        "SELECT dermatologist_id, dermatologist_name "
        "FROM dermatologist ORDER BY dermatologist_name"
    )
    dermatologists = cursor.fetchall()

    cursor.execute(
        """
        SELECT c.consult_id,
               c.consult_date,
               c.payment_status,
               d.dermatologist_name
        FROM consultation c
        JOIN dermatologist d ON c.dermatologist_id = d.dermatologist_id
        WHERE c.customer_id = %s
        ORDER BY c.consult_date DESC
    """,
        (session["user_id"],),
    )
    previous_consults = cursor.fetchall()

    cursor.close()
    conn.close()

    now_dt = datetime.now()
    for c in previous_consults:
        dt = c["consult_date"]
        c["is_future"] = dt > now_dt + timedelta(minutes=10)
        c["is_expired"] = dt < now_dt - timedelta(hours=1)
        c["can_join"] = (dt - timedelta(minutes=10)) <= now_dt <= (dt + timedelta(hours=1))

    return render_template(
        "consultation.html",
        dermatologists=dermatologists,
        previous_consults=previous_consults,
    )


@app.route("/available_slots/<int:derm_id>")
def available_slots(derm_id):
    date_str = request.args.get("date")
    if not date_str:
        date_str = datetime.today().strftime("%Y-%m-%d")

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    cursor.execute(
        "SELECT dermatologist_avail FROM dermatologist WHERE dermatologist_id=%s",
        (derm_id,),
    )
    derm = cursor.fetchone()

    if not derm or not derm["dermatologist_avail"]:
        cursor.close()
        conn.close()
        return jsonify([])

    all_slots = [
        s.strip() for s in derm["dermatologist_avail"].split(",") if s.strip()
    ]

    cursor.execute(
        """
        SELECT TIME(consult_date) AS booked_time
        FROM consultation
        WHERE dermatologist_id=%s
          AND DATE(consult_date)=%s
    """,
        (derm_id, date_str),
    )
    booked_rows = cursor.fetchall()
    cursor.close()
    conn.close()

    booked_times = []
    for row in booked_rows:
        bt = row["booked_time"]
        if bt:
            try:
                booked_times.append(bt.strftime("%H:%M"))
            except Exception:
                continue

    available = [slot for slot in all_slots if slot not in booked_times]
    return jsonify(available)


# --------------------------------------------------
# LIVE CONSULTATION (TWILIO)
# --------------------------------------------------
@app.route("/consultation/live/<int:consult_id>", endpoint="live_consultation")
def live_consultation(consult_id):
    if "user_id" not in session and "derm_id" not in session:
        flash("Please log in to join your consultation.", "warning")
        return redirect("/login")

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # Figure out who is joining
    if "derm_id" in session:
        cursor.execute(
            """
            SELECT c.consult_date, cust.cust_name, d.dermatologist_name
            FROM consultation c
            JOIN customer cust ON c.customer_id = cust.cust_id
            JOIN dermatologist d ON c.dermatologist_id = d.dermatologist_id
            WHERE c.consult_id = %s AND c.dermatologist_id = %s
            """,
            (consult_id, session["derm_id"]),
        )
        role = "derm"
        identity = session.get("derm_name", f"derm_{session['derm_id']}")
    else:
        cursor.execute(
            """
            SELECT c.consult_date, d.dermatologist_name, cust.cust_name
            FROM consultation c
            JOIN dermatologist d ON c.dermatologist_id = d.dermatologist_id
            JOIN customer cust ON c.customer_id = cust.cust_id
            WHERE c.consult_id = %s AND c.customer_id = %s
            """,
            (consult_id, session["user_id"]),
        )
        role = "user"
        identity = session.get("user", f"user_{session['user_id']}")

    consult = cursor.fetchone()
    cursor.close()
    conn.close()

    # No matching consultation for this user/derm
    if not consult:
        flash("Consultation not found or unauthorized access.", "danger")
        if role == "derm":
            return redirect(url_for("derm_appointments"))
        else:
            return redirect(url_for("consultation"))

    # ✅ consult_time is always set here (outside the if above)
    consult_time = consult["consult_date"]

    # Normalize to datetime if it comes as string
    if isinstance(consult_time, str):
        try:
            consult_time = datetime.strptime(consult_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            consult_time = datetime.strptime(consult_time, "%Y-%m-%dT%H:%M")

    now_time = datetime.now()

    # 👩‍⚕️ Dermatologist: can join only at or AFTER scheduled time, until +1 hour
    if role == "derm":
        if now_time < consult_time:
            flash("You can join the session only at the scheduled time.", "warning")
            return redirect(request.referrer or url_for("derm_appointments"))

    # 👤 Patient: can join from 10 minutes BEFORE scheduled time, until +1 hour
    else:
        if now_time < consult_time - timedelta(minutes=10):
            flash("You can join only 10 minutes before the session.", "warning")
            return redirect(request.referrer or url_for("consultation"))

    # For both: session expires 1 hour after start
    if now_time > consult_time + timedelta(hours=1):
        flash("This consultation session has expired.", "danger")
        if role == "derm":
            return redirect(request.referrer or url_for("derm_appointments"))
        else:
            return redirect(request.referrer or url_for("consultation"))

    # Generate Twilio access token and render room
    room_name = f"consult_{consult_id}"
    token = AccessToken(
        TWILIO_ACCOUNT_SID,
        TWILIO_API_KEY_SID,
        TWILIO_API_KEY_SECRET,
        identity=identity,
    )
    token.add_grant(VideoGrant(room=room_name))
    access_token = token.to_jwt()

    return render_template(
        "live_consultation.html",
        access_token=access_token,
        room_name=room_name,
        user_name=identity,
        role=role,
    )


# --------------------------------------------------
# DERMATOLOGIST AUTH
# --------------------------------------------------
@app.route("/derm/login", methods=["GET", "POST"])
def derm_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode("utf-8")

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM dermatologist WHERE dermatologist_email=%s", (email,)
        )
        derm = cursor.fetchone()
        cursor.close()
        conn.close()

        if derm and bcrypt.checkpw(
            password, derm["dermatologist_password"].encode("utf-8")
        ):
            session["derm_id"] = derm["dermatologist_id"]
            session["derm_name"] = derm["dermatologist_name"]
            flash(f"Welcome, {derm['dermatologist_name']}!", "success")
            return redirect("/derm/dashboard")
        else:
            flash("Invalid email or password", "danger")
    return render_template("derm_login.html")


@app.route("/derm/logout")
def derm_logout():
    session.pop("derm_id", None)
    session.pop("derm_name", None)
    flash("You have been logged out.", "info")
    return redirect("/derm/login")


# --------------------------------------------------
# DERMATOLOGIST DASHBOARD
# --------------------------------------------------
@app.route("/derm/dashboard")
def derm_dashboard():
    if "derm_id" not in session:
        flash("Please log in first.", "warning")
        return redirect("/derm/login")

    derm_id = session["derm_id"]

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    # ---------- Today's schedule ----------
    cursor.execute(
        """
        SELECT c.consult_id,
               c.consult_date,
               c.payment_status,
               cust.cust_name
        FROM consultation c
        JOIN customer cust ON c.customer_id = cust.cust_id
        WHERE c.dermatologist_id = %s
          AND DATE(c.consult_date) = CURDATE()
        ORDER BY c.consult_date
        """,
        (derm_id,),
    )
    todays_schedule = cursor.fetchall()

    now_dt = datetime.now()
    for row in todays_schedule:
        dt = row["consult_date"]
        row["can_join"] = (dt - timedelta(minutes=10)) <= now_dt <= (dt + timedelta(hours=1))
        row["is_future"] = now_dt < (dt - timedelta(minutes=10))
        row["is_past"] = now_dt > (dt + timedelta(hours=1))

    today_appointments = len(todays_schedule)

    # ---------- Summary numbers ----------
    cursor.execute(
        """
        SELECT COUNT(DISTINCT customer_id) AS total_patients
        FROM consultation
        WHERE dermatologist_id = %s
        """,
        (derm_id,),
    )
    total_patients = cursor.fetchone()["total_patients"] or 0

    cursor.execute(
        """
        SELECT COUNT(*) AS upcoming_count
        FROM consultation
        WHERE dermatologist_id = %s
          AND consult_date >= NOW()
        """,
        (derm_id,),
    )
    upcoming_count = cursor.fetchone()["upcoming_count"] or 0

    # ---------- Analytics for last 7 days ----------
    cursor.execute(
        """
        SELECT DATE(consult_date) AS day,
               COUNT(*) AS consults,
               COUNT(DISTINCT customer_id) AS patients
        FROM consultation
        WHERE dermatologist_id = %s
          AND consult_date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
        GROUP BY DATE(consult_date)
        ORDER BY day
        """,
        (derm_id,),
    )
    analytics_rows = cursor.fetchall()

    cursor.close()
    conn.close()

    analytics_labels = [r["day"].strftime("%a") for r in analytics_rows]
    analytics_patients = [int(r["patients"]) for r in analytics_rows]
    analytics_consults = [int(r["consults"]) for r in analytics_rows]

    # ---------- Weekly overview numbers for the bottom-right card ----------
    week_total_consults = sum(int(r["consults"]) for r in analytics_rows) if analytics_rows else 0
    if analytics_rows:
        busiest_row = max(analytics_rows, key=lambda r: r["consults"])
        busiest_day_label = busiest_row["day"].strftime("%A")
        avg_consults_per_day = round(week_total_consults / len(analytics_rows), 1)
    else:
        busiest_day_label = "No data yet"
        avg_consults_per_day = 0

    return render_template(
        "derm_dashboard.html",
        derm_name=session["derm_name"],
        today_appointments=today_appointments,
        total_patients=total_patients,
        upcoming_count=upcoming_count,
        todays_schedule=todays_schedule,
        analytics_labels=analytics_labels,
        analytics_patients=analytics_patients,
        analytics_consults=analytics_consults,
        week_total_consults=week_total_consults,
        avg_consults_per_day=avg_consults_per_day,
        busiest_day_label=busiest_day_label,
    )



# --------------------------------------------------
# DERMATOLOGIST APPOINTMENTS PAGE
# --------------------------------------------------
# --------------------------------------------------
# DERMATOLOGIST APPOINTMENTS PAGE
# --------------------------------------------------
@app.route("/derm/appointments")
def derm_appointments():
    if "derm_id" not in session:
        flash("Please log in first.", "warning")
        return redirect("/derm/login")

    derm_id = session["derm_id"]

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute(
        """
        SELECT c.consult_id, c.consult_date, c.payment_status,
               c.derm_notes, cust.cust_name
        FROM consultation c
        JOIN customer cust ON c.customer_id = cust.cust_id
        WHERE c.dermatologist_id = %s
        ORDER BY c.consult_date DESC
        """,
        (derm_id,),
    )
    consults = cursor.fetchall()
    cursor.close()
    conn.close()

    now = datetime.now()
    for c in consults:
        dt = c["consult_date"]
        c["is_expired"] = dt < now - timedelta(hours=1)
        c["is_completed"] = dt < now - timedelta(hours=1)
        # join allowed from 10 min before until 1h after
        c["can_join"] = (dt - timedelta(minutes=10)) <= now <= (dt + timedelta(hours=1))

    return render_template("derm_appointments.html", consults=consults, now=now)

# --------------------------------------------------
# DERMATOLOGIST NOTES + SLOTS + PASSWORD RESET
# --------------------------------------------------
@app.route("/derm/add_note/<int:consult_id>", methods=["POST"])
def derm_add_note(consult_id):
    if "derm_id" not in session:
        return jsonify({"success": False, "msg": "Unauthorized"}), 403

    note = request.form.get("note", "").strip()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE consultation
        SET derm_notes = %s
        WHERE consult_id = %s AND dermatologist_id = %s
    """,
        (note, consult_id, session["derm_id"]),
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "msg": "Note saved successfully!"})


@app.route("/derm/slots", methods=["GET", "POST"])
def derm_slots():
    if "derm_id" not in session:
        flash("Please log in first.", "warning")
        return redirect("/derm/login")

    derm_id = session["derm_id"]
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    if request.method == "POST":
        new_slots = request.form["slots"]
        cursor.execute(
            "UPDATE dermatologist SET dermatologist_avail=%s WHERE dermatologist_id=%s",
            (new_slots, derm_id),
        )
        conn.commit()
        flash("Availability updated successfully!", "success")
        return redirect("/derm/slots")

    cursor.execute(
        "SELECT dermatologist_avail FROM dermatologist WHERE dermatologist_id=%s",
        (derm_id,),
    )
    derm = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template(
        "derm_slots.html", slots=derm["dermatologist_avail"] if derm else ""
    )


@app.route("/derm/forgot_password", methods=["GET", "POST"])
def derm_forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM dermatologist WHERE dermatologist_email=%s", (email,)
        )
        derm = cursor.fetchone()
        cursor.close()
        conn.close()

        if not derm:
            flash("No dermatologist found with that email.", "warning")
            return redirect(url_for("derm_forgot_password"))

        token = serializer.dumps(email, salt="derm-reset-salt")
        reset_link = url_for("derm_reset_password", token=token, _external=True)
        print(f"🔗 Dermatologist reset link: {reset_link}")  # demo
        flash("Simulated: Password reset link printed in console.", "info")

    return render_template("derm_forgot_password.html")


@app.route("/derm/reset_password/<token>", methods=["GET", "POST"])
def derm_reset_password(token):
    try:
        email = serializer.loads(token, salt="derm-reset-salt", max_age=900)
    except (SignatureExpired, BadSignature):
        flash("Invalid or expired link.", "danger")
        return redirect(url_for("derm_forgot_password"))

    if request.method == "POST":
        new_password = request.form["password"].encode("utf-8")
        hashed_pw = bcrypt.hashpw(new_password, bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE dermatologist SET dermatologist_password=%s "
            "WHERE dermatologist_email=%s",
            (hashed_pw, email),
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Password reset successful! Please log in.", "success")
        return redirect("/derm/login")

    return render_template("derm_reset_password.html", email=email)


# --------------------------------------------------
# GLOWCARE AI ASSISTANT (GROQ LLM)
# --------------------------------------------------
@app.route("/ask_llm", methods=["POST"])
def ask_llm():
    data = request.get_json()
    question = data.get("question", "").strip()

    if not question:
        return jsonify({"reply": "Please type a question."})

    user_id = session.get("user_id")
    cust_name = session.get("user")
    customer_email = session.get("email")

    def fetch_user_orders():
        if not user_id:
            return []
        conn = get_db_connection()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(
            """
            SELECT ord_id, total_amount, ord_date, status
            FROM orders 
            WHERE cust_id=%s 
            ORDER BY ord_date DESC
        """,
            (user_id,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows

    def fetch_user_consultations():
        if not user_id:
            return []
        conn = get_db_connection()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(
            """
            SELECT c.consult_id, c.consult_date, c.payment_status,
                   d.dermatologist_name
            FROM consultation c
            JOIN dermatologist d ON c.dermatologist_id = d.dermatologist_id
            WHERE c.customer_id=%s
            ORDER BY c.consult_date DESC
        """,
            (user_id,),
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows

    def fetch_dermatologists():
        conn = get_db_connection()
        cur = conn.cursor(pymysql.cursors.DictCursor)
        cur.execute(
            """
            SELECT dermatologist_id, dermatologist_name, dermatologist_avail
            FROM dermatologist
        """
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows

    ai_context = {
        "is_logged_in": bool(user_id),
        "customer_id": user_id,
        "customer_name": cust_name,
        "customer_email": customer_email,
        "orders": fetch_user_orders() if user_id else [],
        "consultations": fetch_user_consultations() if user_id else [],
        "dermatologists": fetch_dermatologists(),
    }

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    system_prompt = f"""
You are GLOWCARE AI — an intelligent assistant inside a dermatology e-commerce app.

You have live access to:
- user profile (name, email)
- product list
- user orders
- user consultations
- available dermatologists + their slots

NEVER hallucinate data. If something is missing, say: "I couldn't find that."

Here is the real user context (DO NOT REVEAL RAW JSON TO THE USER):

{json.dumps(ai_context, default=str)}

Your abilities:
1. Order tracking (find their orders, dates, amounts, status)
2. Product lookup (by name or brand)
3. Dermatologist info and availability
4. Consultation help and next appointment
5. Ingredient explanations and skin routine tips
6. Product recommendations by skin type
7. Friendly chat

If the user is NOT logged in and they ask for personal info,
respond with: "Please log in to access your personal data securely."

Never invent products, orders, or appointments.
"""

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
        "temperature": 0.4,
    }

    groq_response = requests.post(url, json=payload, headers=headers)

    try:
        result = groq_response.json()
        reply = result["choices"][0]["message"]["content"]
    except Exception as e:
        return jsonify({"reply": f"⚠️ AI Error: {str(e)}"})

    return jsonify({"reply": reply})


# --------------------------------------------------
# RUN APP
# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
