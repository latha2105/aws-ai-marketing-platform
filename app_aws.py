from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import boto3
import uuid

# ---------------- BASIC APP SETUP ---------------- #
app = Flask(__name__)
app.secret_key = "aws-ai-marketing-platform-2026-secret-key"
AWS_REGION = "us-east-1"

# ---------------- AWS SETUP ---------------- #
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
sns = boto3.client("sns", region_name=AWS_REGION)

USER_TABLE = dynamodb.Table("UserTable")        # PK: email
ADMIN_TABLE = dynamodb.Table("AdminTable")      # PK: email
CAMPAIGN_TABLE = dynamodb.Table("CampaignsTable")  # PK: campaign_id

SNS_TOPIC_ARN = None  # set by test_app.py when using Moto

# ---------------- DECORATORS ---------------- #
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper

# ---------------- ROUTES (PAGES) ---------------- #
@app.route("/")
@app.route("/index")
@app.route("/index.html")
def index():
    return render_template("index.html")


@app.route("/login")
@app.route("/login.html")
def login():
    return render_template("login.html")


@app.route("/signup")
@app.route("/signup.html")
def signup():
    return render_template("signup.html")


@app.route("/about")
@app.route("/about.html")
def about():
    return render_template("about.html")


@app.route("/home")
@app.route("/home.html")
@login_required
def home():
    return render_template("home.html")

@app.route("/shop")
@app.route("/shop.html")
@login_required
def shop():
    return render_template("shop.html")

@app.route("/admin_login")
@app.route("/admin_login.html")
def admin_login():
    return render_template("admin_login.html")

# ---------------- ADMIN DASHBOARD ---------------- #
@app.route("/dashboard")
@app.route("/dashboard.html")
@admin_required
def dashboard():
    response = CAMPAIGN_TABLE.scan()
    campaigns = response.get("Items", [])
    return render_template("dashboard.html", campaigns=campaigns)


@app.route("/campaign_history")
@app.route("/campaign_history.html")
@admin_required
def campaign_history():
    response = CAMPAIGN_TABLE.scan()
    campaigns = response.get("Items", [])
    return render_template("campaign_history.html", campaigns=campaigns)

# ---------------- CAMPAIGN PAGE ---------------- #
@app.route("/campaign")
@app.route("/campaign.html")
@login_required
def campaign():
    return render_template("campaign.html")

# ---------------- FORM HANDLERS ---------------- #

# USER LOGIN
@app.route("/api/login-submit", methods=["POST"])
def login_submit():
    email = request.form.get("email", "").lower()
    password = request.form.get("password", "")

    user = USER_TABLE.get_item(Key={"email": email}).get("Item")
    if user and check_password_hash(user["password"], password):
        session["user_email"] = email
        session["role"] = "user"
        return redirect(url_for("shop"))

    admin = ADMIN_TABLE.get_item(Key={"email": email}).get("Item")
    if admin and check_password_hash(admin["password"], password):
        session["user_email"] = email
        session["role"] = "admin"
        return redirect(url_for("dashboard"))

    flash("Invalid credentials")
    return redirect(url_for("login"))


# USER SIGNUP
@app.route("/api/signup-submit", methods=["POST"])
def signup_submit():
    email = request.form.get("signupEmail", "").lower()
    password = request.form.get("signupPassword", "")
    confirm = request.form.get("confirmPassword", "")
    full_name = request.form.get("fullName", "")
    contact = request.form.get("contact", "")

    if password != confirm:
        flash("Passwords do not match")
        return redirect(url_for("signup"))

    if USER_TABLE.get_item(Key={"email": email}).get("Item"):
        flash("User already exists")
        return redirect(url_for("signup"))

    USER_TABLE.put_item(Item={
        "email": email,
        "password": generate_password_hash(password),
        "name": full_name,
        "contact": contact,
        "created_at": datetime.utcnow().isoformat()
    })

    flash("Signup successful. Please login.")
    return redirect(url_for("login"))


# ADMIN LOGIN
@app.route("/api/admin-login-submit", methods=["POST"])
def admin_login_submit():
    email = request.form.get("adminEmail", "").lower()
    password = request.form.get("adminPassword", "")

    admin = ADMIN_TABLE.get_item(Key={"email": email}).get("Item")
    if admin and check_password_hash(admin["password"], password):
        session["user_email"] = email
        session["role"] = "admin"
        return redirect(url_for("dashboard"))

    flash("Invalid admin credentials")
    return redirect(url_for("admin_login"))



# CREATE CAMPAIGN
@app.route("/api/generate-campaign", methods=["POST"])
@login_required
def generate_campaign():
    campaign_id = str(uuid.uuid4())
    interest = request.form.get("userInterests", "")

    CAMPAIGN_TABLE.put_item(Item={
        "campaign_id": campaign_id,
        "user_email": session["user_email"],
        "interest": interest,
        "status": "Active",
        "created_at": datetime.utcnow().isoformat()
    })

    return jsonify({"status": "success", "campaign_id": campaign_id})


# ---------------- LOGOUT ---------------- #
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------- RUN APP ---------------- #
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


