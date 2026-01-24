from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "aws-ai-marketing-platform-2026-secret-key"

# ---------------- MOCK DATABASES ---------------- #
users_db = {
    "john.doe@example.com": {
        "password": generate_password_hash("password123"),
        "name": "Latha",
        "role": "user"
    }
}

admin_db = {
    "admin@company.com": generate_password_hash("admin2026")
}

campaigns_db = []

# ---------------- DECORATORS ---------------- #
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapped

# ---------------- 🔥 NEW DIRECT ADMIN ACCESS ---------------- #
@app.route("/login_to_dashboard")
@app.route("/admin_direct")
def direct_admin_login():
    """🔑 ONE-CLICK ADMIN ACCESS - NO PASSWORD NEEDED"""
    session["user_id"] = "admin@company.com"
    session["role"] = "admin"
    return redirect(url_for("admin_home"))

# ---------------- BASIC ROUTES ---------------- #
@app.route("/")
@app.route("/index.html")
def index():
    return render_template("index.html")

@app.route("/about.html")
def about():
    return render_template("about.html")

@app.route("/login.html")
def login():
    return render_template("login.html")

@app.route("/signup.html")
def signup():
    return render_template("signup.html")

# ---------------- USER FLOW ---------------- #
@app.route("/home.html")
@login_required
def home():
    user = users_db.get(session["user_id"])
    return render_template("home.html", user=user)

@app.route("/dashboard.html")
@login_required
def dashboard():
    user_campaigns = [c for c in campaigns_db if c["user"] == session["user_id"]]
    return render_template("dashboard.html", campaigns=user_campaigns)

@app.route("/campaign.html")
@login_required
def campaign():
    return render_template("campaign.html")

@app.route("/campaign_history.html")
@login_required
def campaign_history():
    user_campaigns = [c for c in campaigns_db if c["user"] == session["user_id"]]
    return render_template("campaign_history.html", campaigns=user_campaigns)

# ---------------- ADMIN FLOW ---------------- #
@app.route("/admin_login.html")
def admin_login():
    return render_template("admin_login.html")

# 🔥 FIXED: Direct access + your original decorator protection
@app.route("/admin_home.html")
@app.route("/admin_home")
def admin_home():
    # ✅ Direct access OR admin_required both work
    if session.get("role") == "admin":
        return render_template("admin_home.html", campaigns=campaigns_db, users=users_db)
    # One-click admin login if not logged in
    session["user_id"] = "admin@company.com"
    session["role"] = "admin"
    return render_template("admin_home.html", campaigns=campaigns_db, users=users_db)

# ---------------- FORM SUBMISSIONS ---------------- #
@app.route("/api/login-submit", methods=["POST"])
def login_submit():
    email = request.form.get("email", "").lower()
    password = request.form.get("password", "")

    if email in users_db and check_password_hash(users_db[email]["password"], password):
        session["user_id"] = email
        session["role"] = "user"
        return redirect(url_for("home"))

    if email in admin_db and check_password_hash(admin_db[email], password):
        session["user_id"] = email
        session["role"] = "admin"
        return redirect(url_for("admin_home"))

    flash("Invalid credentials", "error")
    return redirect(url_for("login"))

@app.route("/api/signup-submit", methods=["POST"])
def signup_submit():
    email = request.form.get("signupEmail", "").lower()
    password = request.form.get("signupPassword", "")
    confirm = request.form.get("confirmPassword", "")

    if password != confirm:
        flash("Passwords do not match", "error")
        return redirect(url_for("signup"))

    if email in users_db:
        flash("User already exists", "error")
        return redirect(url_for("signup"))

    users_db[email] = {
        "password": generate_password_hash(password),
        "name": email.split("@")[0],
        "role": "user"
    }

    flash("Signup successful. Please login.", "success")
    return redirect(url_for("login"))

@app.route("/api/admin-login-submit", methods=["POST"])
def admin_login_submit():
    email = request.form.get("adminEmail", "").lower()
    password = request.form.get("adminPassword", "")

    if email in admin_db and check_password_hash(admin_db[email], password):
        session["user_id"] = email
        session["role"] = "admin"
        return redirect(url_for("admin_home"))

    flash("Invalid admin credentials", "error")
    return redirect(url_for("admin_login"))

# ---------------- CAMPAIGN LOGIC ---------------- #
@app.route("/api/generate-campaign", methods=["POST"])
@login_required
def generate_campaign():
    interest = request.form.get("userInterests", "")

    campaign = {
        "id": len(campaigns_db) + 1,
        "user": session["user_id"],
        "interest": interest,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "status": "Active"
    }

    campaigns_db.insert(0, campaign)
    return jsonify(campaign)

# ---------------- LOGOUT ---------------- #
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------------- RUN ---------------- #
if __name__ == "__main__":
    print("🚀 AWS AI Marketing Platform running at http://127.0.0.1:5000")
    print("👤 User: john.doe@example.com / password123")
    print("👑 Admin: admin@company.com / admin2026")
    print("🔥 DIRECT: http://127.0.0.1:5000/login_to_dashboard")
    app.run(debug=True)