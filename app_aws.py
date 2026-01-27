# app_aws.py - COMPLETE MARKETING PLATFORM WITH DYNAMODB + SNS

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import boto3
from datetime import datetime
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "aws-ai-marketing-platform-2026-super-secret-key"
)

# ---------------- AWS CONFIG ----------------
REGION = "us-east-1"
dynamodb = boto3.resource("dynamodb", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

# ---------------- DYNAMODB TABLES ----------------
# PKs:
# Users -> email
# Admin -> email
# Products -> category
# Campaigns -> campaign_id

users_table = dynamodb.Table("Users")
admin_table = dynamodb.Table("Admin")
products_table = dynamodb.Table("Products")
campaigns_table = dynamodb.Table("Campaigns")

# ---------------- SNS ----------------
SNS_TOPIC_ARN = os.environ.get(
    "SNS_TOPIC_ARN",
    "arn:aws:sns:us-east-1:YOUR-ACCOUNT-ID:marketing-notifications"
)

# ---------------- UTILITIES ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def send_sns_notification(subject, message):
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS limit safety
            Message=message
        )
    except Exception as e:
        print("SNS Error:", e)

# ---------------- HOME & PRODUCT TRACKING ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        data = request.json or {}

        user_email = session.get("user_email", data.get("user_email", "guest"))
        product_name = data.get("product_name", "unknown")
        category = data.get("category", "general")
        action = data.get("action", "search")

        # SAFE DynamoDB update (validated syntax)
        products_table.update_item(
            Key={"category": category},
            UpdateExpression="""
                SET products = list_append(if_not_exists(products, :empty), :prod),
                    interactions = if_not_exists(interactions, :zero) + :inc
            """,
            ExpressionAttributeValues={
                ":prod": [product_name],
                ":empty": [],
                ":inc": 1,
                ":zero": 0
            }
        )

        send_sns_notification(
            f"Product {action.title()}",
            f"User: {user_email}\nProduct: {product_name}\nCategory: {category}\nTime: {datetime.now().isoformat()}"
        )

        return jsonify({"status": "success"})

    return render_template("index.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

# ---------------- USER AUTH ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = hash_password(request.form["password"])
        name = request.form["name"]

        if "Item" in users_table.get_item(Key={"email": email}):
            flash("User already exists!")
            return render_template("signup.html")

        users_table.put_item(Item={
            "email": email,
            "password": password,
            "name": name,
            "created_at": datetime.now().isoformat(),
            "role": "user"
        })

        send_sns_notification("New User Signup", f"{name} ({email}) registered")
        flash("Signup successful! Please login.")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = hash_password(request.form["password"])

        res = users_table.get_item(Key={"email": email})
        if "Item" in res and res["Item"]["password"] == password:
            session["user_email"] = email
            session["user_name"] = res["Item"]["name"]
            return redirect(url_for("home"))

        flash("Invalid credentials!")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------------- ADMIN ----------------
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        password = hash_password(request.form["password"])

        res = admin_table.get_item(Key={"email": email})
        if "Item" in res and res["Item"]["password"] == password:
            session["admin_email"] = email
            session["admin_name"] = res["Item"].get("name", "Admin")
            return redirect(url_for("admin_home"))

        flash("Invalid admin credentials!")

    return render_template("admin_login.html")

@app.route("/admin_home")
def admin_home():
    if "admin_email" not in session:
        return redirect(url_for("admin_login"))

    users = users_table.scan().get("Items", [])
    campaigns = campaigns_table.scan().get("Items", [])
    products = products_table.scan().get("Items", [])

    return render_template(
        "admin_home.html",
        total_users=len(users),
        total_campaigns=len(campaigns),
        total_products=len(products),
        active_campaigns=len([c for c in campaigns if c.get("status") == "active"]),
        total_messages=sum(p.get("interactions", 0) for p in products),
        total_revenue=len(campaigns) * 1000
    )

# ---------------- CAMPAIGNS ----------------
@app.route("/create_campaign", methods=["POST"])
def create_campaign():
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    campaign_id = f"camp_{int(datetime.now().timestamp())}"

    campaigns_table.put_item(Item={
        "campaign_id": campaign_id,
        "name": data["name"],
        "target_product": data["product"],
        "target_users": data.get("users", []),
        "status": "active",
        "budget": data.get("budget", 0),
        "created_at": datetime.now().isoformat(),
        "created_by": session["admin_email"],
        "metrics": {"sent": 0, "clicks": 0, "conversions": 0}
    })

    send_sns_notification("New Campaign", f"Campaign {data['name']} launched")
    return jsonify({"status": "success", "campaign_id": campaign_id})

# ---------------- PRODUCT APIs ----------------
@app.route("/api/search_product", methods=["POST"])
def search_product():
    data = request.json or {}
    category = data.get("category", "general")

    products_table.update_item(
        Key={"category": category},
        UpdateExpression="SET searches = if_not_exists(searches, :z) + :i",
        ExpressionAttributeValues={":i": 1, ":z": 0}
    )

    return jsonify({"success": True})

@app.route("/api/click_product", methods=["POST"])
def click_product():
    user_email = session.get("user_email", "guest")
    send_sns_notification("Product Click", f"{user_email} clicked a product")
    return jsonify({"success": True})

# ---------------- RUN ----------------
if __name__ == "__main__":
    print("🚀 AWS Marketing Platform Starting...")
    app.run(host="0.0.0.0", port=5000, debug=False)

