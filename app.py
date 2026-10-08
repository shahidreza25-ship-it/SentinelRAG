from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import os
from agents.collector import collect_ioc
from rag.retriever import retrieve_ioc

app = Flask(__name__)

app.config["SECRET_KEY"] = "sentinelrag-secret-key"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(BASE_DIR, "database", "sentinelrag.db")
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), default="Analyst")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password:
            flash("Please fill all fields.", "error")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        if len(password) < 6:
            flash("Password must contain at least 6 characters.", "error")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Account already exists.", "error")
            return redirect(url_for("login"))

        user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role="Analyst"
        )

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully.", "success")

        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():


    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze_ioc():
    data = request.get_json() or {}

    ioc_type = data.get("type", "IP")
    value = data.get("value", "").strip()

    if not value:
        return {"error": "IOC value is required."}, 400

    collected = collect_ioc(ioc_type, value)

    intelligence = retrieve_ioc(collected["indicator"])

    if intelligence:

        severity = intelligence.get("severity", "MEDIUM")
        confidence = intelligence.get("confidence", 50)
        mitre = intelligence.get("mitre", [])

        if severity == "HIGH":
            risk_score = 90
            classification = "HIGH RISK"

        elif severity == "MEDIUM":
            risk_score = 60
            classification = "MEDIUM RISK"

        else:
            risk_score = 30
            classification = "LOW RISK"

        return {
            "indicator": value,
            "type": ioc_type,
            "classification": classification,
            "risk_score": risk_score,
            "confidence": confidence,
            "evidence": 1,
            "description": intelligence.get("description", ""),
            "mitre": mitre
        }

    return {
        "indicator": value,
        "type": ioc_type,
        "classification": "UNKNOWN",
        "risk_score": 0,
        "confidence": 0,
        "evidence": 0,
        "description": "No matching intelligence found.",
        "mitre": []
    }


  


@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash("Logged out successfully.", "success")

    return redirect(url_for("index"))


with app.app_context():

    os.makedirs(
        os.path.join(BASE_DIR, "database"),
        exist_ok=True
    )

    db.create_all()

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )