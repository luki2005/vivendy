from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import os

# ===================== Config =====================
ADMIN_EMAIL = "lukas.falkenauge2005@gmail.com"
ADMIN_PASSWORD = "falkenauge"

MONGO_URL = "mongodb+srv://lukasfalkenauge2005_db_user:xNOTQGRe5t6hszDU@cluster4.aiejafm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster4"
client = MongoClient(MONGO_URL)
db = client["vivwendy"]

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"  # altes Secret wiederhergestellt
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
MAX_LOGIN_ATTEMPTS = 4

# ===================== Helpers =====================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("username") != ADMIN_EMAIL:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

# ===================== Auth =====================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"].lower()
        password = request.form["password"]

        # Check blocked emails
        if db.blocked_emails.find_one({"email": email}):
            return render_template("register.html", error="Diese E-Mail ist gesperrt")

        if db.users.find_one({"$or": [{"username": username}, {"email": email}]}):
            return render_template("register.html", error="User existiert bereits")

        db.users.insert_one({
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "banned": False,
            "ban_reason": None,
            "role": "user",
            "login_attempts": 0  # neue Spalte für Login-Versuche
        })
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_input = request.form["login"].strip()
        password = request.form["password"]

        user = db.users.find_one({"$or": [{"username": login_input}, {"email": login_input}]})

        if not user:
            return render_template("login.html", error="Falsche Login-Daten")

        # Check if account is banned
        if user.get("banned"):
            return render_template("banned.html", reason=user.get("ban_reason"))

        # Check password
        if not check_password_hash(user["password_hash"], password):
            # Login Attempt erhöhen
            attempts = user.get("login_attempts", 0) + 1
            update_data = {"login_attempts": attempts}
            if attempts >= MAX_LOGIN_ATTEMPTS:
                update_data["banned"] = True
                update_data["ban_reason"] = "Passwort 4 mal falsch eingegeben"
            db.users.update_one({"_id": user["_id"]}, {"$set": update_data})

            if attempts >= MAX_LOGIN_ATTEMPTS:
                return render_template("banned.html", reason="Passwort 4 mal falsch eingegeben. Bitte den Moderator kontaktieren.")

            return render_template("login.html", error="Falsche Login-Daten")

        # Reset login attempts on success
        db.users.update_one({"_id": user["_id"]}, {"$set": {"login_attempts": 0}})

        session["user_id"] = str(user["_id"])
        session["username"] = user["email"]  # Email für Admin Check
        session["role"] = user.get("role", "user")
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ===================== Admin Panel =====================
@app.route("/admin/users", methods=["GET", "POST"])
@login_required
@admin_only
def admin_users():
    users = list(db.users.find())
    return render_template("admin_users.html", users=users)


@app.route("/admin/ban/<user_id>", methods=["POST"])
@login_required
@admin_only
def ban_user(user_id):
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"banned": True, "ban_reason": request.form.get("reason")}})
    return redirect(url_for("admin_users"))


@app.route("/admin/unban/<user_id>", methods=["POST"])
@login_required
@admin_only
def unban_user(user_id):
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"banned": False, "ban_reason": None, "login_attempts": 0}})
    return redirect(url_for("admin_users"))


@app.route("/admin/password/<user_id>", methods=["POST"])
@login_required
@admin_only
def admin_change_password(user_id):
    password = request.form.get("password")
    if not password or len(password) < 6:
        return redirect(url_for("admin_users"))
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"password_hash": generate_password_hash(password), "login_attempts": 0, "banned": False, "ban_reason": None}})
    return redirect(url_for("admin_users"))


@app.route("/admin/block-email", methods=["POST"])
@login_required
@admin_only
def block_email():
    email = request.form.get("email").lower()
    reason = request.form.get("reason", "gesperrt")

    if not db.blocked_emails.find_one({"email": email}):
        db.blocked_emails.insert_one({"email": email, "reason": reason})

    # Bestehende User mit dieser E-Mail bannen
    db.users.update_many({"email": email}, {"$set": {"banned": True, "ban_reason": "E-Mail gesperrt"}})
    return redirect(url_for("admin_users"))


@app.route("/admin/logout")
@login_required
@admin_only
def admin_logout():
    session.pop("admin_access", None)
    return redirect(url_for("index"))

# ===================== Personen & Events =====================
@app.route("/")
@login_required
def index():
    personen = list(db.persons.find())
    return render_template("index.html", personen=personen)


@app.route("/person/new", methods=["GET", "POST"])
@login_required
def person_new():
    if request.method == "POST":
        file = request.files.get("bild")
        filename = None
        if file and file.filename:
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        db.persons.insert_one({
            "name": request.form["name"],
            "geburtsdatum": request.form.get("geburtsdatum"),
            "beschreibung": request.form.get("beschreibung"),
            "bild_dateiname": filename
        })
        return redirect(url_for("index"))
    return render_template("person_new.html")


@app.route("/person/<id>")
@login_required
def person_detail(id):
    person = db.persons.find_one({"_id": ObjectId(id)})
    events = list(db.events.find({"person_id": id}))
    return render_template("person_detail.html", person=person, events=events)


@app.route("/person/<id>/event/new", methods=["GET", "POST"])
@login_required
def event_new(id):
    person = db.persons.find_one({"_id": ObjectId(id)})
    if request.method == "POST":
        db.events.insert_one({
            "person_id": id,
            "titel": request.form["titel"],
            "datum": request.form["datum"],
            "beschreibung": request.form.get("beschreibung")
        })
        return redirect(url_for("person_detail", id=id))
    return render_template("event_new.html", person=person)


# ===================== Run =====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
