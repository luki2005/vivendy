from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import os

# ===================== Config =====================
ADMIN_PANEL_PASSWORD = "falkenauge"

MONGO_URL = "mongodb+srv://lukasfalkenauge2005_db_user:xNOTQGRe5t6hszDU@cluster4.aiejafm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster4"
client = MongoClient(MONGO_URL)
db = client["vivwendy"]

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_KEY"
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")

# ===================== Helpers =====================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
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
            "role": "user"
        })
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_input = request.form["login"].strip()
        password = request.form["password"]

        user = db.users.find_one({
            "$or": [{"username": login_input}, {"email": login_input}]
        })

        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Falsche Login-Daten")

        if user["banned"]:
            return render_template("banned.html", reason=user.get("ban_reason"))

        session["user_id"] = str(user["_id"])
        session["username"] = user["username"]
        session["role"] = user.get("role", "user")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ===================== Admin-Panel =====================
@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    # Passwort-Abfrage für Admin-Panel
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PANEL_PASSWORD:
            session["admin_access"] = True
        else:
            return render_template("admin_login.html", error="Falsches Passwort")

    if not session.get("admin_access"):
        return render_template("admin_login.html")

    users = list(db.users.find())
    return render_template("admin_users.html", users=users)


@app.route("/admin/ban/<user_id>", methods=["POST"])
def ban_user(user_id):
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"banned": True, "ban_reason": request.form.get("reason")}}
    )
    return redirect(url_for("admin_users"))


@app.route("/admin/unban/<user_id>", methods=["POST"])
def unban_user(user_id):
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"banned": False, "ban_reason": None}}
    )
    return redirect(url_for("admin_users"))


@app.route("/admin/password/<user_id>", methods=["POST"])
def admin_change_password(user_id):
    password = request.form.get("password")
    if not password or len(password) < 6:
        return redirect(url_for("admin_users"))

    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"password_hash": generate_password_hash(password)}}
    )
    return redirect(url_for("admin_users"))


@app.route("/admin/block-email", methods=["POST"])
def block_email():
    email = request.form.get("email").lower()
    reason = request.form.get("reason", "gesperrt")

    if not db.blocked_emails.find_one({"email": email}):
        db.blocked_emails.insert_one({"email": email, "reason": reason})

    # Bestehende User mit dieser E-Mail bannen
    db.users.update_many(
        {"email": email},
        {"$set": {"banned": True, "ban_reason": "E-Mail gesperrt"}}
    )
    return redirect(url_for("admin_users"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_access", None)
    return redirect(url_for("index"))

# ===================== App =====================
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
