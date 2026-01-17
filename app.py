from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import date
import os
from pymongo import MongoClient
from bson import ObjectId

# ---------- MongoDB ----------

MONGO_URL = "mongodb+srv://lukasfalkenauge2005_db_user:xNOTQGRe5t6hszDU@cluster4.aiejafm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster4"

client = MongoClient(MONGO_URL)
db = client["vivwendy"]

# ---------- Flask ----------

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.secret_key = "b7f4c2e9a1d84f6fb3c0e2a9f7d1c4e8c9a3f2b7d6e4a1f0b8c2d9e7f3a1c6b"

# ---------- Helpers ----------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ---------- Auth Routes ----------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if db.users.find_one({"$or": [{"username": username}, {"email": email}]}):
            return render_template('register.html', error="User existiert bereits")

        hashed = generate_password_hash(password)

        db.users.insert_one({
            "username": username,
            "email": email,
            "password_hash": hashed,
            "banned": False,
            "ban_reason": None,
            "role": "user"
        })

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login'].strip()
        password = request.form['password']

        user = db.users.find_one({
            "$or": [
                {"username": login_input},
                {"email": login_input}
            ]
        })

        if user:
            if user.get("banned") is True:
                return render_template("banned.html", reason=user.get("ban_reason"))

            if check_password_hash(user["password_hash"], password):
                session['user_id'] = str(user["_id"])
                session['username'] = user["username"]
                session['role'] = user.get("role", "user")
                return redirect(url_for('index'))

        return render_template('login.html', error="Falsche Login-Daten.")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- Admin Routes ----------

@app.route('/admin/users')
@login_required
def admin_users():
    users = list(db.users.find())
    return render_template("admin_users.html", users=users)


@app.route('/admin/ban/<user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    reason = request.form.get("reason")
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"banned": True, "ban_reason": reason}}
    )
    return redirect(url_for("admin_users"))


@app.route('/admin/unban/<user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"banned": False, "ban_reason": None}}
    )
    return redirect(url_for("admin_users"))

# ---------- App Routes ----------

@app.route('/')
@login_required
def index():
    personen = list(db.persons.find())
    return render_template('index.html', personen=personen)


@app.route('/person/new', methods=['GET', 'POST'])
@login_required
def person_new():
    if request.method == 'POST':
        name = request.form['name']
        geburtsdatum = request.form.get('geburtsdatum')
        beschreibung = request.form.get('beschreibung')

        file = request.files.get('bild')
        filename = None

        if file and file.filename:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db.persons.insert_one({
            "name": name,
            "geburtsdatum": geburtsdatum,
            "beschreibung": beschreibung,
            "bild_dateiname": filename
        })

        return redirect(url_for('index'))

    return render_template('person_new.html')


@app.route('/person/<id>/event/new', methods=['GET', 'POST'])
@login_required
def event_new(id):
    person = db.persons.find_one({"_id": ObjectId(id)})

    if request.method == 'POST':
        titel = request.form['titel']
        datum = request.form['datum']
        beschreibung = request.form.get('beschreibung')

        db.events.insert_one({
            "person_id": id,
            "titel": titel,
            "datum": datum,
            "beschreibung": beschreibung
        })

        return redirect(url_for('person_detail', id=id))

    return render_template('event_new.html', person=person)


@app.route('/person/<id>')
@login_required
def person_detail(id):
    person = db.persons.find_one({"_id": ObjectId(id)})
    events = list(db.events.find({"person_id": id}))
    return render_template('person_detail.html', person=person, events=events)

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import date
import os
from pymongo import MongoClient
from bson import ObjectId

# ---------- MongoDB ----------

MONGO_URL = "mongodb+srv://lukasfalkenauge2005_db_user:xNOTQGRe5t6hszDU@cluster4.aiejafm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster4"

client = MongoClient(MONGO_URL)
db = client["vivwendy"]

# ---------- Flask ----------

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.secret_key = "b7f4c2e9a1d84f6fb3c0e2a9f7d1c4e8c9a3f2b7d6e4a1f0b8c2d9e7f3a1c6b"

# ---------- Helpers ----------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ---------- Auth Routes ----------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if db.users.find_one({"$or": [{"username": username}, {"email": email}]}):
            return render_template('register.html', error="User existiert bereits")

        hashed = generate_password_hash(password)

        db.users.insert_one({
            "username": username,
            "email": email,
            "password_hash": hashed,
            "banned": False,
            "ban_reason": None,
            "role": "user"
        })

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login'].strip()
        password = request.form['password']

        user = db.users.find_one({
            "$or": [
                {"username": login_input},
                {"email": login_input}
            ]
        })

        if user:
            if user.get("banned") is True:
                return render_template("banned.html", reason=user.get("ban_reason"))

            if check_password_hash(user["password_hash"], password):
                session['user_id'] = str(user["_id"])
                session['username'] = user["username"]
                session['role'] = user.get("role", "user")
                return redirect(url_for('index'))

        return render_template('login.html', error="Falsche Login-Daten.")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ---------- Admin Routes ----------

@app.route('/admin/users')
@login_required
def admin_users():
    users = list(db.users.find())
    return render_template("admin_users.html", users=users)


@app.route('/admin/ban/<user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    reason = request.form.get("reason")
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"banned": True, "ban_reason": reason}}
    )
    return redirect(url_for("admin_users"))


@app.route('/admin/unban/<user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"banned": False, "ban_reason": None}}
    )
    return redirect(url_for("admin_users"))

# ---------- App Routes ----------

@app.route('/')
@login_required
def index():
    personen = list(db.persons.find())
    return render_template('index.html', personen=personen)


@app.route('/person/new', methods=['GET', 'POST'])
@login_required
def person_new():
    if request.method == 'POST':
        name = request.form['name']
        geburtsdatum = request.form.get('geburtsdatum')
        beschreibung = request.form.get('beschreibung')

        file = request.files.get('bild')
        filename = None

        if file and file.filename:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db.persons.insert_one({
            "name": name,
            "geburtsdatum": geburtsdatum,
            "beschreibung": beschreibung,
            "bild_dateiname": filename
        })

        return redirect(url_for('index'))

    return render_template('person_new.html')


@app.route('/person/<id>/event/new', methods=['GET', 'POST'])
@login_required
def event_new(id):
    person = db.persons.find_one({"_id": ObjectId(id)})

    if request.method == 'POST':
        titel = request.form['titel']
        datum = request.form['datum']
        beschreibung = request.form.get('beschreibung')

        db.events.insert_one({
            "person_id": id,
            "titel": titel,
            "datum": datum,
            "beschreibung": beschreibung
        })

        return redirect(url_for('person_detail', id=id))

    return render_template('event_new.html', person=person)


@app.route('/person/<id>')
@login_required
def person_detail(id):
    person = db.persons.find_one({"_id": ObjectId(id)})
    events = list(db.events.find({"person_id": id}))
    return render_template('person_detail.html', person=person, events=events)



if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
