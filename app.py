from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import date
import os
from pymongo import MongoClient
from bson import ObjectId

MONGO_URL = "DEINE_MONGO_URL_HIER" 
client = MongoClient(MONGO_URL) 
db = client["vivwendy"]


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vivwendy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.secret_key = "CHANGE_THIS_SECRET_KEY"

db = SQLAlchemy(app)

# ---------- Models ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    geburtsdatum = db.Column(db.Date, nullable=True)
    beschreibung = db.Column(db.Text, nullable=True)
    bild_dateiname = db.Column(db.String(255), nullable=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), nullable=False)
    titel = db.Column(db.String(200), nullable=False)
    datum = db.Column(db.Date, nullable=False)
    beschreibung = db.Column(db.Text, nullable=True)
    person = db.relationship('Person', backref=db.backref('events', lazy=True))

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
            "password_hash": hashed
        })

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login'].strip()
        password = request.form['password']

        user = User.query.filter(
            (User.username == login_input) | (User.email == login_input)
        ).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))

        return render_template('login.html', error="Falsche Login-Daten.")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

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
    with app.app_context():
        db.create_all()
    app.run(debug=True)
