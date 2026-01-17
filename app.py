from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import date
import os

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
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if not username or not email or not password:
            return render_template('register.html', error="Bitte alle Felder ausfüllen.")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            return render_template('register.html', error="Username oder E-Mail bereits vergeben.")

        hashed = generate_password_hash(password)
        user = User(username=username, email=email, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
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
    personen = Person.query.all()
    return render_template('index.html', personen=personen)

@app.route('/person/new', methods=['GET', 'POST'])
@login_required
def person_new():
    if request.method == 'POST':
        name = request.form['name']
        geburtsdatum = request.form.get('geburtsdatum') or None
        beschreibung = request.form.get('beschreibung')

        file = request.files.get('bild')
        filename = None
        if file and file.filename:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        person = Person(
            name=name,
            geburtsdatum=date.fromisoformat(geburtsdatum) if geburtsdatum else None,
            beschreibung=beschreibung,
            bild_dateiname=filename
        )
        db.session.add(person)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('person_new.html')

@app.route('/person/<int:person_id>')
@login_required
def person_detail(person_id):
    person = Person.query.get_or_404(person_id)
    return render_template('person_detail.html', person=person)

@app.route('/person/<int:person_id>/event/new', methods=['GET', 'POST'])
@login_required
def event_new(person_id):
    person = Person.query.get_or_404(person_id)
    if request.method == 'POST':
        titel = request.form['titel']
        datum = date.fromisoformat(request.form['datum'])
        beschreibung = request.form.get('beschreibung')

        event = Event(
            person_id=person.id,
            titel=titel,
            datum=datum,
            beschreibung=beschreibung
        )
        db.session.add(event)
        db.session.commit()
        return redirect(url_for('person_detail', person_id=person.id))

    return render_template('event_new.html', person=person)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
