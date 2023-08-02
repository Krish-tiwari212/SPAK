import requests
from flask import Flask, render_template, redirect, request, url_for
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, Index
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import json
from algoliasearch.search_client import SearchClient
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message, Mail
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect
from forms import LoginForm, Signupform, Subform, AddForm
from functools import wraps



load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['CACHE_TYPE'] = 'simple'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get('RECAPTCHA_PRIVATE_KEY')
app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get('RECAPTCHA_PUBLIC_KEY')

csrf = CSRFProtect(app)
csrf.init_app(app)
mail = Mail(app)
cache = Cache(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"
db = SQLAlchemy()
db.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(1000))
    name = db.Column(db.String(1000))

class Product(db.Model):
    __tablename__ = 'product'
    name = db.Column(db.String(100), primary_key=True)
    image_url = db.Column(db.String(100), unique=True)
    price = db.Column(db.String(1000))
    size = db.Column(db.String(1000))
    description = db.Column(db.String(1000))


with app.app_context():
    db.create_all()

def admin_only(func):
    @wraps(func)
    def wrapper(*args, ** kwargs):
        if current_user.id == 1 or current_user.username == "krish212":
            return func(*args, ** kwargs)
        else:
            return redirect(url_for('unauthorized'))
    return wrapper

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('signup'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=["GET","POST"])
def home():
    c = Product.query.all()
    form = Subform()
    if form.validate_on_submit() and request.method == "POST":
        name = form.name.data
        email = form.email.data
        msg = Message(f"Someone Contacted You", recipients=["champion.coc212@gmail.com"])
        msg.body = f'First Name: {name}\nEmail: {email}'
        mail.send(msg)
        return redirect('/')
    return render_template('index.html',form=form, l = c)

@app.route("/login", methods = ["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit() and request.method == "POST":
        username = form.username.data
        password = form.password.data
        meth = 'pbkdf2:sha256:260000$'
        o = User.query.filter_by(name=username).first()
        try:
            if o.name == username and check_password_hash(f"{meth}{o.password}", password):
                login_user(o)
                return redirect("/")
            else:
                return render_template("login.html", l=1, form=form)
        except AttributeError:
            print("hello")
            return render_template("login.html", l=1, form=form)
    return render_template('login.html', form=form)

@app.route("/signup", methods = ["GET","POST"])
def signup():
    form = Signupform()
    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        if username == "" or email == "" or form.password.data == "":
            return render_template('signup.html', l=1, p=0, form=form)
        if len(request.form.get("password")) < 8:
            return render_template('signup.html', l=0, p=1, form=form)
        password = (generate_password_hash(form.password.data, method='pbkdf2:sha256:260000',
                                           salt_length=8))[21:]
        new_user = User(name=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect("/")
    return render_template("signup.html", l=0, p=0, form=form)

@app.route("/add", methods=["GET","POST"])
@admin_only
@login_required
def add():
    form = AddForm()
    if form.validate_on_submit() and request.method == "POST":
        new = Product(name=form.product_name.data, image_url=form.image_url.data, price=form.price.data, size=form.size.data, description=form.description.data)
        db.session.add(new)
        db.session.commit()
        return redirect('/')
    return render_template("new_prod.html", form=form)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)