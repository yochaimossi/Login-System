from flask import Flask, redirect, render_template, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = 'not protected'  # creating a session
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///loginsystem.sqlite"  # sql db

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@app.route("/")
def home():
    return redirect(url_for('login'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if 'remember' in session:  # checking if the user wants to rememeber him
            return redirect(url_for("user"))
        return render_template('login.html')
    if request.method == 'POST':
        password = request.form['txt_password']
        username = request.form['txt_name']
        user = User.query.filter_by(username=username).all()
        if user and check_password_hash(user[0].password, password):  # checking if the user and password are mached in the db
            session['user'] = username
            if 'remember' in request.form:  # checking if the user clicked on "remember me" check box
                session['remember'] = True
                return redirect(url_for("user"))
            else:
                return redirect(url_for("user"))
        else:
            return render_template('login.html', login_failed=True)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        if 'remember' in session:
            return redirect(url_for('user'))
        return render_template('signup.html')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        repeated_password = request.form['repeated_password']
        if password != repeated_password:  # if passwords do not match
            return render_template('signup.html', bad_repeat=True)
        if User.query.filter_by(username=username).all():  # checking if username already exists in the db
            return render_template('signup.html', username_exists=True)
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(public_id=str(uuid.uuid4()), username=username, password=hashed_password)
        db.session.add(new_user)  # adding the new user to the db
        db.session.commit()
        session['user'] = username
        return redirect(url_for('user'))


@app.route("/my_app")
def user():
    if 'user' in session:
        user = session['user']
        return render_template('my_app.html', user=user)
    else:
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    if 'user' in session:  # removing "user" from the session
        session.pop('user')
    if 'remember' in session:  # removing "remember" from the session
        session.pop('remember')
    return redirect(url_for("login"))

 
if __name__ == '__main__':
    app.run(debug=True)