from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session,
    request
)

from sqlalchemy import and_
from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    logout_user,
    login_required,
)

from create_app import create_app, db, login_manager, bcrypt
from models import User
from forms import login_form, register_form, help_form, password_form

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app = create_app()

@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=1)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    form = login_form()

    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username = form.username.data).first()
            
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash("Invalid Username or Password")

        except Exception as e:
            flash(e)
        
    return render_template("auth.html", form=form, text="Login Here", btn_action="Login", color1="#fff", color2="black", color3="black", color11="#00ad45")

@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():

    form = register_form()
    
    if form.validate_on_submit():
        try:
            
            password = form.password.data
            username = form.username.data
            email = form.email.data

            newuser = User(
                username = username,
                email = email,
                password=generate_password_hash(password).decode('utf8'),
            )
            db.session.add(newuser)
            db.session.commit()
            flash(f"Account Succesfully created")
            return redirect(url_for("login"))

        except InvalidRequestError:
            db.session.rollback()
            flash(f"Something went wrong")
        except IntegrityError:
            db.session.rollback()
            flash(f"User already exists")
        except DataError:
            db.session.rollback()
            flash(f"Invalid Entry")
        except InterfaceError:
            db.session.rollback()
            flash(f"Error connecting to the database")
        except BuildError:
            db.session.rollback()
            flash(f"An error occured!")
    return render_template("auth.html", form=form, text="Register Here", btn_action="Register", color1="black", color2="#fff", color3="black", color21="#00ad45")

@app.route("/help/", methods=("GET", "POST"), strict_slashes=False)
def help():
    form = help_form()
    if form.validate_on_submit():
        try:
            username = form.username.data
            email = form.email.data
            
            user = User.query.filter(
                and_(
                    User.username.like(username),
                    User.email.like(email)
                )
            ).first()
            
            if user is None:
                raise InvalidRequestError
            else:
                return redirect(url_for("reset", username=username))

        except InvalidRequestError:
            flash("Cannot find an account")

        except Exception as e:
            flash(e)
    
    return render_template("auth.html", form=form, text="Reset Password", btn_action="Reset", color1="black", color2="black", color3 = "#fff", color31="#00ad45")

@app.route("/reset/<username>", methods=("GET", "POST"), strict_slashes=False)
def reset(username):
    form = password_form()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(username=username).first_or_404()
            user.password = generate_password_hash(form.password.data).decode('utf8')

            db.session.add(user)
            db.session.commit()
            flash("Password is changed")
            return redirect(url_for("login"))

        except Exception as e:
            flash(e)
            
    return render_template("auth.html", form=form, text="Reset Password", btn_action="Reset", color1="black", color2="black", color3 = "#fff", color31="#00ad45")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)