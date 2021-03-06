from xml.dom import ValidationErr
from wtforms import (
    StringField,
    PasswordField,
    ValidationError
)

from flask_wtf import FlaskForm
from wtforms.validators import InputRequired, Length, EqualTo, Regexp, Email
import email_validator
from flask_login import current_user
from models import User


class login_form(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=5, max=50)])
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=72)])


class register_form(FlaskForm):
    username = StringField(
        validators=[
            InputRequired(),
            Length(5, 50, message = "Username must be 5 ~ 50 length"),
            Regexp(
                "^[A-Za-z][A-Za-z0-9_.]*$",
                0,
                "Username must have only letters, numbers, dots or underscores",
            ),
        ]
    )
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])
    password = PasswordField(validators=[InputRequired(), Length(8, 72)])
    cpwd = PasswordField(validators=[InputRequired(), Length(8,72), EqualTo("password", message="Passwords must match")])

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Email already registered!")

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already taken")

class help_form(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=5, max=50)])
    email = StringField(validators=[InputRequired(), Email(), Length(1, 64)])

class password_form(FlaskForm):
    password = PasswordField(validators=[InputRequired(), Length(8, 72)])
    cpwd = PasswordField(validators=[InputRequired(), Length(8,72), EqualTo("password", message="Passwords must match")])