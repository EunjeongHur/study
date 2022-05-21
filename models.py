from create_app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique = True, nullable = False)
    password = db.Column(db.String(300), nullable=False)

    def __repr__(self):
        return f'<User: {self.username}>'
