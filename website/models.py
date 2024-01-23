from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    client_number = db.Column(db.String(10), primary_key=True)
    password = db.Column(db.Text)
    password_length = db.Column(db.Text)
    salt = db.Column(db.Text)
    is_blocked = db.Column(db.Boolean, default=False)

    permutation = db.relationship('Permutation', uselist=False, back_populates='user', cascade='all')
    transfers = db.relationship('Transfer')
    user_info = db.relationship('UserInfo', uselist=False, back_populates='user', cascade='all')

    def get_id(self):
        return str(self.client_number)

class Permutation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_number = db.Column(db.String(10), db.ForeignKey('user.client_number'), unique=True)
    permutations = db.Column(db.Text)

    user = db.relationship('User', back_populates='permutation')

class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float(2))
    title = db.Column(db.String(50))
    recipient_client_number = db.Column(db.String(10))
    recipient_first_name = db.Column(db.String(50))
    recipient_last_name = db.Column(db.String(50))
    sender_client_number = db.Column(db.String(10), db.ForeignKey('user.client_number'))
    sender_first_name = db.Column(db.String(50))
    sender_last_name = db.Column(db.String(50))

class UserInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_number = db.Column(db.String(10), db.ForeignKey('user.client_number'), unique=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    balance = db.Column(db.Float(2))
    id_number = db.Column(db.String(9))
    card_number = db.Column(db.String(16))

    user = db.relationship('User', back_populates='user_info')