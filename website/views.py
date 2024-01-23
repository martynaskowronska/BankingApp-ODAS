from flask import Blueprint, render_template, request, flash
from flask_login import login_required, current_user
from .models import User, Permutation, UserInfo, Transfer
from . import db
from .auth import hash_password, encrypt_length
import os
from itertools import combinations 

views = Blueprint('views', __name__)

@views.route('/home', methods=['GET'])
@login_required
def home():
    user_info = UserInfo.query.filter_by(client_number = current_user.client_number).first()
    return render_template("home.html", user=current_user, user_info=user_info)

@views.route('/new_transfer', methods=['GET', 'POST'])
@login_required
def new_transfer():
    if request.method == 'POST':
        title = request.form.get("title")
        amount = request.form.get("amount")
        recipient_client_number = request.form.get("client_number")
        recipient_first_name = request.form.get("first_name")
        recipient_last_name = request.form.get("last_name")
        sender_client_number = current_user.client_number

        recipient = UserInfo.query.filter_by(client_number = recipient_client_number).first()
        sender = UserInfo.query.filter_by(client_number = current_user.client_number).first()

        if recipient_client_number != current_user.client_number:
            if recipient and recipient.first_name == recipient_first_name and recipient.last_name == recipient_last_name:
                if sender.balance >= float(amount):
                    transfer_data = {
                        "amount": amount,
                        "title": title,
                        "recipient_client_number": recipient_client_number,
                        "recipient_first_name": recipient_first_name,
                        "recipient_last_name": recipient_last_name,
                        "sender_client_number": sender_client_number
                    }
                    make_transfer(transfer_data)
                    flash('Transfer sent correctly', category='success')
                else:
                    flash('Not enough money on your account', category='error')
            else:
                flash('Wrong recipient data', category='error')
        else:
            flash('You cannot make a transfer to yourself', category='error')

    return render_template("new_transfer.html", user=current_user)

def make_transfer(transfer_data):
    recipient = UserInfo.query.filter_by(client_number = transfer_data["recipient_client_number"]).first()
    recipient.balance += float(transfer_data["amount"])
    sender = UserInfo.query.filter_by(client_number = transfer_data["sender_client_number"]).first()
    sender.balance -= float(transfer_data["amount"])
    new_transfer = Transfer(title=transfer_data["title"], amount=transfer_data["amount"], recipient_client_number=transfer_data["recipient_client_number"], recipient_first_name=transfer_data["recipient_first_name"], recipient_last_name=transfer_data["recipient_last_name"], sender_client_number=transfer_data["sender_client_number"])
    db.session.add(new_transfer)
    db.session.commit()

@views.route('/transfers', methods=['GET'])
@login_required
def transfer_list():
    user_info = UserInfo.query.filter_by(client_number = current_user.client_number).first()
    received_transfers = Transfer.query.filter_by(recipient_client_number = current_user.client_number).all()
    return render_template("transfer_list.html", user=current_user, user_info=user_info, received_transfers=received_transfers)

@views.route('/data', methods=['GET'])
@login_required
def account_data():
    user_info = UserInfo.query.filter_by(client_number = current_user.client_number).first()
    return render_template("data.html", user=current_user, user_info=user_info)

@views.route('/password_change', methods=['GET', 'POST'])
@login_required
def password_change():
    if request.method == 'POST':
        current_password = hash_password(request.form.get("current_password"), current_user.salt)
        if current_user.password == current_password:
            new_password = request.form.get("new_password")
            repeated_password = request.form.get("repeated_password")
            if new_password == repeated_password:
                new_salt = os.urandom(64)
                change_password(new_password, new_salt)
                flash('Password successfully changed', category='success')
            else:
                flash('New password does not match', category='error')
        else:
            flash('Wrong current password', category='error')

    return render_template("password_change.html", user=current_user)

def generate_substrings(password):
    substrings = []
    length = len(password) - (round(len(password)/2) - 1)
    index_combinations = combinations(range(len(password)), length)

    for indices in index_combinations:
        substring = ''.join(password[i] for i in sorted(indices))
        substrings.append(substring)

    return substrings

def hash_substrings(substrings, salt):
    result=''
    for substring in substrings:
        hashed_substring = hash_password(substring, salt)
        result += hashed_substring
    return result

def change_password(new_password, new_salt):
    current_user.password = hash_password(new_password, new_salt)
    current_user.salt = new_salt
    current_user.password_length = encrypt_length(len(new_password))

    hashed_substrings = hash_substrings(generate_substrings(new_password), new_salt)
    permutations = Permutation.query.filter_by(client_number=current_user.client_number).first()
    if permutations:
        permutations.permutations = hashed_substrings
    else:
        flash('Something went wrong. Try again', category='error')

    db.session.commit()
