from flask import Blueprint, render_template, request, flash, redirect, url_for, session
import random
from .models import User, Permutation
from Crypto.Cipher import AES
from dotenv import load_dotenv
import os, hashlib
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

def gen_random_inputs(pswd_lenght):
    no_of_inputs = round(pswd_lenght/2) - 1
    inputs = random.sample(range(pswd_lenght), no_of_inputs)
    return inputs

def encrypt_length(password_length):
    load_dotenv()
    key = os.getenv("AES_KEY").encode('utf-8')
    password_length_bytes = int.to_bytes(password_length, byteorder='big')
    iv = os.urandom(16) 

    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(password_length_bytes)

    encrypted_length = iv + ciphertext

    return encrypted_length

def decrypt_length(encrypted_data):
    load_dotenv()
    key = os.getenv("AES_KEY").encode('utf-8')

    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    decrypt_cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    decrypted_length_bytes = decrypt_cipher.decrypt(ciphertext)
    decrypted_length = int.from_bytes(decrypted_length_bytes, byteorder='big')

    return decrypted_length

def hash_password(password, salt):
    hashed_password = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 500000)

    return hashed_password.hex()

def verify_password(provided_password, stored_password, salt):
    hash_provided_password = hash_password(provided_password, salt)

    for i in range(0, len(stored_password), len(hash_provided_password)):
        substring = stored_password[i:i+len(hash_provided_password)]
        if substring == hash_provided_password:
            return True
        
    return False

@auth.route('/', methods=['GET', 'POST'])
def client_number():
    if request.method == 'POST':
        client_number = request.form.get('client_number')
        user = User.query.filter_by(client_number = client_number).first()
        if user:
            session['client_number'] = client_number
            session['password_access'] = True
            return redirect(url_for('auth.password'))
        else:
            flash('Wrong client number. Try again.', category = 'error')
    return render_template("client_number.html", user=current_user)

@auth.route('/password', methods=['GET', 'POST'])
def password():
    if not session.get('password_access'):
        flash('Please enter client number to access this page', category='error')
        return redirect(url_for('auth.client_number'))

    user = User.query.filter_by(client_number = session['client_number']).first()
    enc_pswd_lenght = user.password_length
    pswd_length = decrypt_length(enc_pswd_lenght)

    if request.method == 'GET':
        session['non_required_inputs'] = gen_random_inputs(pswd_length)
        return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user)
    else:
        provided_password = ''.join(request.form.get(f'input{i}') for i in range(pswd_length) if i not in session['non_required_inputs'])
        salt = user.salt
        permutations = Permutation.query.filter_by(client_number = session['client_number']).first()
        if permutations:
            stored_password = permutations.permutations
            if verify_password(provided_password, stored_password, salt):
                login_user(user, remember=True)
                session.pop('non_required_inputs')
                session.pop('client_number')
                session.pop('password_access')
                return redirect(url_for('views.home'))
            else:
                flash('Wrong password. Try again.', category='error')
                session['non_required_inputs'] = gen_random_inputs(pswd_length)
                return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user)
        else:
            flash('Something went wrog. Try again.', category='error')
            session['non_required_inputs'] = gen_random_inputs(pswd_length)
            return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], suer=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.client_number'))
