from flask import Blueprint, render_template, request, flash, redirect, url_for, session
import random
from .models import User, Permutation
from Crypto.Cipher import AES
from dotenv import load_dotenv
import os, hashlib
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta, timezone
from . import db

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
            if user.is_blocked == False:
                session['client_number'] = client_number
                session['password_access'] = True
                if 'attempt' not in session:
                    session['attempt'] = 3
                return redirect(url_for('auth.password'))
            else:
                flash('Your account have been blocked. Please contact bank', category='error')
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
    cooldown_duration = 60

    if user.is_blocked:
        flash('Your account have been blocked. Please contact bank', category='error')
        return redirect(url_for('auth.client_number'))

    if request.method == 'GET':
        session['non_required_inputs'] = gen_random_inputs(pswd_length)
        if session['attempt'] < 0:
            return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user, disable_button = True)
        if 'time_elapsed' in session:
            time_elapsed = datetime.now(timezone.utc) - session['last_attempt']
            session['time_elapsed'] = time_elapsed.total_seconds()
            if session['time_elapsed'] < cooldown_duration:
                return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user, disable_button = True)

        return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user, disable_button = False)
    else:
        provided_password = ''.join(request.form.get(f'input{i}') for i in range(pswd_length) if i not in session['non_required_inputs'])
        salt = user.salt
        permutations = Permutation.query.filter_by(client_number = session['client_number']).first()
        
        if permutations:
            stored_password = permutations.permutations
            if verify_password(provided_password, stored_password, salt):
                session.clear()
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                attempt = session.get('attempt')
                attempt -= 1
                session['attempt'] = attempt
                session['last_attempt'] = datetime.now(timezone.utc)

                if 'last_try' in session:
                    flash('Your account has been blocked. Please contact bank', category='error')
                    user.is_blocked = True
                    db.session.commit()
                    session.clear()
                    return redirect(url_for('auth.client_number'))

                if attempt == 1:
                    flash('This is your last attempt. After that you will have to wait 10 minutes', category='error')
                
                if attempt == 0:
                    flash('3 failed attempts. You need to wait 10 minutes. After another failed attempt your account will be blocked', category='error')
                    time_elapsed = datetime.now(timezone.utc) - session['last_attempt']
                    session['time_elapsed'] = time_elapsed.total_seconds()
                    session['last_try'] = True
                    return redirect(url_for('auth.client_number'))
                
                if session['attempt'] < 0:
                    return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user, disable_button = True)

                flash('Wrong password. Try again.', category='error')
                session['non_required_inputs'] = gen_random_inputs(pswd_length)
                return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], user=current_user, disable_button=False)
        else:
            flash('Something went wrog. Try again.', category='error')
            session['non_required_inputs'] = gen_random_inputs(pswd_length)
            return render_template("password.html", no_inputs=pswd_length, non_required_inputs = session['non_required_inputs'], suer=current_user, disable_button = False)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.client_number'))
