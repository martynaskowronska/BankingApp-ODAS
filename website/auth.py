from flask import Blueprint, render_template, request, flash, redirect, url_for
import random

auth = Blueprint('auth', __name__)

def gen_random_inputs(pswd_lenght):
    no_of_inputs = round(pswd_lenght/2) - 1
    inputs = random.sample(range(pswd_lenght), no_of_inputs)
    return inputs


@auth.route('/', methods=['GET', 'POST'])
def client_number():
    if request.method == 'POST':
        client_number = request.form.get('client_number')
        return redirect(url_for('auth.password'))
    return render_template("client_number.html")

@auth.route('/password', methods=['GET', 'POST'])
def password():
    if request.method == 'GET':
        required_inputs = gen_random_inputs(6)
        print (required_inputs)
    return render_template("password.html", no_inputs=6, required_inputs = required_inputs)

@auth.route('/logout')
def logout():
    return "<p>Logout</p>"
