from flask import Blueprint, render_template

auth = Blueprint('auth', __name__)

@auth.route('/', methods=['GET', 'POST'])
def client_number():
    return render_template("client_number.html")

@auth.route('/password', methods=['GET', 'POST'])
def password():
    return render_template("password.html")

@auth.route('/logout')
def logout():
    return "<p>Logout</p>"
