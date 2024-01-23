from flask import Blueprint, render_template
from flask_login import login_required, current_user
from .models import User, Permutation, UserInfo, Transfer

views = Blueprint('views', __name__)

@views.route('/home')
@login_required
def home():
    user_info = UserInfo.query.filter_by(client_number = current_user.client_number).first()
    return render_template("home.html", user=current_user, user_info=user_info)

@views.route('/new_transfer')
@login_required
def new_transfer():
    return render_template("new_transfer.html", user=current_user)