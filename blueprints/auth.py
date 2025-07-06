from flask import Blueprint, render_template, request, redirect, session, flash
from utils.ldap_utils import authenticate

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(username)
        print(password)

        if authenticate(username, password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            print('Authentication failed')
            flash('Invalid credentials. Please try again.')
            return redirect('/')

    return render_template('login.html')


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')
