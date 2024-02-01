from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'db.sqlite'

def connect_db():
    return sqlite3.connect(DATABASE)

def init_db():
    with app.app_context():
        db = connect_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.before_first_request
def before_first_request():
    if not os.path.exists(DATABASE):
        init_db()

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'):
        g.db.close()

@app.route('/')
def home():
    if 'user_id' in session:
        user = get_user_by_id(session['user_id'])
        return render_template('home.html', username=user['username'])
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Both username and password are required', 'error')
        else:
            hashed_password = generate_password_hash(password, method='sha256')
            insert_user(username, hashed_password)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

def insert_user(username, password):
    g.db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    g.db.commit()

def get_user_by_username(username):
    cursor = g.db.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
    columns = [column[0] for column in cursor.description]
    return dict(zip(columns, cursor.fetchone()))

def get_user_by_id(user_id):
    cursor = g.db.execute('SELECT id, username, password FROM users WHERE id = ?', (user_id,))
    columns = [column[0] for column in cursor.description]
    return dict(zip(columns, cursor.fetchone()))

if __name__ == '__main__':
    with app.app_context():
        g.db = connect_db()
    app.run(debug=True)
