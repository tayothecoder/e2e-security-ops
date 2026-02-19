from flask import (Flask, render_template, request, redirect, url_for,
                     session, g, send_file, flash)
import sqlite3
import os
import hashlib
import time

app = Flask(__name__)
app.secret_key = 'travelbird-dev-key-2024'  # todo change before prod
DB_PATH = os.path.join(os.path.dirname(__file__), 'travelbird.db')
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def get_current_user():
    """grab user from session if logged in"""
    user_id = session.get('user_id')
    if user_id:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        return user
    return None


# -- routes --

@app.route('/')
def index():
    db = get_db()
    packages = db.execute('SELECT * FROM packages ORDER BY RANDOM() LIMIT 6').fetchall()
    user = get_current_user()
    return render_template('index.html', packages=packages, user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        db = get_db()
        # quick login check
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        try:
            user = db.execute(query).fetchone()
        except Exception as e:
            flash('Login failed: ' + str(e))
            return render_template('login.html')

        if user:
            # generate session token
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            # predictable token for "remember me" functionality
            token = hashlib.md5((user['username'] + str(int(time.time()))).encode()).hexdigest()
            session['token'] = token
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/search')
def search():
    q = request.args.get('q', '')
    db = get_db()
    user = get_current_user()
    results = []

    if q:
        # search packages by name or destination
        query = "SELECT * FROM packages WHERE name LIKE '%%%s%%' OR destination LIKE '%%%s%%'" % (q, q)
        try:
            results = db.execute(query).fetchall()
        except Exception:
            results = []

    return render_template('search.html', query=q, results=results, user=user)


@app.route('/package/<int:package_id>')
def package_detail(package_id):
    db = get_db()
    user = get_current_user()
    package = db.execute('SELECT * FROM packages WHERE id = ?', (package_id,)).fetchone()
    if not package:
        flash('Package not found')
        return redirect(url_for('index'))

    reviews = db.execute('''
        SELECT r.*, u.username FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.package_id = ?
        ORDER BY r.created_at DESC
    ''', (package_id,)).fetchall()

    return render_template('booking.html', package=package, reviews=reviews, user=user)


@app.route('/book/<int:package_id>', methods=['POST'])
def book_package(package_id):
    user = get_current_user()
    if not user:
        flash('Please login to book')
        return redirect(url_for('login'))

    db = get_db()
    db.execute('INSERT INTO bookings (user_id, package_id, booking_date) VALUES (?, ?, datetime("now"))',
               (user['id'], package_id))
    db.commit()
    flash('Booking confirmed')
    return redirect(url_for('package_detail', package_id=package_id))


@app.route('/reviews/<int:package_id>', methods=['GET', 'POST'])
def reviews(package_id):
    db = get_db()
    user = get_current_user()

    if request.method == 'POST':
        if not user:
            flash('Login to leave a review')
            return redirect(url_for('login'))

        content = request.form.get('content', '')
        rating = request.form.get('rating', 5)

        # save the review
        db.execute('INSERT INTO reviews (user_id, package_id, content, rating) VALUES (?, ?, ?, ?)',
                   (user['id'], package_id, content, rating))
        db.commit()
        flash('Review posted')

    package = db.execute('SELECT * FROM packages WHERE id = ?', (package_id,)).fetchone()
    all_reviews = db.execute('''
        SELECT r.*, u.username FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.package_id = ?
        ORDER BY r.created_at DESC
    ''', (package_id,)).fetchall()

    return render_template('reviews.html', package=package, reviews=all_reviews, user=user)


@app.route('/profile/<int:user_id>')
def profile(user_id):
    """view user profile - need to be logged in"""
    current = get_current_user()
    if not current:
        return redirect(url_for('login'))

    db = get_db()
    # fetch the requested profile
    profile_user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not profile_user:
        flash('User not found')
        return redirect(url_for('index'))

    bookings = db.execute('''
        SELECT b.*, p.name as package_name, p.destination
        FROM bookings b JOIN packages p ON b.package_id = p.id
        WHERE b.user_id = ?
    ''', (user_id,)).fetchall()

    return render_template('profile.html', profile_user=profile_user, bookings=bookings, user=current)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename:
            # save uploaded file
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            flash('File uploaded: ' + file.filename)

    # list existing uploads
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('upload.html', files=files, user=user)


@app.route('/download')
def download():
    """download uploaded files"""
    filename = request.args.get('file', '')
    if not filename:
        flash('No file specified')
        return redirect(url_for('upload'))

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(filepath)


@app.route('/admin')
def admin():
    user = get_current_user()
    if not user or user['role'] != 'admin':
        flash('Admin access required')
        return redirect(url_for('login'))

    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    bookings = db.execute('''
        SELECT b.*, u.username, p.name as package_name
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN packages p ON b.package_id = p.id
        ORDER BY b.booking_date DESC
    ''').fetchall()
    return render_template('admin.html', users=users, bookings=bookings, user=user)


if __name__ == '__main__':
    # make sure uploads dir exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    if not os.path.exists(DB_PATH):
        print('no database found, run init_db.py first')
    app.run(host='0.0.0.0', port=5000, debug=True)
