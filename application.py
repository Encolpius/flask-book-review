import os, requests

from flask import Flask, flash, redirect, session, render_template, url_for, request, json
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt

app = Flask(__name__)



# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv('DATABASE_URL'))
db = scoped_session(sessionmaker(bind=engine))


@app.route('/',  methods=['GET', 'POST'])
def index():
    if 'logged_in' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        flash("You must be logged in to do that.", "message-error")
        return render_template('login.html')
    else:
        isbns = db.execute("SELECT isbn FROM books ORDER BY random() LIMIT 4")
        return render_template('index.html', isbns=isbns)


@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'logged_in' not in session:
            flash('Please log in.', 'message-error')
            return redirect(url_for("login"))
    username = session['username']
    if request.method == "POST":
        search_request = request.form['userSearchInput']
        book_info = find_book_info(search_request)
        if len(book_info) < 1:
            return render_template('home.html', 
                                    message='No results found. Please try again.', 
                                    username=username)
        else:
            return render_template('home.html', books=book_info, username=username)
    else:
        return render_template("home.html", username=username)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form["username"]
        username_in_db = db.execute('SELECT username FROM users WHERE username = :username', {'username': username}).first()
        if username_in_db == None: 
            email = request.form['email']
            password = sha256_crypt.encrypt(request.form['password'])
            db.execute( "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)",
                {'username': username, 'email': email, 'password': password })
            db.commit()
            flash('Account successfully created!', 'message-success')
            return render_template('index.html')
        elif username == username_in_db.username:
            flash('Error: Username already taken. Please choose another.', 'message-error')
            return redirect(url_for('signup'))
    else:
        return render_template('signup.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        get_user = db.execute('SELECT username FROM users WHERE username = :username', {'username': user }).first().username
        if get_user == None:
            flash('User not found. Please try again.', 'message-error')
            return redirect(url_for('login'))

        get_password = db.execute("SELECT password FROM users WHERE username = :username", {'username': user}).first().password
        if sha256_crypt.verify(request.form['password'], get_password) != True:
            flash('Incorrect password. Please try again.', 'message-error')
            return redirect(url_for('login'))
        else:
            session['username'] = request.form['username']
            session['logged_in'] = True
            flash('You have successfully logged in.', 'message-success')
            return redirect(url_for('home'))
    else: 
        return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have successfully logged out.', 'message-success')
    return redirect(url_for('index'))


@app.route('/book/<title>', methods=['GET', 'POST'])
def books(title):
    if 'logged_in' not in session:
        flash('Please log in.', 'message-error')
        return redirect(url_for("login"))

    book = db.execute('SELECT * FROM books WHERE title LIKE :title', {'title': title}).first()
    reviews = db.execute('SELECT * FROM reviews WHERE book LiKE :title', {'title': title}).fetchall()
    url = "https://www.goodreads.com/book/review_counts.json"
    params = {
        "key": "q63Wwt9QwstBB6Ju3KtJ2g",
        "isbns": book.isbn
        }
    res = requests.get(url, params=params).json()
    if request.method == 'GET':
        return render_template('books.html', book=book, request=res, reviews=reviews)


@app.route('/review/<title>', methods=['GET', 'POST'])
def review(title):
    if request.method == 'POST':
        return render_template('review.html', title=title)


def find_book_info(search_request):
    results = db.execute('SELECT * FROM books WHERE title LIKE :title OR author LIKE :author OR isbn LIKE :isbn',
                        {'title': '%' + search_request + '%',
                         'author': '%' + search_request + "%",
                         'isbn': '%' + search_request + "%"
                        }).fetchall()
    return results