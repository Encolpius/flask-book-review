import os, requests, re, statistics

from flask import Flask, flash, redirect, session, render_template, url_for, request, json, jsonify, abort, Markup
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt
from statistics import mean

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
        db.commit()
        return render_template('index.html', isbns=isbns)

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'logged_in' not in session:
            flash('Please log in.', 'message-error')
            return redirect(url_for("login"))
    if request.method == "POST":
        search_request = request.form['userSearchInput']
        book_info = find_book_info(search_request)
        if len(book_info) < 1:
            return render_template('home.html', 
                                    message='No results found. Please try again.', 
                                    username=username)
        else:
            return render_template('home.html', books=book_info)
    else:
        return render_template("home.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        username_in_db = db.execute('SELECT username FROM users WHERE username = :username', {'username': username}).first()
        db.commit()
        if username_in_db == None: 
            if len(username) > 20:
                flash("Username length is max 20 characters.", "message-error")
                return redirect(url_for("signup"))
            elif not re.match("^[A-Za-z0-9_-]*$", username):
                flash("Letters, numbers, and underscore characters allowed only.", 'message-error')
                return redirect(url_for("signup"))
            firstname = request.form['firstname']
            if len(firstname) > 12:
                flash("First name max length is 12 characters.", 'message-error')
                return redirect(url_for('signup'))
            password = sha256_crypt.encrypt(request.form['password'])
            db.execute( "INSERT INTO users (username, firstname, password) VALUES (:username, :firstname, :password)",
                {'username': username, 'firstname': firstname, 'password': password })
            db.commit()
            session['username'] = username
            session['firstname'] = firstname
            session['logged_in'] = True
            flash('Account successfully created!', 'message-success')
            return redirect(url_for('home'))
        elif username == username_in_db.username:
            flash('Error: Username already taken. Please choose another.', 'message-error')
            return redirect(url_for('signup'))
    else:
        return render_template('signup.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form['username']
        get_user = db.execute('SELECT * FROM users WHERE username = :username', {'username': user }).first()
        db.commit()
        if get_user == None:
            flash('User not found. Please try again.', 'message-error')
            return redirect(url_for('login'))
        get_password = get_user.password
        db.commit()
        if sha256_crypt.verify(request.form['password'], get_password) != True:
            flash('Incorrect password. Please try again.', 'message-error')
            return redirect(url_for('login'))
        else:
            session['username'] = get_user.username
            session['firstname'] = get_user.firstname
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
    db.commit()
    reviews = db.execute('SELECT * FROM reviews WHERE book LIKE :title', {'title': title}).fetchall()
    db.commit()
    rating_data = db.execute('SELECT rating FROM reviews WHERE book LIKE :title', {'title': title}).fetchall()
    db.commit()
    ratings = []
    if len(rating_data) > 0:
        for rating in rating_data:
            ratings.append(rating[0]) 
        ratings = mean(ratings)
    else:
        ratings = 'N/A'
    url = "https://www.goodreads.com/book/review_counts.json"
    params = {
        "key": "q63Wwt9QwstBB6Ju3KtJ2g",
        "isbns": book.isbn
        }
    res = requests.get(url, params=params).json()
    has_review = check_for_review(session.get("username"), book.title)
    db.commit()
    if has_review == False:
        value = Markup('<button class="review-button">Write a Review</button>')
    else:
        value = Markup('<p style="color: red;">You have already reviewed this book.</p>')
    if request.method == 'GET':
        return render_template('books.html', book=book, request=res, 
                                             reviews=reviews, review_markup=value, ratings=ratings)

@app.route('/review/<title>', methods=['GET', 'POST'])
def review(title):
    if request.method == 'POST':
        rating = request.form["rating"]
        review_text = request.form["review_text"]
        db.execute( "INSERT INTO reviews (book, rating, review_text, author, date) VALUES (:book, :rating, :review_text, :author, now())",
                {'book': title, 'rating': rating, 'review_text': review_text, 'author': session.get("username")})
        db.commit()
        return redirect(url_for('review', title=title))
    else:
        if db.execute("SELECT author FROM reviews WHERE book LIKE :title", {'title': title}).first() != None:
            db.commit()
            return redirect(url_for('books', title=title))
        else:
            return render_template('review.html', title=title)

@app.route('/api/<isbn>', methods=['GET'])
def get_api(isbn):
    book = db.execute('SELECT * FROM books WHERE isbn LIKE :isbn', {'isbn': isbn}).first()
    db.commit()
    if book == None:
        return abort(404)
    else:
        return jsonify(title=book.title,
                       author=book.author,
                       year=book.year,
                       isbn=book.isbn)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

def find_book_info(search_request):
    results = db.execute('SELECT * FROM books WHERE title LIKE :title OR author LIKE :author OR isbn LIKE :isbn',
                        {'title': '%' + search_request + '%',
                         'author': '%' + search_request + "%",
                         'isbn': '%' + search_request + "%"
                        }).fetchall()
    db.commit()
    return results

def check_for_review(username, title):
    authors = db.execute("SELECT author FROM reviews WHERE book = :title", {"title": title}).fetchall()
    for author in authors:
        if username == author.author:
            return True 
    return False