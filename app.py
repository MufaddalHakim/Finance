import os
import string
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    username = db.execute('SELECT username FROM users WHERE id = :id', id=session['user_id'])[0]['username']
    cash = db.execute('SELECT cash FROM users WHERE id = :id', id=session['user_id'])[0]['cash']
    portfolio = db.execute('SELECT * FROM purchases WHERE username = :username', username=username)
    shareTotal = []
    prices = []
    company = []
    total = 0

    symbols = []
    for dict in portfolio:
        if dict['symbol'] not in symbols:
            symbols.append(dict['symbol'])

    shareCount = {}
    for symbol in symbols:
        shareCount[symbol] = 0
        company.append(lookup(symbol)['name'])

    for symbol in symbols:
        sharesList = []
        sharesHistory = db.execute('SELECT shares FROM purchases WHERE username=:username AND symbol=:symbol', username=username, symbol=symbol)
        for dict in sharesHistory:
            sharesList.append(dict['shares'])
        shareCount[symbol] = sum(sharesList)
        shareTotal.append(lookup(symbol)['price'] * abs(shareCount[symbol]))
        prices.append(lookup(symbol)['price'])

    total = sum(shareTotal)
    total += cash
    return render_template('index.html', symbols=symbols, shareCount=shareCount, cash=cash, total=total, shareTotal=shareTotal, prices=prices, company=company)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol").upper()
        if lookup(symbol) == None:
            return apology("Symbol does not exist")

        shares = request.form.get("shares")
        try:
            shares = int(shares)
        except:
            return apology("Please enter a valid number")
        if shares < 0:
            return apology("Please enter a valid number")

        price = lookup(symbol)['price']
        userid = session["user_id"]
        cash = db.execute('SELECT cash FROM users WHERE id = :userid', userid=userid)
        shareTotal = price*shares
        if cash[0]['cash'] < shareTotal:
            return apology("Insufficient balance")
        db.execute('INSERT INTO purchases (userid, username, company, symbol, price, shares, time) VALUES (:userid, :username, :company, :symbol, :price, :shares, :time)',
                    userid=userid, username=db.execute('SELECT username FROM users WHERE id = :userid', userid=userid)[0]['username'], company=lookup(symbol)['name'], symbol=symbol,
                    price=price, shares=shares, time=db.execute('SELECT strftime("%Y-%m-%d %H:%M:%S", "now")')[0]['strftime("%Y-%m-%d %H:%M:%S", "now")'])
        remainingCash = cash[0]['cash'] - shareTotal
        db.execute('UPDATE users SET cash=:remainingCash WHERE id=:id', remainingCash=remainingCash, id=userid)

        return redirect('/')
    else:
        return render_template('buy.html')




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    username = db.execute('SELECT username FROM users WHERE id=:userid', userid=session['user_id'])[0]['username']
    portfolio = db.execute('SELECT * FROM purchases WHERE username=:username', username=username)
    prices = []
    for dict in portfolio:
        prices.append(lookup(dict['symbol'])['price'])
    return render_template('history.html', portfolio=portfolio, prices=prices)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("stock")
        price = lookup(symbol)
        return render_template('quoted.html', price=price)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template('register.html')
    else:
        username = request.form.get("username")
        password1 = request.form.get("password")
        password2 = request.form.get("confirmation")
        usernames = db.execute("SELECT username FROM users")
        if not username:
            return apology("Must provide username", 403)
        elif not password1:
            return apology("Must provide password", 403)
        elif not password2:
            return apology("Must confirm password", 403)
        elif password1 == password2:
            if username not in usernames:
                db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)", username=username, password=generate_password_hash(password1))
                return redirect('/')
            else:
                return apology("Username not available", 403)
        else:
            return apology("Passwords do not match", 403)

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        username = db.execute('SELECT username FROM users WHERE id = :userid', userid=session['user_id'])[0]['username']
        portfolio = db.execute('SELECT shares, symbol FROM purchases WHERE username = :username', username=username)
        symbols = []
        for dict in portfolio:
            if dict['symbol'] not in symbols:
                symbols.append(dict['symbol'])

        shareCount = {}
        for symbol in symbols:
            shareCount[symbol] = 0

        for symbol in symbols:
            sharesList = []
            sharesHistory = db.execute('SELECT shares FROM purchases WHERE username=:username AND symbol=:symbol', username=username, symbol=symbol)
            for dict in sharesHistory:
                sharesList.append(dict['shares'])
            shareCount[symbol] = sum(sharesList)

        return render_template('sell.html', shareCount=shareCount)

    else:
        symbol = request.form.get('symbol').upper()
        shares = request.form.get('shares')
        userid = session['user_id']
        username = db.execute('SELECT username FROM users WHERE id=:userid', userid=session['user_id'])[0]['username']
        portfolio = db.execute('SELECT shares FROM purchases WHERE username=:username AND symbol=:symbol', username=username, symbol=symbol)
        availableShares = 0

        try:
            shares = int(shares)
        except:
            return apology("Please enter a valid number")
        if shares < 0:
            return apology("Please enter a valid number")

        for dict in portfolio:
            availableShares += dict['shares']
        if availableShares < shares:
            return apology("Insufficient Shares")

        price = lookup(symbol)['price']


        db.execute('INSERT INTO purchases (userid, username, company, symbol, price, shares, time) VALUES (:userid, :username, :company, :symbol, :price, :shares, :time)', userid=userid,
                    username=db.execute('SELECT username FROM users WHERE id = :userid', userid=userid)[0]['username'], company=lookup(symbol)['name'], symbol=symbol, price=price,
                    shares=-shares, time=db.execute('SELECT strftime("%Y-%m-%d %H:%M:%S", "now")')[0]['strftime("%Y-%m-%d %H:%M:%S", "now")'])

        cash = db.execute('SELECT cash FROM users WHERE id = :userid', userid=userid)[0]['cash']
        newCash = cash + (shares*price)
        db.execute('UPDATE users SET cash=:newCash WHERE id=:userid', newCash=newCash, userid=userid)

        return redirect('/')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
