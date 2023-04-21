import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

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

# Object containing current date and time
now = datetime.now()

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Gets info about the stocks bought and the remaining cash the user has and is passed to index.html
    stock_bought = db.execute(
        "SELECT name, symbol, SUM(number) as total FROM stocks2 GROUP BY symbol HAVING usernameId = :user_id", user_id=session["user_id"])
    balance_left = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])

    # Holds the prices of each stock
    price = []
    for i in range(len(stock_bought)):
        price.append(lookup(stock_bought[i]["symbol"]))
        stock_price = price[i]["price"]
        stock_bought[i].update({"price" : stock_price})

    # Calculating the total of all stocks and cash left and later displaying it in index.html
    total_stock = 0
    for k in range(len(stock_bought)):
        total_stock = (stock_bought[k]["price"] * stock_bought[k]["total"]) + total_stock
    total = total_stock + balance_left[0]["cash"]

    return render_template("index.html", stock_bought=stock_bought, balance=balance_left, total_sum=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbols = lookup(request.form.get("symbol"))
        # Returns error if no symbol inputted
        if not request.form.get("symbol"):
            return apology("Missing Symbol")

        # Returns error if none existnet stock is entered
        if symbols == None:
            return apology("Invalid Symbol")

        # Returns an error if no number of shares is entered and ensures the number of shares is a +ve integer
        if not request.form.get("shares"):
            return apology("Invalid Number of shares")

        if request.form.get("shares", type = int) < 1:
            return apology("Invalid Number of shares")

        # Store the stocks bought in a database if the user can afford it
        balance = db.execute(
            "SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])
        if balance[0]["cash"] < (symbols["price"] * request.form.get("shares", type=int)):
            return apology("Not enough income to purchase stocks")
        else:
            db.execute(
                "UPDATE users SET cash = :balance_left WHERE id = :user_id", balance_left=balance[0]["cash"] - (symbols["price"] * request.form.get("shares", type=int)), user_id=session["user_id"])

            # Adds a new database entry if stock was never bought but updates entry if stock was previously bought
            stocks_owned = db.execute(
                "SELECT symbol FROM stocks2 WHERE usernameId = :user_id", user_id=session["user_id"])
            search_result = 0

            # Performs the search
            for i in range(len(stocks_owned)):
                if stocks_owned[i]["symbol"] == request.form.get("symbol"):
                    search_result=1
                    break
                else:
                    search_result=0

            # Updates an existing entry
            if search_result == 1:
                number_stocks_owned = db.execute(
                    "SELECT number FROM stocks2 WHERE usernameId = :user_id AND symbol = :symbol", user_id=session["user_id"], symbol=request.form.get("symbol"))
                db.execute(
                    "UPDATE stocks2 SET number = :new WHERE usernameId = :user_id AND symbol = :symbol", user_id=session["user_id"], symbol=request.form.get("symbol"), new=number_stocks_owned[0]["number"] + request.form.get("shares", type=int))

            # Adds a new table entry
            else:
                db.execute(
                    "INSERT INTO stocks2 VALUES (:user_id, :stock_name, :stock_number, :symbol)", symbol=request.form.get("symbol"), user_id=session["user_id"], stock_name=symbols["name"], stock_number=request.form.get("shares", type=int))

            # Updates the history table
            db.execute("INSERT INTO history VALUES(:user_id, :symbol, :number, :change, :date, :price)", user_id = session["user_id"], symbol = request.form.get("symbol"), change = "bought", price = symbols["price"], number = request.form.get("shares", type = int), date = now.strftime("%d/%m/%Y %H:%M:%S"))
            return redirect("/")


    if request.method == "GET":
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stock_bought = db.execute("SELECT symbol, number, price, date, change FROM history WHERE usernameId = :user_id ORDER BY date DESC", user_id = session["user_id"])
    return render_template("history.html", stock_bought = stock_bought)

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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
        symbols = lookup(request.form.get("symbol"))
        if symbols == None:
            return apology("Symbol doesn't exist")
        else:
            return render_template("quoted.html", name=symbols["name"], price=symbols["price"], symbol=symbols["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Displays the registration form if user reaches /register via get
    if request.method == "GET":
        return render_template("register.html")

    # POST
    else:

        # Ensures that a username was entered
        if not request.form.get("username"):
            return apology("Missing Username")

        # Ensures that a password was entered
        if not request.form.get("password"):
            return apology("Missing password")

        # Ensures that a confirmation password was entered
        if not request.form.get("confirmation"):
            return apology("Missing confirmation password")

        # Ensures that password and confirmation password are the same
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Password is not the same")

        # Checks if username kept is already in the database
        rows = db.execute("SELECT * FROM users WHERE username = :username", username = request.form.get("username"))
        if len(rows) != 0:
            return apology("Username already used")
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username = request.form.get("username"), hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=16))
            return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":

        # Stores info about symbol
        symbol = lookup(request.form.get("symbol"))

        # Ensures that a symbol was submitted
        if not request.form.get("symbol"):
            return apology("Missing Symbol")

        # Ensures that a number of shares was submitted
        if not request.form.get("shares", type = int) or request.form.get("shares", type = int) < 1:
            return apology("Invalid number of shares")

        stock_list = db.execute("SELECT symbol, SUM(number) FROM stocks2 WHERE usernameId = :user_id GROUP BY symbol", user_id = session["user_id"])

        # Gets symbols and compares them to inputted symbol
        symbols = []
        for i in range(len(stock_list)):
            symbols.append(stock_list[i]["symbol"])

        if request.form.get("symbol") not in symbols:
            return apology("Symbol not owned")

        stock_number = db.execute("SELECT SUM(number) AS total FROM stocks2 WHERE usernameId = :user_id AND symbol = :symbol", symbol = request.form.get("symbol"), user_id = session["user_id"])
        if request.form.get("shares", type = int) > stock_number[0]["total"]:
            return apology("Too many shares")
        else:
            # Updates cash of user
            cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id = session["user_id"])
            cash_left = cash[0]["cash"] + (symbol["price"] * request.form.get("shares", type = int))
            db.execute("UPDATE users SET cash = :cash WHERE id = :user_id", user_id = session["user_id"], cash = cash_left)

            # Updates the number of remaining stocks after selling and stores in history
            remaining_stocks = stock_number[0]["total"] - request.form.get("shares", type = int)
            db.execute("UPDATE stocks2 SET number = :remaining WHERE usernameId = :user_id AND symbol = :symbol", remaining = remaining_stocks, symbol = request.form.get("symbol"), user_id = session["user_id"])
            db.execute("INSERT INTO history VALUES(:user_id, :symbol, :number, :change, :date, :price)", user_id = session["user_id"], symbol = request.form.get("symbol"), change = "sold", price = symbol["price"], number = request.form.get("shares", type = int), date = now.strftime("%d/%m/%Y %H:%M:%S"))
        return redirect("/")
    else:
        stock_list = db.execute("SELECT symbol, SUM(number) AS total FROM stocks2 WHERE usernameId = :user_id GROUP BY symbol", user_id = session["user_id"])
        return render_template("sell.html", stock_list=stock_list)

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Allows the user to change their password"""

    # Renders the page if GET is used
    if request.method == "GET":
        return render_template("password.html")

    # Performs logic if POST is used
    else:
        # Variables to be used
        oldpass = request.form.get("oldpass")
        newpass = request.form.get("newpass")
        confirmation = request.form.get("confirmation")

        # Checks that inputs were filled
        if not oldpass or not newpass or not confirmation:
            return apology("Missing Password")

        # Checks if newpass and confirmation are the same
        if newpass != confirmation:
            return apology("Confirmed password doesn't match new password")

        # Checks if oldpass is correct
        passcompare = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id = session["user_id"])
        if check_password_hash(passcompare[0]["hash"], oldpass) == False:
            return apology("Enter Old Password Again")

        # Hashes and stores the newpass
        hashnewpass = generate_password_hash(newpass, method='pbkdf2:sha256', salt_length=16)
        db.execute("UPDATE users SET hash = :hashnewpass WHERE id = :user_id", user_id = session["user_id"], hashnewpass=hashnewpass)

        return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
