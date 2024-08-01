import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # get a LIST of dict now only has symbol, shares and cash
    stocks = db.execute(
        "SELECT symbol, shares, cash FROM users JOIN portfolio ON users.id = portfolio.user_id WHERE users.id = ?",
        session["user_id"],
    )

    # current cash of the user
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]

    # grand total
    grand_total = cash

    # loop though each dict to modify it up to 5 items
    for stock in stocks:
        # price of the symbol
        price = lookup(stock["symbol"])["price"]

        # 2 key-value pairs that will be update in the dictionary
        keys = ("price", "stock's total")
        values = (price, stock["shares"] * price)

        # update into the dictionary
        for key, value in zip(keys, values):
            if key == "stock's total":
                grand_total += value

            stock.update({key: value})

    # return a list into index.html
    return render_template(
        "index.html", stocks=stocks, grand_total=grand_total, cash=cash
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        # what lookup returns
        stock = lookup(request.form.get("symbol"))

        # validate user input
        if stock == None:
            return apology("invalid symbol", 400)
        elif (
            not request.form.get("shares")
            or not request.form.get("shares").isdecimal()
            or int(request.form.get("shares")) <= 0
        ):
            return apology("invalid shares", 400)

        # amount of cash owned by the user
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
            "cash"
        ]

        # can user afford that stock
        if cash < stock["price"] * int(request.form.get("shares")):
            return apology("insufficient cash", 400)

        # add that amount of shares of that symbol to the user portfolio
        # current shares of that user to that stock
        current_shares = db.execute(
            "SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?",
            session["user_id"],
            stock["symbol"],
        )

        # if current share is empty means the user has never bought that stock before
        if not current_shares:
            db.execute(
                "INSERT INTO portfolio (user_id, symbol, shares) VALUES (? , ?, ?)",
                session["user_id"],
                stock["symbol"],
                int(request.form.get("shares")),
            )
        # if exits current shares means the user has bought this stock before
        else:
            db.execute(
                "UPDATE portfolio SET shares = ? WHERE user_id = ? and symbol = ?",
                current_shares[0]["shares"] + int(request.form.get("shares")),
                session["user_id"],
                stock["symbol"],
            )

        # update the remaining cash after buying shares
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            cash - (stock["price"] * int(request.form.get("shares"))),
            session["user_id"],
        )

        # record transaction history
        # time of the transaction
        time = datetime.datetime.now()

        # concatenate shares amount (+2, +4,...)
        shares_transacted = "+" + request.form.get("shares")

        # insert into the history table
        db.execute(
            "INSERT INTO history (user_id, symbol, shares, price, date, time) VALUES (?, ?, ?, ?, ?, ?)",
            session["user_id"],
            stock["symbol"],
            shares_transacted,
            stock["price"],
            time.strftime("%x"),
            time.strftime("%X"),
        )

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])

    return render_template("history.html", history=history)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

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

        # what lookup returns
        stock = lookup(request.form.get("symbol"))

        # check if the lookup fails
        if stock == None:
            return apology("invalid symbol", 400)
        # when lookup is succesful
        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # when user type input into the register form
    if request.method == "POST":
        # errors checking
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("wrong password confirmation", 400)

        # insert new user to database
        try:
            db.execute(
                "INSERT INTO users (username, hash) VALUES(?, ?)",
                request.form.get("username"),
                generate_password_hash(request.form.get("password")),
            )
        # when username is already taken
        except ValueError:
            return apology("username already taken", 400)

        # remember new user id
        session["user_id"] = db.execute(
            "SELECT id FROM users WHERE username = ?", request.form.get("username")
        )[0]["id"]

        # redirect to homepage
        return redirect("/")

    # when user reach the register page (with no input)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # get a LIST of dict now only has symbol, shares and cash
    stocks = db.execute(
        "SELECT symbol, shares, cash FROM users JOIN portfolio ON users.id = portfolio.user_id WHERE users.id = ?",
        session["user_id"],
    )

    # list of all the symbols the user has purchased
    symbols = []
    for temp_dict in stocks:
        symbols.append(temp_dict["symbol"])

    if request.method == "POST":
        # see which dictionary with the symbol the user wants to sell
        stock = {}
        for tmp_dict in stocks:
            # symbol error checking
            # if the symbol the user typed in is not in the database means the user doenst own it or invalid symbol
            if tmp_dict["symbol"] == request.form.get("symbol"):
                stock = tmp_dict
                break
        else:
            return apology("invalid symbol", 400)

        # ---------------DEBUGGING---------------
        print("# ---------------DEBUGGING---------------")
        print(stock["cash"])
        print(stock["shares"])

        # shares errors checking
        if (
            not request.form.get("shares")
            or not request.form.get("shares").isdecimal()
            or int(request.form.get("shares")) <= 0
            or int(request.form.get("shares")) > stock["shares"]
        ):
            return apology("invalid shares", 400)

        # update the current shares
        # if after selling shares reaches 0, delete that stock
        if stock["shares"] - int(request.form.get("shares")) == 0:
            db.execute(
                "DELETE FROM portfolio WHERE user_id = ? AND symbol = ?",
                session["user_id"],
                stock["symbol"],
            )
        # else update it as usual
        else:
            db.execute(
                "UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?",
                stock["shares"] - int(request.form.get("shares")),
                session["user_id"],
                stock["symbol"],
            )

        # update the current cash
        db.execute(
            "UPDATE users SET cash = ? WHERE users.id = ?",
            stock["cash"]
            + (int(request.form.get("shares")) * lookup(stock["symbol"])["price"]),
            session["user_id"],
        )

        # record transaction history
        # time of the transaction
        time = datetime.datetime.now()

        # concatenate shares amount (-2, -4,...)
        shares_transacted = "-" + request.form.get("shares")

        # insert into the history table
        db.execute(
            "INSERT INTO history (user_id, symbol, shares, price, date, time) VALUES (?, ?, ?, ?, ?, ?)",
            session["user_id"],
            stock["symbol"],
            shares_transacted,
            lookup(stock["symbol"])["price"],
            time.strftime("%x"),
            time.strftime("%X"),
        )

        return redirect("/")

    else:
        return render_template("sell.html", symbols=symbols)


@app.route("/deposit_cash", methods=["GET", "POST"])
@login_required
def deposit_cash():
    if request.method == "POST":
        # validate errors
        if not request.form.get("deposit_cash"):
            apology("missing cash", 400)

        # cash the user has
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
            "cash"
        ]

        # update into the database
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            cash + int(request.form.get("deposit_cash")),
            session["user_id"],
        )

        return redirect("/")

    else:
        return render_template("deposit_cash.html")
